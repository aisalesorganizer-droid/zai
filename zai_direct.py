"""
zai_direct.py — Z.ai Direct HTTP Client (No Browser)
======================================================
Replaces the Playwright browser with a direct curl_cffi HTTP call.
Requires the HMAC key extracted by extract_hmac_key.py.

Drop into your Zai/ folder. Plug in the key and it's done.

Speed comparison:
  Browser (zai_persistent.py) : ~4–12s per request
  Direct HTTP (this file)     : ~1–3s (pure model inference time, no browser overhead)

Multi-account rotation built-in:
  Supports N accounts, round-robin or random selection.
  Automatic failover on auth errors.

Usage:
    # Standalone test
    python zai_direct.py "Hello, who are you?"

    # As a drop-in provider
    from zai_direct import ZAIDirect
    client = ZAIDirect()
    for chunk in client.chat([{"role": "user", "content": "hi"}], stream=True):
        print(chunk, end="", flush=True)

Requirements:
    pip install curl_cffi
    (No playwright needed!)

Files read:
    sig_key_result.json        — HMAC key (from extract_hmac_key.py)
    z_ai_account.json          — Single account (legacy support)
    zai_guest_accounts/acc*.json — Multi-account pool (preferred)
"""

from __future__ import annotations

import hmac
import hashlib
import json
import os
import sys
import time
import uuid
import random
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional
from urllib.parse import urlencode

try:
    from curl_cffi import requests as cffi_requests
    CFFI_AVAILABLE = True
except ImportError:
    import urllib.request, urllib.error
    CFFI_AVAILABLE = False
    print("⚠ curl_cffi not installed. Install it for TLS fingerprint spoofing:")
    print("    pip install curl_cffi")
    print("  Falling back to urllib (may be detected).\n")


# ── Constants ──────────────────────────────────────────────────────────────────

BASE_URL        = "https://chat.z.ai"
COMPLETIONS_URL = f"{BASE_URL}/api/v2/chat/completions"
SUPPORTED_MODELS = ["glm-5", "glm-4.7"]

_HERE           = os.path.dirname(os.path.abspath(__file__))
SIG_KEY_FILE    = os.path.join(_HERE, "sig_key_result.json")
ACCOUNT_FILE    = os.path.join(_HERE, "z_ai_account.json")
ACCOUNTS_DIR    = os.path.join(_HERE, "zai_guest_accounts")

# Browser fingerprint — Chrome 124 on Windows (matches your captured requests)
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)
FE_VERSION = "prod-fe-1.0.262"


# ── HMAC Signature ─────────────────────────────────────────────────────────────

# Known-good verification samples — used both for startup check and auto-recovery
# verification. All from prod-fe-1.0.262, guest account 8396eac6.
_VERIFY_SAMPLES = [
    # (request_id, user_id, prompt, timestamp_ms, expected_sig)
    (
        "fa57ec78-a091-4a51-8398-46b4ed4654c6",
        "8396eac6-d9a2-4686-b66a-359d7085649f",
        "test_alpha_001", 1773754824064,
        "de42f93c36db37abca253ce92ca344d0a0d968de9544fd81606767bfde5eb9e8",
    ),
    (
        "8cef1f20-dcaa-4b03-b341-3e5477b9e875",
        "8396eac6-d9a2-4686-b66a-359d7085649f",
        "test_beta_002", 1773754836424,
        "44c8862802e92687608cae7fe9a0543f00967ba3761ad4a5cf95e8b3538efba6",
    ),
    (
        "b0ed54aa-5bf4-4773-b8c0-f4d45b0ac583",
        "8396eac6-d9a2-4686-b66a-359d7085649f",
        "test_gamma_003", 1773754846228,
        "3b8ea9da7142bc2a8ef30aa36b75c4ad081fc24f60828d997bfe7b47249f526d",
    ),
]

# CDN base pattern — version placeholder filled in at runtime
_CDN_BASE    = "https://z-cdn.chatglm.cn/z-ai/frontend/{version}/_app/immutable/chunks/"

# Known signing chain filenames (from HAR initiator stack, prod-fe-1.0.262).
# Tried in order — first match wins. If all 404, fallback scans all page scripts.
_KNOWN_CHUNKS = [
    "COvEVlW5.js",   # main signing logic
    "DFZQlWS9.js",   # called from signing chain
    "AgMBD70M.js",   # fetch wrapper that adds X-Signature
    "Cu64bUoQ.js",   # window.fetch entry point
]

_FETCH_HEADERS = {
    "User-Agent": UA if "UA" in dir() else (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
    ),
    "Referer":    "https://chat.z.ai/",
    "Origin":     "https://chat.z.ai",
}


def _http_get(url: str, timeout: int = 15) -> Optional[str]:
    """Simple GET — uses curl_cffi if available, else urllib."""
    try:
        if CFFI_AVAILABLE:
            resp = cffi_requests.get(url, headers=_FETCH_HEADERS,
                                     timeout=timeout, impersonate="chrome124")
            if resp.status_code == 200:
                return resp.text
        else:
            import urllib.request
            req = urllib.request.Request(url, headers=_FETCH_HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def _detect_fe_version(html: str) -> Optional[str]:
    """
    Scan homepage HTML for the frontend version string.
    Looks for pattern: prod-fe-X.X.XXX
    Returns the version string or None.
    """
    import re
    m = re.search(r'prod-fe-\d+\.\d+\.\d+', html)
    return m.group(0) if m else None


def _scan_bundle_for_key(js_text: str) -> Optional[str]:
    """
    Scan a JS bundle for the HMAC master key.
    Tests candidates as: raw UTF-8, hex-decoded, base64-decoded.
    Returns the raw key string if verified against all 3 samples, else None.

    Priority order (from fetch_and_crack.py):
      1. Strings near signing keywords
      2. 32-128 char hex strings
      3. 32-128 char base64 strings
    """
    import re, base64

    def _test_key_str(candidate: str) -> Optional[str]:
        """Try a candidate string as utf8/hex/b64. Return it if it passes all 3 samples."""
        attempts = [candidate.encode("utf-8", errors="replace")]

        # hex decode
        clean = candidate.replace(" ", "").replace("-", "")
        if re.fullmatch(r"[0-9a-fA-F]+", clean) and len(clean) % 2 == 0 and len(clean) >= 16:
            try:
                attempts.append(bytes.fromhex(clean))
            except Exception:
                pass

        # base64 decode
        for pad in ["", "=", "=="]:
            try:
                dec = base64.b64decode(candidate + pad)
                if len(dec) >= 8:
                    attempts.append(dec)
                    break
            except Exception:
                pass

        for key_bytes in attempts:
            # Quick check: does this key produce the right signature for a temp engine?
            hits = 0
            for req_id, uid, p, ts, exp in _VERIFY_SAMPLES:
                try:
                    key_str = key_bytes.decode("utf-8")
                    # Build a temporary engine with this key to test
                    import math
                    ts_str = str(ts)
                    import base64 as _b64
                    v   = _b64.b64encode(p.encode("utf-8")).decode("ascii")
                    entries = sorted([("requestId", req_id), ("timestamp", ts_str), ("user_id", uid)])
                    n   = ",".join(f"{k},{val}" for k, val in entries)
                    d   = f"{n}|{v}|{ts_str}"
                    S   = math.floor(ts / (5 * 60 * 1000))
                    E   = hmac.new(key_str.encode("utf-8"), str(S).encode("utf-8"), hashlib.sha256).hexdigest()
                    sig = hmac.new(E.encode("utf-8"), d.encode("utf-8"), hashlib.sha256).hexdigest()
                    if sig == exp:
                        hits += 1
                except Exception:
                    pass
            if hits == len(_VERIFY_SAMPLES):
                # Full match — return the raw string form for MASTER_KEY
                try:
                    return key_bytes.decode("utf-8")
                except Exception:
                    return key_bytes.hex()  # fallback: store as hex string
        return None

    # Priority 1: strings near signing keywords
    kw_pat = re.compile(
        r'(?:hmac|HMAC|sign(?:ature)?|secret|SHA256|X-Signature|x-signature)'
        r'[^"\'`]{0,80}["\'\`]([^"\'`]{8,128})["\'\`]',
        re.IGNORECASE
    )
    for m in kw_pat.finditer(js_text):
        result = _test_key_str(m.group(1))
        if result:
            return result

    # Priority 2: 32-128 char hex strings
    for m in re.finditer(r'["\'\`]([0-9a-fA-F]{32,128})["\'\`]', js_text):
        result = _test_key_str(m.group(1))
        if result:
            return result

    # Priority 3: 32-128 char base64 strings
    for m in re.finditer(r'["\'\`]([A-Za-z0-9+/]{32,128}={0,2})["\'\`]', js_text):
        result = _test_key_str(m.group(1))
        if result:
            return result

    return None


def _auto_recover_key() -> Optional[tuple[str, str]]:
    """
    Auto-recovery pipeline. Called when the hardcoded MASTER_KEY fails verification.

    Steps:
      1. Fetch chat.z.ai homepage → detect new FE_VERSION
      2. Try known chunk filenames on new CDN path
      3. If any 404, collect all <script> URLs from homepage and scan those too
      4. If key found → save to sig_key_result.json, return (new_key, new_version)
      5. If not found → return None (caller will warn user)

    Returns:
        (master_key_str, fe_version_str) on success
        None on failure
    """
    import re

    print("  ⚠ HMAC key outdated — starting auto-recovery...")

    # ── Step 1: Detect new FE_VERSION ─────────────────────────────────────
    print("  → Fetching chat.z.ai to detect frontend version...")
    html = _http_get(BASE_URL, timeout=20)
    if not html:
        print("  ✗ Could not reach chat.z.ai — check your connection.")
        return None

    new_version = _detect_fe_version(html)
    if not new_version:
        print("  ✗ Could not detect FE_VERSION from homepage.")
        return None

    print(f"  → Detected version: {new_version}")

    # ── Step 2: Try known chunk filenames on new CDN path ─────────────────
    cdn_base = _CDN_BASE.format(version=new_version)
    print(f"  → CDN base: {cdn_base}")

    found_key = None
    scanned_urls: set = set()

    for filename in _KNOWN_CHUNKS:
        url = cdn_base + filename
        scanned_urls.add(url)
        print(f"  → Fetching {filename} ...")
        js_text = _http_get(url, timeout=20)
        if not js_text:
            print(f"    ✗ Not found (404 or error)")
            continue
        print(f"    ✓ {len(js_text):,} chars — scanning...")
        found_key = _scan_bundle_for_key(js_text)
        if found_key:
            print(f"    🔑 Key found in {filename}!")
            break

    # ── Step 3: Fallback — scan all <script> URLs from homepage ───────────
    if not found_key:
        print("  → Known filenames not found. Scanning all page scripts...")
        script_urls = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        # Also catch inline next.js chunk patterns
        chunk_urls  = re.findall(
            r'"([^"]*/_app/immutable/chunks/[^"]+\.js)"',
            html
        )
        all_urls = []
        for u in script_urls + chunk_urls:
            if not u.startswith("http"):
                u = BASE_URL + u
            if u not in scanned_urls:
                all_urls.append(u)
                scanned_urls.add(u)

        print(f"  → Found {len(all_urls)} additional scripts to scan")
        for url in all_urls:
            js_text = _http_get(url, timeout=15)
            if not js_text or len(js_text) < 100:
                continue
            found_key = _scan_bundle_for_key(js_text)
            if found_key:
                print(f"    🔑 Key found in {url.split('/')[-1]}!")
                break

    # ── Step 4: Save and return ────────────────────────────────────────────
    if found_key:
        result = {
            "hmac_key_str":              found_key,
            "fe_version":                new_version,
            "algorithm":                 "HMAC-SHA256",
            "auto_recovered":            True,
            "recovered_at":              datetime.now(timezone.utc).isoformat(),
        }
        try:
            with open(SIG_KEY_FILE, "w") as f:
                json.dump(result, f, indent=2)
            print(f"  ✅ New key saved → {SIG_KEY_FILE}")
        except Exception as e:
            print(f"  ⚠ Could not save key file: {e}")

        print(f"  ✅ Auto-recovery complete ({new_version})")
        return found_key, new_version

    print("  ❌ Auto-recovery failed — could not find key in any bundle.")
    print("     Run: python fetch_and_crack.py")
    return None


class SignatureEngine:
    """
    Computes X-Signature for Z.ai requests.

    Reverse-engineered from AgMBD70M.js (prod-fe-1.0.262).
    The signing function Ds(n, e, t) in the bundle:

        n = sortedPayload  — "requestId,<val>,timestamp,<val>,user_id,<val>"
                             (Object.entries({requestId,timestamp,user_id}).sort().join(","))
        e = prompt text    — the raw trimmed prompt string
        t = timestamp_ms   — Unix timestamp in milliseconds (string)

        v   = btoa(utf8_bytes(e))              # base64-encoded prompt
        d   = n + "|" + v + "|" + t            # full message
        S   = floor(ts / (5 * 60 * 1000))      # 5-minute time bucket
        E   = HMAC-SHA256(MASTER_KEY, str(S))  # ephemeral signing key
        sig = HMAC-SHA256(E, d).hexdigest()    # final X-Signature

    MASTER_KEY is hardcoded in the JS bundle, obfuscated with RC4+base64
    and a string-array shuffle. Extracted and verified against 3 live HAR
    samples (all 3 accounts, guest mode).

    On startup, the hardcoded key is verified. If it fails (Z.ai rotated their
    JS bundle), auto-recovery kicks in: fetches the new bundle from CDN,
    scans for the new key, verifies, saves to sig_key_result.json, and
    continues — all without user intervention.
    """

    MASTER_KEY = "key-@@@@)))()((9))-xxxx&&&%%%%%"

    def __init__(self):
        # No file loading needed — key is embedded above.
        # Verification happens in ZAIDirect.__init__() after instantiation.
        pass

    @classmethod
    def from_file(cls, path: str = SIG_KEY_FILE) -> "SignatureEngine":
        # Legacy shim — key is now hardcoded, file is ignored
        return cls()

    def sign(self, request_id: str, user_id: str, prompt: str, timestamp_ms: int) -> str:
        """
        Compute X-Signature.

        Args:
            request_id   : UUID for this specific request  (new uuid4 each call)
            user_id      : Account user ID from JWT payload
            prompt       : Trimmed prompt text (last user message)
            timestamp_ms : Current Unix time in milliseconds (int)

        Returns:
            64-char hex HMAC-SHA256 signature
        """
        import base64
        ts_str = str(timestamp_ms)

        # base64-encode the prompt bytes
        v = base64.b64encode(prompt.encode("utf-8")).decode("ascii")

        # sortedPayload: Object.entries({requestId, timestamp, user_id}).sort().join(",")
        entries = sorted([
            ("requestId", request_id),
            ("timestamp", ts_str),
            ("user_id",   user_id),
        ])
        n = ",".join(f"{k},{val}" for k, val in entries)

        # Full message: n + "|" + v + "|" + timestamp
        d = f"{n}|{v}|{ts_str}"

        # 5-minute time bucket → ephemeral key E
        import math
        S = math.floor(timestamp_ms / (5 * 60 * 1000))
        E = hmac.new(
            self.MASTER_KEY.encode("utf-8"),
            str(S).encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        # Final signature
        return hmac.new(
            E.encode("utf-8"),
            d.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def verify_against_samples(self) -> bool:
        """
        Sanity check against 3 known-good samples extracted from guest HAR.
        All from prod-fe-1.0.262, guest account 8396eac6...
        """
        return all(
            self.sign(req_id, uid, p, ts) == exp
            for req_id, uid, p, ts, exp in _VERIFY_SAMPLES
        )


# ── Account ────────────────────────────────────────────────────────────────────

class Account:
    """Single Z.ai account — JWT + cookies."""

    def __init__(self, data: Dict):
        self.jwt_token   = data.get("jwt_token") or data.get("token", "")
        self.user_id     = data.get("user_id", "")
        self.fe_version  = data.get("fe_version", FE_VERSION)
        self.cookies     = data.get("cookies", [])
        self.label       = data.get("label", self.user_id[:8])
        self._fail_count = 0
        self._last_fail  = 0.0
        self._lock       = threading.Lock()

    @classmethod
    def from_file(cls, path: str) -> "Account":
        with open(path) as f:
            data = json.load(f)
        return cls(data)

    @property
    def cookie_header(self) -> str:
        return "; ".join(
            f"{c['name']}={c['value']}"
            for c in self.cookies
            if c.get("domain", "").endswith("z.ai")
        )

    @property
    def is_healthy(self) -> bool:
        if self._fail_count >= 3:
            # Back off for 5 minutes after 3 failures
            if time.time() - self._last_fail < 300:
                return False
            # Reset after backoff
            self._fail_count = 0
        return True

    def mark_failure(self):
        with self._lock:
            self._fail_count += 1
            self._last_fail = time.time()

    def mark_success(self):
        with self._lock:
            self._fail_count = 0

    def __repr__(self):
        return f"Account({self.label})"


# ── Account Pool ───────────────────────────────────────────────────────────────

class AccountPool:
    """
    Multi-account round-robin pool with automatic failover.

    Looks for accounts in this order:
      1. zai_guest_accounts/  directory (guest_01.json … any *.json)
      2. z_ai_account.json  (legacy single-account file)
    """

    def __init__(self):
        self._accounts: List[Account] = []
        self._index    = 0
        self._lock     = threading.Lock()
        self._load()

    def _load(self):
        # Multi-account directory
        if os.path.isdir(ACCOUNTS_DIR):
            import glob
            for path in sorted(glob.glob(os.path.join(ACCOUNTS_DIR, "*.json"))):
                try:
                    acc = Account.from_file(path)
                    acc.label = os.path.basename(path).replace(".json", "")
                    self._accounts.append(acc)
                    print(f"  Loaded account: {acc.label} ({acc.user_id[:8]}...)")
                except Exception as e:
                    print(f"  ⚠ Skipped {path}: {e}")

        # Legacy single account
        if not self._accounts and os.path.exists(ACCOUNT_FILE):
            try:
                acc = Account.from_file(ACCOUNT_FILE)
                self._accounts.append(acc)
                print(f"  Loaded account: {acc.label}")
            except Exception as e:
                print(f"  ⚠ Could not load {ACCOUNT_FILE}: {e}")

        if not self._accounts:
            raise RuntimeError(
                "No accounts found.\n"
                "Run: python zai_setup_pool.py\n"
                "Or place account JSON files in: zai_guest_accounts/"
            )

        print(f"  Account pool ready: {len(self._accounts)} account(s)")

    def next(self) -> Account:
        """Round-robin, skipping unhealthy accounts."""
        with self._lock:
            for _ in range(len(self._accounts)):
                acc = self._accounts[self._index % len(self._accounts)]
                self._index += 1
                if acc.is_healthy:
                    return acc
        raise RuntimeError("All accounts are unhealthy. Try again later or re-run --setup.")

    def replace_account(self, old: "Account", new: "Account"):
        """
        Atomically swap a dead account for a freshly captured one.
        Preserves its position in the round-robin order.
        """
        with self._lock:
            for i, acc in enumerate(self._accounts):
                if acc is old:
                    self._accounts[i] = new
                    return

    def __len__(self):
        return len(self._accounts)


# ── Guest Refresher ────────────────────────────────────────────────────────────

class GuestRefresher:
    """
    Silently captures a fresh Z.ai guest session in a background thread
    when a 401 is detected on an account.

    Uses a lock to prevent two simultaneous refreshes (e.g. if two requests
    hit 401 at the same time on different accounts).

    Usage:
        refresher = GuestRefresher(pool)
        new_account = refresher.refresh(dead_account, account_path)
        # blocks until done or timeout
    """

    # How long to wait for a headless capture (seconds)
    TIMEOUT = 30

    def __init__(self, pool: AccountPool):
        self._pool    = pool
        self._lock    = threading.Lock()

    def refresh(self, dead: "Account", account_path: str) -> bool:
        """
        Capture a fresh guest session for `dead`, overwrite its file,
        and swap it into the pool.

        Runs the Playwright capture in a background thread.
        Blocks the caller until capture completes or times out.

        Returns True on success, False on failure.
        """
        # Only one refresh at a time — if another is in progress, wait for it
        acquired = self._lock.acquire(timeout=self.TIMEOUT)
        if not acquired:
            return False

        result_box: List[Optional[Account]] = [None]
        done_event = threading.Event()

        def _worker():
            try:
                new_acc = _capture_guest_session(
                    label=dead.label,
                    path=account_path,
                )
                result_box[0] = new_acc
            except Exception:
                result_box[0] = None
            finally:
                done_event.set()

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        done_event.wait(timeout=self.TIMEOUT)
        self._lock.release()

        new_acc = result_box[0]
        if new_acc:
            self._pool.replace_account(dead, new_acc)
            return True
        return False


def _capture_guest_session(label: str, path: str) -> Optional["Account"]:
    """
    Headless Playwright guest session capture.
    Mirrors zai_setup_pool.py's capture_guest_session() but returns
    an Account object directly (no print output — silent).

    Called by GuestRefresher in a background thread.
    """
    import base64 as _b64
    import re as _re

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return None

    jwt_token   = None
    user_id     = None
    fe_version  = FE_VERSION
    all_cookies = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-dev-shm-usage",
                ],
            )
            context = browser.new_context(
                user_agent=UA,
                locale="en-US",
                timezone_id="Asia/Manila",
            )
            page = context.new_page()
            # domcontentloaded is sufficient — Z.ai keeps background connections
            # open so networkidle never fires in headless mode.
            page.goto(BASE_URL, wait_until="domcontentloaded", timeout=25000)
            time.sleep(2)  # let cookie-setting JS run after DOM ready

            # Poll for guest token cookie
            deadline = time.time() + 20
            while time.time() < deadline:
                cookies = context.cookies(BASE_URL)
                token_cookie = next(
                    (c for c in cookies if c["name"] == "token"), None
                )
                if token_cookie:
                    jwt_token = token_cookie["value"]
                    break
                time.sleep(0.5)

            # Fallback: localStorage
            if not jwt_token:
                try:
                    jwt_token = page.evaluate("localStorage.getItem('token')")
                except Exception:
                    pass

            if not jwt_token:
                browser.close()
                return None

            # Decode user_id
            try:
                p64 = jwt_token.split(".")[1]
                p64 += "=" * (4 - len(p64) % 4)
                payload = json.loads(_b64.b64decode(p64))
                user_id = payload.get("id", "")
            except Exception:
                user_id = ""

            # Detect fe_version
            try:
                html = page.content()
                m = _re.search(r'prod-fe-\d+\.\d+\.\d+', html)
                if m:
                    fe_version = m.group(0)
            except Exception:
                pass

            all_cookies = context.cookies(BASE_URL)
            browser.close()

    except Exception:
        return None

    # Build account data dict
    data = {
        "label":       label,
        "jwt_token":   jwt_token,
        "user_id":     user_id,
        "fe_version":  fe_version,
        "cookies":     all_cookies,
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }

    # Overwrite the file (delete old, write fresh)
    try:
        if os.path.exists(path):
            os.remove(path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass  # file write failure is non-fatal — account still usable in memory

    return Account(data)


# ── URL Params Builder ─────────────────────────────────────────────────────────

def _build_url_params(
    account: Account,
    prompt: str,
    timestamp_ms: int,
    signature: str,
    request_id: str,
) -> Dict[str, str]:
    """
    Build the full query string that Z.ai expects.
    Based on exact params captured from your HAR files.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
              f"{int(time.time() * 1000) % 1000:03d}Z"
    now_utc = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

    return {
        "timestamp":           str(timestamp_ms),
        "requestId":           request_id,
        "user_id":             account.user_id,
        "version":             "0.0.1",
        "platform":            "web",
        "token":               account.jwt_token,
        "user_agent":          UA,
        "language":            "en-US",
        "languages":           "en-US,en",
        "timezone":            "Asia/Manila",
        "cookie_enabled":      "true",
        "screen_width":        "1366",
        "screen_height":       "768",
        "screen_resolution":   "1366x768",
        "viewport_height":     "641",
        "viewport_width":      "1366",
        "viewport_size":       "1366x641",
        "color_depth":         "32",
        "pixel_ratio":         "1",
        "current_url":         f"{BASE_URL}/",
        "pathname":            "/",
        "search":              "",
        "hash":                "",
        "host":                "chat.z.ai",
        "hostname":            "chat.z.ai",
        "protocol":            "https:",
        "referrer":            "",
        "title":               "Z.ai - Free AI Chatbot & Agent powered by GLM-5 & GLM-4.7",
        "timezone_offset":     "-480",
        "local_time":          now_iso,
        "utc_time":            now_utc,
        "is_mobile":           "false",
        "is_touch":            "false",
        "max_touch_points":    "0",
        "browser_name":        "Chrome",
        "os_name":             "Windows",
        "signature_timestamp": str(timestamp_ms),
    }


def _build_headers(account: Account, signature: str) -> Dict[str, str]:
    return {
        "Accept":             "text/event-stream",
        "Accept-Language":    "en-US,en;q=0.9",
        "Authorization":      f"Bearer {account.jwt_token}",
        "Content-Type":       "application/json",
        "Origin":             BASE_URL,
        "Referer":            f"{BASE_URL}/",
        "User-Agent":         UA,
        "X-FE-Version":       account.fe_version,
        "X-Signature":        signature,
        "Cookie":             account.cookie_header,
        "DNT":                "1",
        "Sec-Fetch-Dest":     "empty",
        "Sec-Fetch-Mode":     "cors",
        "Sec-Fetch-Site":     "same-origin",
    }


def _build_body(
    messages: List[Dict],
    prompt: str,
    model: str,
    stream: bool,
    chat_id: Optional[str] = None,
    user_name: str = "User",
    enable_thinking: bool = True,
) -> Dict:
    """
    Build POST body matching exactly what Z.ai's frontend sends.
    Variables like USER_NAME are informational — not signed.
    """
    now = datetime.now()
    msg_id = str(uuid.uuid4())
    cid    = chat_id or str(uuid.uuid4())

    return {
        "stream":    stream,
        "model":     model,
        "messages":  messages,
        "signature_prompt": prompt,
        "params":    {},
        "extra":     {},
        "features": {
            "image_generation": False,
            "web_search":       False,
            "auto_web_search":  False,
            "preview_mode":     True,
            "flags":            [],
            "enable_thinking":  enable_thinking,
        },
        "variables": {
            "{{USER_NAME}}":         user_name,
            "{{USER_LOCATION}}":     "Unknown",
            "{{CURRENT_DATETIME}}":  now.strftime("%Y-%m-%d %H:%M:%S"),
            "{{CURRENT_DATE}}":      now.strftime("%Y-%m-%d"),
            "{{CURRENT_TIME}}":      now.strftime("%H:%M:%S"),
            "{{CURRENT_WEEKDAY}}":   now.strftime("%A"),
            "{{CURRENT_TIMEZONE}}":  "Asia/Manila",
            "{{USER_LANGUAGE}}":     "en-US",
        },
        "chat_id":                        cid,
        "id":                             str(uuid.uuid4()),
        "current_user_message_id":        msg_id,
        "current_user_message_parent_id": None,
        "background_tasks": {
            "title_generation": True,
            "tags_generation":  True,
        },
    }


# ── SSE Parser ─────────────────────────────────────────────────────────────────

SSE_DEBUG = os.environ.get("ZAI_SSE_DEBUG", "").lower() in ("1", "true", "yes")


def _sse_debug(msg: str):
    if SSE_DEBUG:
        print(f"\n[SSE] {msg}", file=sys.stderr)


def _process_sse_line(line: bytes, thinking_buf: list, in_answer: bool):
    """
    Parse one SSE line.
    Returns (delta_to_yield_or_None, done: bool, in_answer: bool)

    Phase handling:
      - "thinking"     : buffer content, don't yield yet
      - "answer"       : yield content
      - anything else  : treat as answer if we're already in answer phase,
                         otherwise ignore (handles "answer_start", "", etc.)
    """
    line = line.strip()
    if not line:
        return None, False, in_answer
    if not line.startswith(b"data:"):
        return None, False, in_answer

    payload = line[5:].strip()

    if payload == b"[DONE]":
        _sse_debug("[DONE] received (raw)")
        return None, True, in_answer

    try:
        obj = json.loads(payload)
    except json.JSONDecodeError:
        _sse_debug(f"JSON decode error: {payload[:80]}")
        return None, False, in_answer

    d = obj.get("data", {})

    # Z.ai sometimes sends data: "[DONE]" as a JSON string instead of raw token
    if isinstance(d, str):
        if d.strip() == "[DONE]":
            _sse_debug("[DONE] received (json string)")
            return None, True, in_answer
        _sse_debug(f"data is string (non-DONE): {d[:80]}")
        return None, False, in_answer

    if not isinstance(d, dict):
        _sse_debug(f"data is not dict: {type(d)} => {str(d)[:80]}")
        return None, False, in_answer

    delta = d.get("delta_content", "")
    phase = d.get("phase", "")

    _sse_debug(f"phase={phase!r:20s} delta={repr(delta)[:60]}")

    # "done" phase signals end of stream — treat as [DONE]
    # NOTE: delta may carry the final token (e.g. "'s") — yield it before stopping
    if phase == "done":
        return delta if delta else None, True, in_answer

    if phase == "thinking":
        if delta:
            thinking_buf.append(delta)
        return None, False, in_answer

    if phase == "answer":
        return delta if delta else None, False, True

    # "other" or unknown phase — if we're already in answer mode keep streaming
    if in_answer and delta:
        return delta, False, True

    return None, False, in_answer


def _parse_sse_stream(raw_iter) -> Generator[str, None, None]:
    """
    Parse Z.ai SSE stream → yield text chunks (answer phase only).

    Z.ai SSE format:
        data: {"type":"chat:completion","data":{"delta_content":"...","phase":"thinking"}}
        data: {"type":"chat:completion","data":{"delta_content":"...","phase":"answer"}}
        data: [DONE]

    Yields only answer-phase delta_content. Falls back to thinking if no answer phase.

    Set env var ZAI_SSE_DEBUG=1 to print every raw SSE frame to stderr.
    """
    thinking_buf = []
    in_answer    = False
    buffer       = b""

    def handle_line(line: bytes):
        nonlocal in_answer
        delta, done, in_answer = _process_sse_line(line, thinking_buf, in_answer)
        return delta, done

    for chunk in raw_iter:
        if isinstance(chunk, str):
            chunk = chunk.encode()
        buffer += chunk

        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            delta, done = handle_line(line)
            if done:
                # Flush leftover buffer before stopping (rare but possible)
                if buffer.strip():
                    delta2, _ = handle_line(buffer)
                    if delta2:
                        yield delta2
                return
            if delta:
                yield delta

    # Flush any bytes that arrived without a trailing newline
    if buffer.strip():
        delta, done = handle_line(buffer)
        if delta:
            yield delta

    # If no answer phase was ever seen, fall back to thinking content
    if not in_answer and thinking_buf:
        yield "".join(thinking_buf)


def _parse_sse_full(raw_text: str) -> tuple[str, str]:
    """
    Parse full SSE text → (thinking_text, answer_text).
    Returns (thinking, "") if no answer phase, ("", answer) otherwise.
    """
    thinking_parts = []
    answer_parts   = []

    for line in raw_text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            break
        try:
            obj   = json.loads(payload)
            d     = obj.get("data", {})
            # FIX: Handle case where data is a string instead of dict
            if not isinstance(d, dict):
                continue
            delta = d.get("delta_content", "")
            phase = d.get("phase", "")
            if phase == "thinking":
                thinking_parts.append(delta)
            elif phase == "answer":
                answer_parts.append(delta)
        except json.JSONDecodeError:
            pass

    return "".join(thinking_parts), "".join(answer_parts)


# ── HTTP Engine ────────────────────────────────────────────────────────────────

class HTTPEngine:
    """Handles the actual HTTP request — curl_cffi preferred, urllib fallback."""

    def __init__(self):
        self._session = cffi_requests.Session(impersonate="chrome124") if CFFI_AVAILABLE else None

    def post_stream(self, url: str, headers: Dict, body: Dict):
        """POST and return a streaming response iterator."""
        data = json.dumps(body, separators=(",", ":"))

        if CFFI_AVAILABLE:
            return self._session.post(
                url,
                headers=headers,
                data=data,
                stream=True,
                timeout=60,
            )
        else:
            # urllib fallback
            req = urllib.request.Request(
                url,
                data=data.encode(),
                headers=headers,
                method="POST",
            )
            return urllib.request.urlopen(req, timeout=60)

    def close(self):
        if self._session:
            self._session.close()


# ── Refresh Status Line ────────────────────────────────────────────────────────
# Printed to stderr so it doesn't interfere with streaming stdout output.
# zai_chat.py clears it after the refresh completes.

_REFRESH_MSG = "\033[2m  ⟳ Refreshing session...\033[0m"

def _refresh_status_print():
    """Print dim 'Refreshing session...' line to stderr."""
    print(_REFRESH_MSG, end="\r", flush=True, file=sys.stderr)

def _refresh_status_clear():
    """Erase the refresh status line from stderr."""
    print("\033[2K", end="\r", flush=True, file=sys.stderr)


# ── ZAIDirect Client ───────────────────────────────────────────────────────────

class ZAIDirect:
    """
    Drop-in replacement for ZAI / ZAIPersistent.
    No browser. Direct HTTP with computed X-Signature.

    Requires sig_key_result.json (from extract_hmac_key.py).
    """

    def __init__(
        self,
        model:    str = "glm-5",
        sig_key:  Optional[str] = None,   # ignored, kept for API compat
        verbose:  bool = False,
    ):
        self.default_model = model
        self.verbose       = verbose

        # Signature engine — key is hardcoded, no file needed
        self.signer = SignatureEngine()

        if not self.signer.verify_against_samples():
            # Key failed — attempt auto-recovery before giving up
            result = _auto_recover_key()
            if result:
                new_key, new_version = result
                self.signer.MASTER_KEY = new_key
                # Also update module-level FE_VERSION for outgoing requests
                import sys
                sys.modules[__name__].__dict__["FE_VERSION"] = new_version
                if not self.signer.verify_against_samples():
                    print("⚠ WARNING: Recovered key still fails verification — requests may fail.")
            else:
                print("⚠ WARNING: HMAC key outdated and auto-recovery failed.")
                print("           Run: python fetch_and_crack.py")
        elif verbose:
            print("✅ HMAC signing verified against known samples.")

        # Load account pool + guest refresher
        self.pool      = AccountPool()
        self.http      = HTTPEngine()
        self.refresher = GuestRefresher(self.pool)
        self._lock     = threading.Lock()

    def _log(self, *args):
        if self.verbose:
            print(*args)

    def chat(
        self,
        messages:        List[Dict[str, str]],
        model:           Optional[str] = None,
        stream:          bool = True,
        chat_id:         Optional[str] = None,
        max_retry:       int = 2,
        enable_thinking: bool = True,
    ) -> Generator[str, None, None] | str:
        """
        Send a chat request.

        Args:
            messages        : OpenAI-style [{"role":"user","content":"..."}]
            model           : "glm-5" or "glm-4.7"
            stream          : True → yields text chunks; False → returns full string
            chat_id         : Reuse a conversation. None = new conversation.
            max_retry       : Retries on transient errors.
            enable_thinking : Whether to enable GLM chain-of-thought reasoning.

        Returns:
            Generator[str] if stream=True, str if stream=False.
        """
        model = model or self.default_model
        # Extract prompt — last user message is what gets signed
        prompt = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                content = m.get("content", "")
                prompt = content if isinstance(content, str) else str(content)
                break

        if stream:
            return self._chat_stream(messages, prompt, model, chat_id, max_retry, enable_thinking)
        else:
            return self._chat_sync(messages, prompt, model, chat_id, max_retry, enable_thinking)

    def _chat_stream(self, messages, prompt, model, chat_id, max_retry, enable_thinking=True):
        # 429 backoff state — shared across attempts
        _backoff = [2.0]   # mutable so inner scope can update it

        for attempt in range(max_retry + 1):
            account = self.pool.next()
            ts      = int(time.time() * 1000)
            req_id  = str(uuid.uuid4())
            sig     = self.signer.sign(req_id, account.user_id, prompt, ts)

            params  = _build_url_params(account, prompt, ts, sig, req_id)
            headers = _build_headers(account, sig)
            body    = _build_body(messages, prompt, model, stream=True,
                                  chat_id=chat_id, enable_thinking=enable_thinking)
            url     = COMPLETIONS_URL + "?" + urlencode(params)

            self._log(f"  → Request: ts={ts} sig={sig[:12]}... account={account.label}")

            try:
                resp = self.http.post_stream(url, headers, body)
                if CFFI_AVAILABLE:

                    # ── 401: Session expired → silent guest refresh ────────────
                    if resp.status_code == 401:
                        account.mark_failure()
                        self._log(f"  ✗ 401 on {account.label} — refreshing session")

                        # Find the file path for this account
                        acc_path = os.path.join(ACCOUNTS_DIR, f"{account.label}.json")
                        if not os.path.exists(acc_path):
                            acc_path = ACCOUNT_FILE  # legacy fallback

                        # Signal UI to show dim status line
                        _refresh_status_print()

                        ok = self.refresher.refresh(account, acc_path)

                        # Clear the status line
                        _refresh_status_clear()

                        if ok:
                            self._log(f"  ✅ Session refreshed for {account.label}")
                            # Don't count this as a retry attempt — just loop
                            continue
                        else:
                            self._log(f"  ✗ Refresh failed for {account.label}")
                            if attempt < max_retry:
                                continue
                            raise RuntimeError(
                                f"Session expired on {account.label} and "
                                f"auto-refresh failed.\n"
                                f"Run: python zai_setup_pool.py --refill"
                            )

                    # ── 429: Rate limited → exponential backoff ───────────────
                    elif resp.status_code == 429:
                        wait = _backoff[0]
                        _backoff[0] = min(wait * 2, 60.0)  # cap at 60s
                        self._log(
                            f"  ✗ 429 Rate limited on {account.label} "
                            f"— waiting {wait:.0f}s"
                        )
                        account.mark_failure()
                        if attempt < max_retry:
                            time.sleep(wait)
                            continue
                        raise RuntimeError(
                            f"Z.ai rate limit hit after {attempt+1} attempts. "
                            f"Wait a moment and try again."
                        )

                    # ── Other non-200 ─────────────────────────────────────────
                    elif resp.status_code != 200:
                        self._log(f"  ✗ HTTP {resp.status_code} — retrying")
                        account.mark_failure()
                        if attempt < max_retry:
                            time.sleep(1)
                            continue
                        raise RuntimeError(f"Z.ai returned HTTP {resp.status_code}")

                    # ── 200: Success ──────────────────────────────────────────
                    account.mark_success()
                    yield from _parse_sse_stream(resp.iter_content(chunk_size=256))

                else:
                    account.mark_success()
                    yield from _parse_sse_stream(resp)
                return

            except RuntimeError:
                raise  # surface clean error messages directly

            except Exception as e:
                self._log(f"  ✗ Error on attempt {attempt+1}: {e}")
                account.mark_failure()
                if attempt < max_retry:
                    time.sleep(1.5)
                else:
                    raise

    def _chat_sync(self, messages, prompt, model, chat_id, max_retry, enable_thinking=True):
        chunks = list(self._chat_stream(messages, prompt, model, chat_id, max_retry, enable_thinking))
        return "".join(chunks)

    def close(self):
        self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ── OpenAI-Compatible Wrapper ──────────────────────────────────────────────────

class ZAIOpenAICompat:
    """
    Wraps ZAIDirect in an OpenAI-compatible interface.
    Use as a drop-in replacement for openai.OpenAI() in simple cases.

    Example:
        client = ZAIOpenAICompat()
        resp = client.chat.completions.create(
            model="glm-5",
            messages=[{"role":"user","content":"Hi!"}],
            stream=False,
        )
        print(resp.choices[0].message.content)
    """

    class _Completions:
        def __init__(self, zai: ZAIDirect):
            self._zai = zai

        def create(self, model="glm-5", messages=None, stream=False, **kwargs):
            messages = messages or []
            if stream:
                return self._zai.chat(messages, model=model, stream=True)
            else:
                text = self._zai.chat(messages, model=model, stream=False)
                return _MockResponse(text, model)

    class _Chat:
        def __init__(self, zai: ZAIDirect):
            self.completions = ZAIOpenAICompat._Completions(zai)

    def __init__(self, **kwargs):
        self._zai = ZAIDirect(**kwargs)
        self.chat = ZAIOpenAICompat._Chat(self._zai)

    def close(self):
        self._zai.close()


class _MockResponse:
    """Mimics openai.types.chat.ChatCompletion just enough for .choices[0].message.content"""
    def __init__(self, text: str, model: str):
        self.model = model
        self.choices = [type("Choice", (), {
            "message": type("Message", (), {"content": text, "role": "assistant"})(),
            "finish_reason": "stop",
        })()]


# ── Setup Utility ──────────────────────────────────────────────────────────────

def setup_multi_account(accounts_data: List[Dict], output_dir: str = ACCOUNTS_DIR):
    """
    Convert your key_and_tokens_acc*.txt captures into account JSON files.
    
    Usage:
        from zai_direct import setup_multi_account
        
        # Each dict is the data from your key_and_tokens_acc*.txt files
        accounts = [
            {
                "label": "acc1",
                "jwt_token": "eyJhbG...",
                "user_id": "08ba2870-...",
                "cookies": [...]
            },
            ...
        ]
        setup_multi_account(accounts)
    """
    os.makedirs(output_dir, exist_ok=True)
    for acc in accounts_data:
        label = acc.get("label", str(uuid.uuid4())[:8])
        path  = os.path.join(output_dir, f"{label}.json")
        with open(path, "w") as f:
            json.dump({
                "label":      label,
                "jwt_token":  acc.get("jwt_token", ""),
                "user_id":    acc.get("user_id", ""),
                "fe_version": acc.get("fe_version", FE_VERSION),
                "cookies":    acc.get("cookies", []),
            }, f, indent=2)
        print(f"  Saved: {path}")
    print(f"\n✅ {len(accounts_data)} account(s) saved to {output_dir}/")


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Z.ai Direct HTTP Client")
    parser.add_argument("message", nargs="?", help="Message to send")
    parser.add_argument("--model", default="glm-5", choices=SUPPORTED_MODELS)
    parser.add_argument("--no-stream", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--verify-key", action="store_true",
                        help="Just verify the HMAC key and exit")
    args = parser.parse_args()

    if args.verify_key:
        signer = SignatureEngine()
        ok = signer.verify_against_samples()
        if ok:
            print("✅ HMAC signing verified — all 3 samples match.")
        else:
            print("❌ HMAC signing FAILED verification.")
        sys.exit(0 if ok else 1)

    if not args.message:
        print("Usage: python zai_direct.py \"Your message here\"")
        print("       python zai_direct.py --verify-key")
        sys.exit(1)

    print(f"[ZAI Direct] Sending: {args.message!r}")
    start = time.time()

    try:
        with ZAIDirect(model=args.model, verbose=args.verbose) as client:
            if args.no_stream:
                result = client.chat(
                    [{"role": "user", "content": args.message}],
                    stream=False,
                )
                elapsed = time.time() - start
                print(f"\n{result}")
                print(f"\n[{elapsed:.2f}s]")
            else:
                for chunk in client.chat(
                    [{"role": "user", "content": args.message}],
                    stream=True,
                ):
                    print(chunk, end="", flush=True)
                elapsed = time.time() - start
                print(f"\n\n[{elapsed:.2f}s]")

    except FileNotFoundError as e:
        print(f"\n❌ {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        raise