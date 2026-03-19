"""
zai_setup_pool.py — One-Time Guest Pool Setup
===============================================
Captures N fresh Z.ai guest sessions headlessly via Playwright.
No login required — Z.ai hands a guest token to any visitor automatically.

Each session is saved as zai_guest_accounts/guest_XX.json containing:
  - jwt_token   : ES256 JWT (no expiry claim — server-side session)
  - user_id     : UUID extracted from JWT payload
  - fe_version  : Frontend version string detected from page
  - cookies     : All z.ai-domain cookies (includes cdn_sec_tc, token, ssxmod_*)
  - label       : "guest_XX"
  - captured_at : ISO timestamp

Usage:
    python zai_setup_pool.py           # capture 10 accounts (default)
    python zai_setup_pool.py --count 5 # capture 5 accounts
    python zai_setup_pool.py --refill  # only capture missing slots up to target

Requirements:
    pip install playwright
    playwright install chromium
"""

from __future__ import annotations

import argparse
import base64
import glob
import json
import os
import re
import sys
import time
from datetime import datetime, timezone

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
except ImportError:
    print("❌ Playwright not installed.")
    print("   pip install playwright && playwright install chromium")
    sys.exit(1)


# ── Constants ──────────────────────────────────────────────────────────────────

_HERE        = os.path.dirname(os.path.abspath(__file__))
ACCOUNTS_DIR = os.path.join(_HERE, "zai_guest_accounts")
BASE_URL     = "https://chat.z.ai"
DEFAULT_COUNT = 10

# How long to wait for Z.ai to issue a guest token (seconds)
TOKEN_TIMEOUT = 30

# Delay between captures to avoid looking like a bot
CAPTURE_DELAY = 2.0


# ── ANSI helpers ───────────────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    CYAN   = "\033[96m"

def _enable_windows_ansi():
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
        except Exception:
            for a in ["RESET","BOLD","DIM","GREEN","YELLOW","RED","CYAN"]:
                setattr(C, a, "")

def bar(label: str):
    print(f"\n{C.DIM}{'─'*50}{C.RESET}")
    print(f"  {C.BOLD}{label}{C.RESET}")
    print(f"{C.DIM}{'─'*50}{C.RESET}")


# ── Core capture function ──────────────────────────────────────────────────────

def capture_guest_session(label: str) -> dict | None:
    """
    Launch a headless Chromium, visit chat.z.ai, and capture the
    auto-issued guest JWT + cookies.

    Z.ai issues a guest token automatically to any visitor — no login needed.
    The token appears in both localStorage and as a 'token' cookie.

    Returns account dict on success, None on failure.
    """
    jwt_token   = None
    user_id     = None
    fe_version  = "prod-fe-1.0.262"   # fallback — updated from page if found
    all_cookies = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-dev-shm-usage",   # stability on some systems
                ],
            )

            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/146.0.0.0 Safari/537.36"
                ),
                locale="en-US",
                timezone_id="Asia/Manila",
            )

            page = context.new_page()

            # Navigate — domcontentloaded is sufficient.
            # Z.ai keeps background connections open so networkidle never fires.
            page.goto(BASE_URL, wait_until="domcontentloaded", timeout=30000)

            # Brief pause to let cookie-setting JS run after DOM is ready
            time.sleep(2)

            # Poll for the guest token cookie (Z.ai sets it on page load)
            deadline = time.time() + TOKEN_TIMEOUT
            while time.time() < deadline:
                cookies = context.cookies(BASE_URL)
                token_cookie = next(
                    (c for c in cookies if c["name"] == "token"), None
                )
                if token_cookie:
                    jwt_token = token_cookie["value"]
                    break
                time.sleep(0.5)

            if not jwt_token:
                # Fallback: try reading from localStorage
                try:
                    jwt_token = page.evaluate(
                        "localStorage.getItem('token')"
                    )
                except Exception:
                    pass

            if not jwt_token:
                print(f"  {C.RED}✗ No token issued for {label}{C.RESET}")
                browser.close()
                return None

            # Decode user_id from JWT payload
            try:
                payload_b64 = jwt_token.split(".")[1]
                payload_b64 += "=" * (4 - len(payload_b64) % 4)
                payload = json.loads(base64.b64decode(payload_b64))
                user_id = payload.get("id", "")
            except Exception:
                user_id = str(hash(jwt_token))[:8]

            # Detect FE_VERSION from page HTML
            try:
                html = page.content()
                m = re.search(r'prod-fe-\d+\.\d+\.\d+', html)
                if m:
                    fe_version = m.group(0)
            except Exception:
                pass

            # Capture all z.ai cookies
            all_cookies = context.cookies(BASE_URL)

            browser.close()

    except PWTimeout:
        print(f"  {C.RED}✗ Timeout capturing {label}{C.RESET}")
        return None
    except Exception as e:
        print(f"  {C.RED}✗ Error capturing {label}: {e}{C.RESET}")
        return None

    return {
        "label":        label,
        "jwt_token":    jwt_token,
        "user_id":      user_id,
        "fe_version":   fe_version,
        "cookies":      all_cookies,
        "captured_at":  datetime.now(timezone.utc).isoformat(),
    }


# ── Save helper ────────────────────────────────────────────────────────────────

def save_account(data: dict, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ── Pool status ────────────────────────────────────────────────────────────────

def pool_status() -> list[str]:
    """Return list of existing guest JSON paths in accounts dir."""
    if not os.path.isdir(ACCOUNTS_DIR):
        return []
    return sorted(glob.glob(os.path.join(ACCOUNTS_DIR, "guest_*.json")))


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    _enable_windows_ansi()

    parser = argparse.ArgumentParser(
        description="Capture Z.ai guest sessions for the account pool"
    )
    parser.add_argument(
        "--count", type=int, default=DEFAULT_COUNT,
        help=f"Number of guest accounts to capture (default: {DEFAULT_COUNT})"
    )
    parser.add_argument(
        "--refill", action="store_true",
        help="Only capture missing slots up to --count (skip existing)"
    )
    args = parser.parse_args()

    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════╗
║       Z.ai Guest Pool Setup              ║
╚══════════════════════════════════════════╝{C.RESET}""")

    os.makedirs(ACCOUNTS_DIR, exist_ok=True)

    # Determine which slots need capturing
    existing = pool_status()
    existing_labels = {
        os.path.basename(p).replace(".json", "")
        for p in existing
    }

    target_labels = [f"guest_{i:02d}" for i in range(1, args.count + 1)]

    if args.refill:
        to_capture = [l for l in target_labels if l not in existing_labels]
        print(f"\n  {C.DIM}Refill mode — {len(existing)} existing, "
              f"{len(to_capture)} missing{C.RESET}")
    else:
        to_capture = target_labels
        print(f"\n  {C.DIM}Full capture — {len(to_capture)} guest accounts{C.RESET}")

    if not to_capture:
        print(f"\n  {C.GREEN}✅ Pool already complete "
              f"({len(existing)} accounts){C.RESET}\n")
        return

    print(f"  {C.DIM}Output → {ACCOUNTS_DIR}{C.RESET}")
    print(f"  {C.DIM}Each capture takes ~5–10 seconds{C.RESET}\n")

    succeeded = 0
    failed    = 0

    for i, label in enumerate(to_capture, 1):
        bar(f"[{i}/{len(to_capture)}] Capturing {label}...")

        account = capture_guest_session(label)

        if account:
            path = os.path.join(ACCOUNTS_DIR, f"{label}.json")
            save_account(account, path)
            succeeded += 1
            uid_short = account["user_id"][:8] if account["user_id"] else "?"
            print(f"  {C.GREEN}✅ {label}{C.RESET}  "
                  f"{C.DIM}user_id={uid_short}...  "
                  f"fe={account['fe_version']}  "
                  f"cookies={len(account['cookies'])}{C.RESET}")
        else:
            failed += 1
            print(f"  {C.RED}✗ {label} failed — skipping{C.RESET}")

        # Brief delay between captures
        if i < len(to_capture):
            time.sleep(CAPTURE_DELAY)

    # ── Final report ───────────────────────────────────────────────────────────
    print(f"\n{C.DIM}{'─'*50}{C.RESET}")
    print(f"\n  {C.BOLD}Done.{C.RESET}")
    print(f"  {C.GREEN}✅ Succeeded : {succeeded}{C.RESET}")
    if failed:
        print(f"  {C.RED}✗  Failed    : {failed}{C.RESET}")

    total = len(pool_status())
    print(f"  {C.DIM}Pool total  : {total} account(s) in {ACCOUNTS_DIR}{C.RESET}")

    if succeeded > 0:
        print(f"\n  {C.DIM}You're ready. Run:{C.RESET}")
        print(f"  {C.CYAN}python zai_chat.py{C.RESET}\n")
    else:
        print(f"\n  {C.RED}All captures failed.{C.RESET}")
        print(f"  {C.DIM}Check your internet connection and try again.{C.RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
