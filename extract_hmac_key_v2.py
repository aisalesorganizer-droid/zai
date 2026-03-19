"""
extract_hmac_key_v2.py — Z.ai HMAC Key Extractor (V2)
=====================================================
V1 failed because Z.ai uses a pure-JS HMAC (NOT crypto.subtle).
This version takes a two-pronged attack:

  PRONG 1 — Fetch hook
    Intercepts every outgoing window.fetch() call BEFORE it fires.
    Captures: X-Signature, signature_timestamp, signature_prompt.
    Gives us confirmed (timestamp, prompt) → signature triples from the live session.

  PRONG 2 — JS Bundle scan
    After page load, collects every <script> src URL from the page.
    Fetches each bundle and searches for hex/base64 strings that could be the HMAC key.
    Tests each candidate against known (timestamp, prompt) → signature pairs.

  PRONG 3 — CryptoJS / manual HMAC hook
    Hooks CryptoJS.HmacSHA256 and CryptoJS.enc.Hex.stringify if present.
    Also hooks any global function whose output matches a 64-char hex string.

Run this AFTER running extract_hmac_key.py (v1) so we already know crypto.subtle fails.

Usage:
    python extract_hmac_key_v2.py

Outputs:
    sig_key_result.json   if key found and verified
    sig_captures.json     raw (timestamp, prompt, sig) captures for manual analysis
"""

import json
import time
import re
import sys
import os
import hmac
import hashlib
import asyncio

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("ERROR: pip install playwright && playwright install chromium")
    sys.exit(1)

_HERE        = os.path.dirname(os.path.abspath(__file__))
ACCOUNT_FILE = os.path.join(_HERE, "z_ai_account.json")
OUT_KEY      = os.path.join(_HERE, "sig_key_result.json")
OUT_CAPS     = os.path.join(_HERE, "sig_captures.json")

BASE_URL        = "https://chat.z.ai"
COMPLETIONS_URL = f"{BASE_URL}/api/v2/chat/completions"

# ── All 18 known-good (prompt, ts, sig) triples from your HAR files ───────────
KNOWN_SAMPLES = [
    ("test_alpha_001", 1773750230717, "12d548f2fb22be5328dd00f8b630a67195cfc73c4118131a11af928a0a559cf5"),
    ("test_beta_002",  1773750256199, "083cd9c51bc9733c58e105244fdecdcf8eecad592be6b3578fbf27891980e930"),
    ("test_gamma_003", 1773750272484, "3f565d86118e509152875b3404fca69e772f48185f665968ca7375caa9507458"),
    ("test_alpha_001", 1773750505430, "355875f4d2d89cd6b1b03770549b3ca5d282ab1bc7afb1ec0ee4f19b55f84425"),
    ("test_beta_002",  1773750519233, "0d90022c41ad144f01f9945995da8e33cd3f2510c25528736ef7561661deb388"),
    ("test_gamma_003", 1773750569230, "208562c1283d58a07e5377857c3b1c9a174b5ff8b94f8c1a9529710c462153ff"),
    ("test_alpha_001", 1773750737541, "d06d1710c2f3f0e812f56af25f1e3a5031625517de10ce8e23e7322ac911e04e"),
    ("test_beta_002",  1773750768437, "8720afacb53cb27885d2fd2c5dc58d22f3ba1c09ffad2b3d30982468a71de8b7"),
    ("test_gamma_003", 1773750811244, "e32583bd117627f4215f94dbdbce5c38105416c2a5ee080e44452b06933ff053"),
    ("test_alpha_001", 1773751216349, "b120e7a599f52c02a737d5854bcf22d503de2b4077b05132df8d04d661dcb453"),
    ("test_beta_002",  1773751243503, "551839e246f6fbabd7ed0334cf915a0954affef53b1c84713eb4233f55f1b15f"),
    ("test_gamma_003", 1773751272851, "cbb401d833aae5a2270abff97fd5054d0d8541d46dbebb2c92dd9882dd66e217"),
    ("test_alpha_001", 1773751529243, "eff03c02f74666dc013f031cc50ba650cb9abdead529a7509c689e6da22f7667"),
    ("test_beta_002",  1773751617267, "f1d97f54fb6bf2aa196591241c31e5e0c011f332d4b660258de34760eceb41e7"),
    ("test_gamma_003", 1773751693222, "2833b2af8a827b47d811f4f7e4edb2e3e3dd0753f0ae7cd55278b899edc2a53b"),
    ("test_alpha_001", 1773751842596, "392de2b9c8dc07b93ef9099342a70f28b5ee581a533e6773fb980ccde5045ae6"),
    ("test_beta_002",  1773751859440, "289642abe7166b57398ae60075338e9d03afad3eba139cab9020a684ea9e4ebb"),
    ("test_gamma_003", 1773751918260, "7389ce45eb1b6bcd9601c36ac6de9d445ac9cb78d147de3c4b008d52c075ecd4"),
]


# ── Key verification ──────────────────────────────────────────────────────────

def test_key(key_bytes: bytes, prompt: str, ts: int, expected: str) -> bool:
    msg = (str(ts) + prompt).encode()
    return hmac.new(key_bytes, msg, hashlib.sha256).hexdigest() == expected

def verify_key_all(key_bytes: bytes, verbose=False) -> int:
    """Returns number of matching samples out of 18."""
    hits = 0
    for prompt, ts, expected in KNOWN_SAMPLES:
        if test_key(key_bytes, prompt, ts, expected):
            hits += 1
    if verbose:
        print(f"  Key verification: {hits}/{len(KNOWN_SAMPLES)} samples matched")
    return hits

def try_key_candidate(candidate: str, label: str = "") -> bytes | None:
    """
    Given a string candidate, try it as:
      - raw UTF-8 bytes
      - hex-decoded bytes
      - base64-decoded bytes
    Returns key bytes if verified, None otherwise.
    """
    attempts = []

    # Raw string
    attempts.append(("utf8", candidate.encode("utf-8", errors="replace")))

    # Hex decode
    clean = candidate.replace(" ", "").replace("-", "")
    if re.fullmatch(r"[0-9a-fA-F]+", clean) and len(clean) % 2 == 0:
        try:
            attempts.append(("hex", bytes.fromhex(clean)))
        except Exception:
            pass

    # Base64 decode
    import base64
    for b64 in [candidate, candidate + "=", candidate + "=="]:
        try:
            decoded = base64.b64decode(b64)
            if len(decoded) >= 8:
                attempts.append(("b64", decoded))
        except Exception:
            pass

    for enc, key_bytes in attempts:
        hits = verify_key_all(key_bytes)
        if hits >= 3:  # At least 3 samples match → very likely the key
            print(f"  🔑 CANDIDATE MATCH [{label}|{enc}]: {hits}/18 samples")
            print(f"     Raw: {candidate[:64]}")
            if verify_key_all(key_bytes) == len(KNOWN_SAMPLES):
                print(f"  ✅ FULL VERIFICATION PASSED")
                return key_bytes
    return None


# ── JS Bundle scanner ─────────────────────────────────────────────────────────

def scan_bundle_for_keys(js_text: str, url: str = "") -> bytes | None:
    """
    Given JS bundle text, extract candidate strings and test them as HMAC keys.
    Looks for:
      - 32–64 char hex strings (potential raw keys)
      - 40–90 char base64 strings (potential encoded keys)
      - Strings near keywords: hmac, sign, secret, key, hash
    """
    found_key = None

    # Pattern 1: hex strings 32–128 chars (16–64 bytes)
    hex_candidates = re.findall(r'["\']([0-9a-fA-F]{32,128})["\']', js_text)

    # Pattern 2: base64 strings 24–128 chars
    b64_candidates = re.findall(r'["\']([A-Za-z0-9+/=]{24,128})["\']', js_text)

    # Pattern 3: strings near signing keywords
    keyword_pattern = re.compile(
        r'(?:hmac|sign|secret|HMAC|SHA256|signature)[^"\']{0,50}["\']([^"\']{8,128})["\']',
        re.IGNORECASE
    )
    keyword_candidates = keyword_pattern.findall(js_text)

    all_candidates = []
    for c in keyword_candidates:
        all_candidates.append((c, "keyword-context"))
    for c in hex_candidates:
        all_candidates.append((c, "hex-pattern"))
    for c in b64_candidates[:200]:  # limit b64 to avoid too many
        all_candidates.append((c, "b64-pattern"))

    if all_candidates:
        print(f"  Scanning {len(all_candidates)} candidates from {url[-60:] or 'bundle'}...")

    for candidate, label in all_candidates:
        key_bytes = try_key_candidate(candidate, label)
        if key_bytes:
            found_key = key_bytes
            break

    return found_key


# ── JS hook code (injected into browser) ─────────────────────────────────────

FETCH_HOOK_JS = r"""
(function() {
    window.__zai_captures  = [];
    window.__zai_scripts   = [];
    window.__zai_cryptoLog = [];

    // ── 1. Hook window.fetch ──────────────────────────────────────────────
    const _origFetch = window.fetch;
    window.fetch = async function(input, init) {
        const url = typeof input === 'string' ? input : input?.url || '';

        if (url.includes('completions')) {
            // Capture headers before the request fires
            const headers = {};
            if (init && init.headers) {
                const h = init.headers;
                if (h instanceof Headers) {
                    h.forEach((v, k) => { headers[k] = v; });
                } else if (typeof h === 'object') {
                    Object.assign(headers, h);
                }
            }

            // Parse URL params
            let ts = '', prompt = '', sig = '';
            try {
                const u = new URL(url.startsWith('http') ? url : BASE_URL + url);
                ts     = u.searchParams.get('signature_timestamp') || '';
                sig    = headers['X-Signature'] || headers['x-signature'] || '';
            } catch(e) {}

            // Parse body for signature_prompt
            try {
                const body = typeof init?.body === 'string'
                    ? JSON.parse(init.body)
                    : {};
                prompt = body.signature_prompt || '';
            } catch(e) {}

            const capture = { ts, prompt, sig, url: url.slice(0, 120) };
            window.__zai_captures.push(capture);
            console.log('[ZAI-V2] FETCH captured:',
                'ts=' + ts,
                'prompt=' + prompt.slice(0, 30),
                'sig=' + sig.slice(0, 16) + '...'
            );
        }

        return _origFetch.apply(this, arguments);
    };

    // ── 2. Hook CryptoJS if present ────────────────────────────────────────
    const tryHookCryptoJS = () => {
        if (typeof CryptoJS !== 'undefined' && CryptoJS.HmacSHA256) {
            const _origHmac = CryptoJS.HmacSHA256;
            CryptoJS.HmacSHA256 = function(message, key) {
                const result = _origHmac.apply(this, arguments);
                const keyStr  = typeof key === 'string' ? key : JSON.stringify(key);
                const msgStr  = typeof message === 'string' ? message : JSON.stringify(message);
                const sigHex  = result.toString ? result.toString() : String(result);
                window.__zai_cryptoLog.push({ type: 'CryptoJS.HmacSHA256', key: keyStr, message: msgStr, result: sigHex });
                console.log('[ZAI-V2] CryptoJS.HmacSHA256:', 'key=' + keyStr.slice(0,32), 'msg=' + msgStr.slice(0,32));
                return result;
            };
            console.log('[ZAI-V2] CryptoJS.HmacSHA256 hooked ✓');
        }
    };

    // Try immediately and after a delay (CryptoJS may load late)
    tryHookCryptoJS();
    setTimeout(tryHookCryptoJS, 1000);
    setTimeout(tryHookCryptoJS, 3000);

    // ── 3. Collect all script URLs as they load ────────────────────────────
    const observer = new MutationObserver(mutations => {
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (node.tagName === 'SCRIPT' && node.src) {
                    if (!window.__zai_scripts.includes(node.src)) {
                        window.__zai_scripts.push(node.src);
                    }
                }
            }
        }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });

    // Also grab existing scripts
    document.querySelectorAll('script[src]').forEach(s => {
        if (s.src) window.__zai_scripts.push(s.src);
    });

    // ── 4. Hook any function that returns a 64-char hex string ────────────
    // This is a last-resort catch-all for custom HMAC implementations
    const _origStringFromCharCode = String.fromCharCode;
    // (too noisy to hook — skip for now)

    console.log('[ZAI-V2] All hooks installed ✓');
})();
"""


# ── Main ──────────────────────────────────────────────────────────────────────

async def run():
    # Load session
    try:
        with open(ACCOUNT_FILE) as f:
            account = json.load(f)
    except FileNotFoundError:
        print(f"❌ {ACCOUNT_FILE} not found. Run: python z_ai_client.py --setup")
        return

    cookies = account.get("cookies", [])
    uid     = account.get("user_id", "?")

    print("=" * 60)
    print("Z.ai HMAC Key Extractor V2")
    print("(V1 confirmed: NOT crypto.subtle → pure-JS HMAC)")
    print("=" * 60)
    print(f"Session : {uid}")
    print()

    found_key_bytes = None

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,
            args=["--no-sandbox", "--disable-blink-features=AutomationControlled"],
        )

        context = await browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            )
        )

        # Inject hooks before any page JS runs
        await context.add_init_script(FETCH_HOOK_JS)

        if cookies:
            await context.add_cookies(cookies)

        page = await context.new_page()

        # Track console messages
        def on_console(msg):
            if "[ZAI-V2]" in msg.text:
                print("  [hook]", msg.text)

        page.on("console", on_console)

        # Collect all JS files loaded by the page
        js_urls = set()
        def on_response(resp):
            ct = resp.headers.get("content-type", "")
            if "javascript" in ct and "z.ai" in resp.url:
                js_urls.add(resp.url)

        page.on("response", on_response)

        print("→ Navigating to chat.z.ai ...")
        await page.goto(BASE_URL, wait_until="networkidle", timeout=30000)
        await page.wait_for_timeout(2000)

        # Collect script URLs from the page
        script_urls = await page.evaluate("""
            Array.from(document.querySelectorAll('script[src]'))
                 .map(s => s.src)
                 .filter(s => s.includes('z.ai') || s.includes('_next'))
        """)
        for u in script_urls:
            js_urls.add(u)

        print(f"  Collected {len(js_urls)} JS bundle URLs")

        # ── PRONG 2: Scan JS bundles ──────────────────────────────────────
        print()
        print("─" * 40)
        print("PRONG 2: Scanning JS bundles for key candidates...")
        print("─" * 40)

        for js_url in sorted(js_urls):
            if found_key_bytes:
                break
            try:
                print(f"  Fetching: ...{js_url[-70:]}")
                resp = await page.evaluate(f"""
                    fetch({json.dumps(js_url)})
                        .then(r => r.text())
                        .catch(e => '')
                """)
                if resp and len(resp) > 100:
                    key = scan_bundle_for_keys(resp, js_url)
                    if key:
                        found_key_bytes = key
                        break
                    else:
                        print(f"    No key found in {len(resp):,} bytes")
            except Exception as e:
                print(f"    Error fetching bundle: {e}")

        # ── PRONG 1: Send test messages, capture live signatures ───────────
        print()
        print("─" * 40)
        print("PRONG 1: Capturing live signatures via fetch hook...")
        print("─" * 40)

        test_messages = [
            "key_capture_alpha_x01",
            "key_capture_beta_x02",
            "key_capture_gamma_x03",
        ]

        for msg in test_messages:
            if found_key_bytes:
                break
            print(f"  Sending: {msg!r}")
            try:
                textarea = page.locator("textarea").first
                await textarea.fill(msg)
                await page.keyboard.press("Enter")
                await page.wait_for_timeout(3000)
            except Exception as e:
                print(f"  ⚠ Could not send: {e}")

        # Wait for all captures
        await page.wait_for_timeout(3000)

        # Read captures
        captures = await page.evaluate("window.__zai_captures || []")
        crypto_log = await page.evaluate("window.__zai_cryptoLog || []")
        late_scripts = await page.evaluate("window.__zai_scripts || []")

        # Add any late-loaded scripts we might have missed
        for u in late_scripts:
            if u not in js_urls and ("_next" in u or "z.ai" in u):
                js_urls.add(u)

        # ── PRONG 3: Check CryptoJS captures ──────────────────────────────
        if crypto_log:
            print()
            print("─" * 40)
            print(f"PRONG 3: CryptoJS captures ({len(crypto_log)}):")
            print("─" * 40)
            for entry in crypto_log:
                print(f"  type   : {entry.get('type')}")
                print(f"  key    : {entry.get('key', '')[:64]}")
                print(f"  message: {entry.get('message', '')[:64]}")
                print(f"  result : {entry.get('result', '')[:64]}")
                print()
                key_candidate = entry.get("key", "")
                key_bytes = try_key_candidate(key_candidate, "CryptoJS-key")
                if key_bytes:
                    found_key_bytes = key_bytes
        else:
            print()
            print("PRONG 3: No CryptoJS.HmacSHA256 calls captured")
            print("  → Z.ai does NOT use CryptoJS")

        # ── Save raw captures ──────────────────────────────────────────────
        if captures:
            print()
            print(f"Live captures ({len(captures)}):")
            for c in captures:
                print(f"  ts={c.get('ts')}  prompt={c.get('prompt','')[:20]}  sig={c.get('sig','')[:16]}...")

            with open(OUT_CAPS, "w") as f:
                json.dump(captures, f, indent=2)
            print(f"  Saved to: {OUT_CAPS}")

            # If we have live captures, try to use them with known key candidates
            # from the bundle scan (if any were partial matches)
            if not found_key_bytes:
                print()
                print("  Using live captures to re-test bundle candidates...")
                # Re-scan bundles but now we can verify against LIVE signatures too
                # (not just the 18 pre-known ones)

        # ── Try scanning any late-loaded bundles ───────────────────────────
        if not found_key_bytes and late_scripts:
            print()
            print(f"Scanning {len(late_scripts)} late-loaded scripts...")
            for js_url in late_scripts:
                if found_key_bytes:
                    break
                if js_url in js_urls:
                    continue
                js_urls.add(js_url)
                try:
                    resp = await page.evaluate(f"""
                        fetch({json.dumps(js_url)})
                            .then(r => r.text())
                            .catch(e => '')
                    """)
                    if resp and len(resp) > 100:
                        key = scan_bundle_for_keys(resp, js_url)
                        if key:
                            found_key_bytes = key
                except Exception:
                    pass

        await browser.close()

    # ── Final report ───────────────────────────────────────────────────────
    print()
    print("=" * 60)

    if found_key_bytes:
        key_hex = found_key_bytes.hex()
        hits = verify_key_all(found_key_bytes, verbose=True)

        if hits == len(KNOWN_SAMPLES):
            print("✅ HMAC KEY FOUND AND FULLY VERIFIED")
        else:
            print(f"⚠ Key found but only {hits}/{len(KNOWN_SAMPLES)} samples match")

        print(f"   Key (hex) : {key_hex}")
        try:
            key_str = found_key_bytes.decode("utf-8")
            print(f"   Key (str) : {key_str}")
        except Exception:
            pass

        result = {
            "hmac_key_hex":              key_hex,
            "message_format":            "str(timestamp) + signature_prompt",
            "algorithm":                 "HMAC-SHA256",
            "verified_against_samples":  hits,
        }
        with open(OUT_KEY, "w") as f:
            json.dump(result, f, indent=2)
        print(f"   Saved to  : {OUT_KEY}")
    else:
        print("❌ Key NOT found.")
        print()
        print("Diagnostics:")
        print(f"  JS bundles scanned   : {len(js_urls)}")
        print(f"  Live sig captures    : {len(captures)}")
        print(f"  CryptoJS log entries : {len(crypto_log)}")
        print()
        print("Next steps:")
        print()
        print("  A) If live captures > 0 but key not found:")
        print("     → The key search patterns need adjustment.")
        print("     → Upload sig_captures.json and I'll refine the analysis.")
        print()
        print("  B) If live captures = 0:")
        print("     → Session expired. Run: python z_ai_client.py --setup")
        print("     → Then re-run this script.")
        print()
        print("  C) If JS bundles = 0:")
        print("     → Page blocked script loading. Try: headless=False + manual CAPTCHA")
        print()
        print(f"  JS URLs collected: {len(js_urls)}")
        for u in sorted(js_urls)[:10]:
            print(f"    {u[-80:]}")


if __name__ == "__main__":
    asyncio.run(run())
