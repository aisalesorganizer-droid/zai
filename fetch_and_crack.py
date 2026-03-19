"""
fetch_and_crack.py — Fetch Z.ai signing bundles and extract the HMAC key
=========================================================================
We know EXACTLY which files contain the signing logic from the HAR initiator stack:

  COvEVlW5.js  — main signing logic (ol → Yy → xr → Gr → Hr → fetch)
  DFZQlWS9.js  — called from signing chain
  AgMBD70M.js  — fetch wrapper that adds X-Signature header
  Cu64bUoQ.js  — window.fetch hook

Run from your Zai/ folder:
    python fetch_and_crack.py

Requires: pip install requests   (or: pip install curl_cffi)
"""

import re, json, os, hmac, hashlib, sys

try:
    import requests
except ImportError:
    try:
        from curl_cffi import requests
    except ImportError:
        print("Install requests first:  pip install requests")
        sys.exit(1)

_HERE    = os.path.dirname(os.path.abspath(__file__))
OUT_KEY  = os.path.join(_HERE, "sig_key_result.json")
CDN_BASE = "https://z-cdn.chatglm.cn/z-ai/frontend/prod-fe-1.0.262/_app/immutable/chunks/"

# Exact files from HAR initiator stack — signing chain in order
CHUNK_FILES = [
    "COvEVlW5.js",   # main: ol(L986,C164753) → Yy(L999) → xr(L992) → Gr(L992) → Hr(L996) → fetch
    "DFZQlWS9.js",   # called from COvEVlW5
    "AgMBD70M.js",   # Ci.window.fetch wrapper (adds X-Signature)
    "Cu64bUoQ.js",   # window.fetch entry point
]

# Known-good (prompt, timestamp) → signature triples — 21 samples, 4 accounts
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
    # Guest account (from latest HAR)
    ("test_alpha_001", 1773754824064, "de42f93c36db37abca253ce92ca344d0a0d968de9544fd81606767bfde5eb9e8"),
    ("test_beta_002",  1773754836424, "44c8862802e92687608cae7fe9a0543f00967ba3761ad4a5cf95e8b3538efba6"),
    ("test_gamma_003", 1773754846228, "3b8ea9da7142bc2a8ef30aa36b75c4ad081fc24f60828d997bfe7b47249f526d"),
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Referer": "https://chat.z.ai/",
    "Origin":  "https://chat.z.ai",
}


def verify_key(key_bytes: bytes) -> int:
    hits = 0
    for prompt, ts, expected in KNOWN_SAMPLES:
        msg = (str(ts) + prompt).encode()
        if hmac.new(key_bytes, msg, hashlib.sha256).hexdigest() == expected:
            hits += 1
    return hits


def try_candidate(raw: str, label: str) -> bytes | None:
    """Try a string as utf8, hex, and base64 key. Return bytes if verified."""
    import base64

    attempts = [("utf8", raw.encode("utf-8", errors="replace"))]

    clean = raw.replace(" ", "").replace("-", "")
    if re.fullmatch(r"[0-9a-fA-F]+", clean) and len(clean) % 2 == 0 and len(clean) >= 16:
        try:
            attempts.append(("hex", bytes.fromhex(clean)))
        except Exception:
            pass

    for pad in ["", "=", "=="]:
        try:
            dec = base64.b64decode(raw + pad)
            if len(dec) >= 8:
                attempts.append(("b64", dec))
                break
        except Exception:
            pass

    for enc, kb in attempts:
        hits = verify_key(kb)
        if hits >= 3:
            print(f"    🔑 CANDIDATE [{label}|{enc}]: {hits}/21  raw={raw[:48]}")
            if hits == len(KNOWN_SAMPLES):
                return kb
    return None


def scan_js(text: str, filename: str) -> bytes | None:
    """Scan a JS bundle text for the HMAC key."""
    found = None

    # ── Priority 1: strings NEAR signing keywords ─────────────────────────
    kw_pat = re.compile(
        r'(?:hmac|HMAC|sign(?:ature)?|secret|SHA256|X-Signature|x-signature)'
        r'[^"\'`]{0,80}["\'\`]([^"\'`]{8,128})["\'\`]',
        re.IGNORECASE
    )
    for m in kw_pat.finditer(text):
        candidate = m.group(1)
        result = try_candidate(candidate, f"keyword@{m.start()}")
        if result:
            return result

    # ── Priority 2: 32–128 char hex strings ───────────────────────────────
    hex_pat = re.compile(r'["\'\`]([0-9a-fA-F]{32,128})["\'\`]')
    for m in hex_pat.finditer(text):
        candidate = m.group(1)
        result = try_candidate(candidate, f"hex@{m.start()}")
        if result:
            return result

    # ── Priority 3: 32–128 char base64 strings ────────────────────────────
    b64_pat = re.compile(r'["\'\`]([A-Za-z0-9+/]{32,128}={0,2})["\'\`]')
    for m in b64_pat.finditer(text):
        candidate = m.group(1)
        result = try_candidate(candidate, f"b64@{m.start()}")
        if result:
            return result

    return None


def extract_around_column(text: str, line_no: int, col: int, window: int = 300) -> str:
    """Extract text around a specific line/column for focused analysis."""
    lines = text.split("\n")
    if line_no >= len(lines):
        return ""
    line = lines[line_no]
    start = max(0, col - window)
    end   = min(len(line), col + window)
    return line[start:end]


def main():
    print("=" * 60)
    print("Z.ai HMAC Key Extractor — Direct Bundle Fetch")
    print(f"CDN: {CDN_BASE}")
    print("=" * 60)
    print()

    found_key = None
    session = requests.Session()

    for filename in CHUNK_FILES:
        if found_key:
            break

        url = CDN_BASE + filename
        print(f"→ Fetching {filename} ...")

        try:
            resp = session.get(url, headers=HEADERS, timeout=20)
            if resp.status_code != 200:
                print(f"  ✗ HTTP {resp.status_code}")
                continue

            text = resp.text
            print(f"  ✓ {len(text):,} chars")

            # Save locally for manual inspection
            local_path = os.path.join(_HERE, filename)
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"  Saved: {local_path}")

            # For COvEVlW5.js — focus on the exact columns from the stack trace
            if filename == "COvEVlW5.js":
                print(f"  Scanning around known signing columns ...")

                # ol function at L986, C164753 — outermost signing call
                snippet_ol = extract_around_column(text, 985, 164753, window=500)
                print(f"  [ol@L986,C164753] snippet: {snippet_ol[:120]!r}")

                # Yy at L999, C5723
                snippet_yy = extract_around_column(text, 998, 5723, window=500)
                print(f"  [Yy@L999,C5723]  snippet: {snippet_yy[:120]!r}")

                # Hr at L996, C4945
                snippet_hr = extract_around_column(text, 995, 4945, window=500)
                print(f"  [Hr@L996,C4945]  snippet: {snippet_hr[:120]!r}")

                # Search focused snippets first
                for snippet, label in [
                    (snippet_ol, "ol-region"),
                    (snippet_yy, "Yy-region"),
                    (snippet_hr, "Hr-region"),
                ]:
                    key = scan_js(snippet, label)
                    if key:
                        found_key = key
                        break

            if not found_key:
                print(f"  Full scan of {filename} ...")
                key = scan_js(text, filename)
                if key:
                    found_key = key

        except Exception as e:
            print(f"  ✗ Error: {e}")

    # ── Report ─────────────────────────────────────────────────────────────
    print()
    print("=" * 60)

    if found_key:
        key_hex = found_key.hex()
        hits = verify_key(found_key)
        print(f"✅ KEY FOUND AND VERIFIED ({hits}/{len(KNOWN_SAMPLES)} samples)")
        print(f"   Hex : {key_hex}")
        try:
            print(f"   Str : {found_key.decode('utf-8')}")
        except Exception:
            pass

        result = {
            "hmac_key_hex":             key_hex,
            "message_format":           "str(timestamp) + signature_prompt",
            "algorithm":                "HMAC-SHA256",
            "verified_against_samples": hits,
        }
        with open(OUT_KEY, "w") as f:
            json.dump(result, f, indent=2)
        print(f"   Saved: {OUT_KEY}")
        print()
        print("   Next step:  python zai_direct.py \"Hello!\"")
    else:
        print("❌ Key not found in automatic scan.")
        print()
        print("The bundles have been saved locally. Manual steps:")
        print()
        print("  1. Open COvEVlW5.js in VS Code")
        print("  2. Go to line 996")  
        print("  3. Look around column 4945 for the Hr function")
        print("  4. Search for: hmac  sign  secret  SHA256")
        print("  5. Copy any suspicious string and run:")
        print("     python verify_sig_key.py <that_string>")
        print()
        print("  OR: Upload COvEVlW5.js here and I'll scan it directly.")


if __name__ == "__main__":
    main()
