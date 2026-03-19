# USAGE — Run Order & Command Reference

Complete guide to setting up and running the Zai client from scratch, in the correct order.

---

## First Time Setup (Run Once)

### Step 1 — Install dependencies

```bash
pip install curl_cffi playwright
playwright install chromium
```

`curl_cffi` handles all runtime HTTP requests with Chrome TLS fingerprint spoofing.
`playwright` + `chromium` is only needed for the guest pool setup and session auto-refresh — not for chat itself.

---

### Step 2 — Build the guest account pool

```bash
python zai_setup_pool.py
```

Launches headless Chromium 10 times, captures a fresh guest session each time, and saves them to `zai_guest_accounts/`. Z.ai issues guest tokens automatically — no login needed.

**Expected output:**
```
[1/10] Capturing guest_01...  ✅ guest_01  user_id=634a2036...
[2/10] Capturing guest_02...  ✅ guest_02  user_id=353bc03d...
...
✅ Succeeded : 10
Pool total  : 10 account(s)
```

Takes ~60–90 seconds total (2 second gap between captures).

**Options:**

```bash
# Capture a different number of accounts (recommended: 20 for full rotation)
python zai_setup_pool.py --count 20

# Only fill missing slots — skip existing accounts
python zai_setup_pool.py --count 20 --refill

# Re-run to top up after some accounts expire
python zai_setup_pool.py --refill
```

---

### Step 3 — Start chatting

```bash
python zai_chat.py
```

That's it. The pool loads automatically, round-robin rotation begins.

---

## Daily Use

```bash
python zai_chat.py
```

Everything is automatic:
- Account rotation (round-robin across all pool accounts)
- Session refresh (background, ~5–10s, shown as `⟳ Refreshing session...`)
- HMAC key recovery (if Z.ai rotates their JS bundle)
- Sliding window (last 30 turns sent per request, full history kept locally)

---

## All Files — What They Do & When To Run

---

### `zai_chat.py` — Terminal Chat Interface

```bash
# Standard start (think off, glm-5, streaming on)
python zai_chat.py

# Start with chain-of-thought reasoning enabled
python zai_chat.py --think

# Start with a specific model
python zai_chat.py --model glm-4.7

# Disable streaming (word-by-word output instead)
python zai_chat.py --no-stream

# Verbose mode — shows request details, account used, signing info
python zai_chat.py --verbose
```

**In-chat commands:**

```
/help                   Show all commands
/think                  Toggle chain-of-thought (flip current state)
/think on               Enable chain-of-thought
/think off              Disable chain-of-thought
/model                  Show current model and options
/model glm-4.7          Switch to glm-4.7
/model glm-5            Switch to glm-5
/clear                  Wipe conversation history, start fresh
/history                Print full local conversation history
/save                   Auto-save history to timestamped JSON
/save my_chat.json      Save history to a specific file
/exit                   Exit and auto-save
/quit                   Same as /exit
```

**When to run:** Every time you want to chat.

---

### `zai_setup_pool.py` — Guest Pool Builder

```bash
# Build a 10-account pool (default)
python zai_setup_pool.py

# Build a 20-account pool (recommended for balanced rotation)
python zai_setup_pool.py --count 20

# Refill only missing slots (safe to re-run anytime)
python zai_setup_pool.py --refill

# Refill up to 20 accounts total
python zai_setup_pool.py --count 20 --refill
```

**When to run:**
- Once on first setup
- After renaming/moving the `zai_guest_accounts/` folder
- If many accounts have gone stale and auto-refresh hasn't kept up
- Anytime you want to expand the pool size

---

### `zai_direct.py` — Core HTTP Engine

Not run directly. Imported by `zai_chat.py`.

Contains:
- `SignatureEngine` — HMAC-SHA256 signing + auto-recovery
- `AccountPool` — round-robin pool management
- `GuestRefresher` — background session refresh
- `HTTPEngine` — curl_cffi HTTP client
- `_parse_sse_stream()` — SSE phase parser

**Standalone test (sends a single message):**

```bash
python zai_direct.py "Hello, who are you?"

# With a specific model
python zai_direct.py "Hello" --model glm-4.7

# Verify the HMAC signing key is working
python zai_direct.py --verify-key

# Non-streaming mode
python zai_direct.py "Hello" --no-stream

# Verbose (shows signing details, account rotation)
python zai_direct.py "Hello" --verbose
```

**When to run standalone:** Testing, debugging, or verifying the HMAC key after an auto-recovery.

---

### `fetch_and_crack.py` — HMAC Key Extractor (Direct CDN)

```bash
python fetch_and_crack.py
```

Fetches the known signing bundle files directly from Z.ai's CDN and scans them for the HMAC master key. Faster than the Playwright-based extractor. Use this if auto-recovery fails and you need to manually update the key.

**When to run:** Only if `zai_direct.py --verify-key` fails AND auto-recovery also fails (Z.ai major CDN restructure).

---

### `extract_hmac_key_v2.py` — HMAC Key Extractor (Playwright)

```bash
python extract_hmac_key_v2.py
```

Three-prong approach:
1. Hooks `window.fetch` to capture live signatures
2. Scans all JS bundles loaded by the page
3. Hooks CryptoJS if present

Slower but more thorough than `fetch_and_crack.py`. Use as a last resort if the direct CDN extractor also fails.

Requires: `pip install playwright && playwright install chromium`

**When to run:** Only if both `fetch_and_crack.py` and auto-recovery fail.

---

### `verify_sig_key.py` — Key Verification

```bash
python verify_sig_key.py <candidate_key>
```

Tests a candidate string as a potential HMAC master key against all 21 known-good HAR samples. Useful when manually hunting for the key in JS source.

**When to run:** During manual key extraction / debugging.

---

### `build_accounts.py` — Account Builder Utility

```bash
python build_accounts.py
```

Converts raw token/cookie data into properly formatted account JSON files for the pool. Used if you have captured sessions manually and want to import them.

**When to run:** Only if adding manually-captured sessions to the pool.

---

### `z_ai_client.py` — Legacy Browser Client (Superseded)

```bash
# Legacy setup (opens real Chrome, requires manual login)
python z_ai_client.py --setup

# Legacy message send
python z_ai_client.py "Hello"

# Capture live X-Signature values for debugging
python z_ai_client.py --find-sig
```

This was the original approach before the HMAC key was reversed. It drove a real Chrome browser to compute signatures. Now superseded by `zai_direct.py` which computes signatures directly without a browser.

**When to run:** Only for debugging signature capture or if `zai_direct.py` is broken.

---

## Folder Structure

```
Zai/
├── zai_chat.py                  ← run this to chat
├── zai_direct.py                ← core engine (auto-imported)
├── zai_setup_pool.py            ← run once to build pool
│
├── zai_guest_accounts/          ← auto-managed guest pool
│   ├── guest_01.json
│   ├── guest_02.json
│   └── ... (up to 20)
│
├── z_ai_account.json            ← legacy fallback (single account)
├── sig_key_result.json          ← auto-written on HMAC key recovery
│
├── zai_js_bundle/               ← saved JS chunks (reference)
│   ├── AgMBD70M.js
│   ├── COvEVlW5.js
│   ├── Cu64bUoQ.js
│   └── DFZQlWS9.js
│
├── zai_(hars_&_tokens)_for_reverse_engineering/   ← original captures
│   ├── chat.z.ai.har
│   ├── guestmode_tokens.txt
│   ├── key_and_tokens_acc1(chat-based).txt
│   └── ...
│
├── fetch_and_crack.py           ← manual key extraction (CDN)
├── extract_hmac_key_v2.py       ← manual key extraction (Playwright)
├── verify_sig_key.py            ← key verification utility
├── build_accounts.py            ← account import utility
├── z_ai_client.py               ← legacy (superseded)
├── zai_persistent.py            ← legacy (superseded)
└── zai.py                       ← legacy (superseded)
```

---

## Troubleshooting

**`No accounts found` on startup**
```bash
python zai_setup_pool.py
```
The `zai_guest_accounts/` folder is empty or missing.

**`HMAC key outdated — starting auto-recovery...`**
Normal. Z.ai rotated their JS bundle. Auto-recovery runs automatically. If it succeeds, chat continues. If it fails, run:
```bash
python fetch_and_crack.py
```

**`Session expired — auto-refresh failed`**
```bash
python zai_setup_pool.py --refill
```
Playwright may not be installed, or Z.ai is temporarily blocking headless browsers.

**Responses are very slow (30–80s)**
Chain-of-thought is on. Toggle it off:
```
/think off
```
Or start with it off by default (already the default in the current version).

**Pool running low after many refreshes**
```bash
python zai_setup_pool.py --count 20 --refill
```
Top up any expired slots.

**Check if signing key is valid**
```bash
python zai_direct.py --verify-key
```
