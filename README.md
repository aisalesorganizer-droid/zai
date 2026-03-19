# Zai — Z.ai Direct HTTP Client

A fully reverse-engineered Python client for [chat.z.ai](https://chat.z.ai) (GLM-5 / GLM-4.7). No browser at runtime. Direct HTTP with a computed `X-Signature` header, a self-healing 20-account guest pool, and a polished terminal chat interface.

---

## What Makes This Interesting

### The X-Signature Problem

Z.ai signs every API request with an `X-Signature` header computed inside their obfuscated frontend JavaScript bundle. The signing algorithm was reverse-engineered from `AgMBD70M.js` (prod-fe-1.0.262) by:

1. Capturing live HAR traffic from 3 accounts + guest mode (21 known-good signature samples)
2. Tracing the JS call stack: `ol → Yy → xr → Gr → Hr → fetch`
3. Deobfuscating RC4+base64 string shuffling to extract the HMAC master key

The algorithm (reproduced in `SignatureEngine`):

```
v   = base64(prompt_utf8)
n   = sorted([requestId, timestamp, user_id]).join(",")
d   = n + "|" + v + "|" + timestamp_ms
S   = floor(timestamp_ms / 300000)          # 5-minute time bucket
E   = HMAC-SHA256(MASTER_KEY, str(S))       # ephemeral key
sig = HMAC-SHA256(E, d).hexdigest()         # X-Signature
```

The master key is hardcoded and verified against all 21 HAR samples on every startup.

### Auto-Recovery

If Z.ai rotates their JS bundle, the startup self-check detects it and triggers automatic key recovery: fetches the new CDN bundle, scans for the new key using keyword + hex + base64 pattern matching, verifies against known samples, and saves to `sig_key_result.json` — all without user intervention.

### SSE Phase Parsing

Z.ai streams responses in a non-standard SSE format with two phases:

- `thinking` — internal chain-of-thought reasoning (buffered, not shown by default)
- `answer` — the actual response (yielded as text chunks)
- `done` — stream terminator (may carry a final token fragment — handled correctly)

A notable bug in Z.ai's frontend: the final token of every response arrives attached to the `done` phase frame rather than the last `answer` frame. The parser recovers this token rather than dropping it.

### Self-Healing Guest Pool

Z.ai issues guest JWTs automatically to any browser visitor — no login required. The pool pre-captures 20 guest sessions headlessly via Playwright. Round-robin rotation spreads load evenly. When a session expires (401), a background thread silently captures a fresh guest session, overwrites the dead account file, and swaps the new account into the pool — the conversation continues without interruption.

---

## Architecture

```
zai_chat.py          — Terminal REPL (UI layer)
    │
    │  sends messages[-60:]  (sliding window — last 30 turns)
    │
zai_direct.py        — HTTP client (engine layer)
    ├── SignatureEngine      — HMAC-SHA256 request signing + auto-recovery
    ├── AccountPool          — Round-robin 20-account guest pool
    ├── GuestRefresher       — Background 401 session refresh via Playwright
    ├── HTTPEngine           — curl_cffi Chrome TLS fingerprint spoofing
    └── _parse_sse_stream()  — SSE phase parser (thinking / answer / done)
```

---

## Files

| File | Purpose | Runtime? |
|------|---------|----------|
| `zai_chat.py` | Interactive terminal chat REPL | ✅ Yes |
| `zai_direct.py` | Core HTTP client — signing, pool, streaming | ✅ Yes |
| `zai_setup_pool.py` | One-time guest pool setup (captures 20 sessions) | 🔧 Setup only |
| `zai_guest_accounts/` | Pool of 20 guest account JSON files | ✅ Yes |
| `z_ai_account.json` | Legacy single-account fallback | ⚠️ Fallback only |
| `sig_key_result.json` | Auto-saved recovered HMAC key (written on key rotation) | 🔄 Auto-managed |
| `zai_js_bundle/` | Saved JS chunks used for key extraction | 🔬 Reference |
| `zai_(hars_&_tokens)_for_reverse_engineering/` | Original HAR captures + tokens | 🔬 Reference |
| `extract_hmac_key_v2.py` | Playwright-based HMAC key extractor (3-prong approach) | 🔬 Debug |
| `fetch_and_crack.py` | Direct CDN bundle fetch + key scanner | 🔬 Debug |
| `verify_sig_key.py` | Standalone key verification against HAR samples | 🔬 Debug |
| `build_accounts.py` | Account JSON builder utility | 🔧 Setup |
| `z_ai_client.py` | Original browser-based client (legacy, superseded) | ❌ Superseded |
| `zai_persistent.py` | Original persistent browser provider (legacy) | ❌ Superseded |
| `zai.py` | Original Playwright browser provider (legacy) | ❌ Superseded |

---

## Dependencies

```bash
pip install curl_cffi playwright
playwright install chromium
```

- `curl_cffi` — Chrome 124 TLS fingerprint spoofing (prevents bot detection)
- `playwright` — headless Chromium for guest session capture only (not used at chat runtime)

---

## Models

| Model | Notes |
|-------|-------|
| `glm-5` | Default. Latest, most capable. |
| `glm-4.7` | Previous generation. Faster on simple tasks. |

---

## Chat Commands

| Command | Effect |
|---------|--------|
| `/help` | Show all commands |
| `/think [on\|off]` | Toggle chain-of-thought reasoning |
| `/model [name]` | Show or switch model |
| `/clear` | Wipe history, start fresh session |
| `/history` | Print full local conversation history |
| `/save [file]` | Save history to JSON |
| `/exit` | Exit and auto-save |

---

## CLI Flags

```bash
python zai_chat.py                  # defaults: glm-5, think off, streaming on
python zai_chat.py --think          # start with chain-of-thought enabled
python zai_chat.py --model glm-4.7  # start with glm-4.7
python zai_chat.py --no-stream      # disable streaming (word-by-word instead)
python zai_chat.py --verbose        # show request/response debug info
```

---

## How Streaming Works

```
Z.ai SSE frame:
  data: {"type":"chat:completion","data":{"delta_content":"Hello","phase":"answer"}}

Parser phases:
  thinking → buffered internally, not shown (unless no answer phase follows)
  answer   → yielded chunk by chunk to typewriter
  other    → ignored unless already in answer phase
  done     → signals end of stream; any delta in this frame is also yielded (Z.ai bug workaround)
```

The typewriter uses a producer/consumer deque: a background thread feeds chunks into a buffer, the main thread drains it with a small inter-character delay only when there's backlog — so fast responses appear instantly and slow responses never add extra lag.

---

## Sliding Window

To prevent request bloat in long conversations, only the last 60 messages (30 turns) are sent to Z.ai per request. The full conversation history is preserved locally and available via `/history` and `/save`. The status bar shows `(sending last 30 of N turns)` once the window becomes active.

---

## Session Management

Guest JWTs have no expiry claim (`exp`). Sessions are invalidated server-side by Z.ai, typically signalled by a 401 response. When this happens:

1. Background thread launches headless Chromium
2. Visits `chat.z.ai` — Z.ai issues a fresh guest JWT automatically
3. New session overwrites the dead account file in `zai_guest_accounts/`
4. New account swaps into the pool at the same round-robin position
5. Failed request retries with fresh credentials
6. Terminal shows `⟳ Refreshing session...` during the ~5–10 second refresh

Rate limiting (429) triggers exponential backoff: 2s → 4s → 8s → ... capped at 60s.

---

## Performance

| Metric | Value |
|--------|-------|
| Requests per session | Unlimited (auto-refresh on expiry) |
| Pool size | 20 guest accounts |
| Rotation | Round-robin — each account handles 1 turn then yields |
| Sliding window | Last 30 turns (60 messages) sent per request |
| Think off latency | ~1–6s typical |
| Think on latency | ~15–80s (full chain-of-thought) |
| Session refresh time | ~5–10s (headless Playwright) |

---

## Known Limitations

- **Final token occasionally dropped** — Z.ai's frontend sends the last token in the `done` phase rather than the last `answer` phase. The parser recovers this token, but very rarely Z.ai terminates the stream one token early server-side (unfixable — Z.ai bug).
- **Guest sessions only** — No support for logged-in accounts at runtime. Guest accounts have no message history on Z.ai's side (but local history is preserved).
- **Windows paths** — Developed and tested on Windows. Linux/macOS should work but are untested.
- **Playwright required for refresh** — If Playwright is not installed, session refresh falls back to a warning message and requires manual `zai_setup_pool.py --refill`.
