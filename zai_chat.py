"""
zai_chat.py — Interactive Terminal Chat for Z.ai
=================================================
A polished REPL chat interface powered by zai_direct.py.

Features:
  - Typewriter streaming  (smooth word-by-word output)
  - Live status bar       (model · thinking mode · message count)
  - Thinking mode toggle  (/think on|off)
  - Hot model switching   (/model glm-4.7)
  - Slash commands        (/help /clear /history /save /exit)
  - Auto-save on exit

Usage:
    python zai_chat.py
    python zai_chat.py --model glm-4.7
    python zai_chat.py --think
    python zai_chat.py --no-stream

Requirements:
    zai_direct.py  (same folder)
    pip install curl_cffi
"""

from __future__ import annotations

import argparse
import collections
import itertools
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Sessions directory ─────────────────────────────────────────────────────────
_HERE        = os.path.dirname(os.path.abspath(__file__))
SESSIONS_DIR = os.path.join(_HERE, "zai_chat_sessions")

try:
    from zai_direct import ZAIDirect, SUPPORTED_MODELS
except ImportError:
    print("❌ Could not import zai_direct.py — make sure it's in the same folder.")
    sys.exit(1)


# ── ANSI ───────────────────────────────────────────────────────────────────────

class C:
    RESET      = "\033[0m"
    BOLD       = "\033[1m"
    DIM        = "\033[2m"
    CYAN       = "\033[96m"
    GREEN      = "\033[92m"
    YELLOW     = "\033[93m"
    RED        = "\033[91m"
    MAGENTA    = "\033[95m"
    BLUE       = "\033[94m"
    WHITE      = "\033[97m"
    CLEAR_LINE = "\033[2K"
    COL0       = "\r"

    @staticmethod
    def disable():
        for a in ["RESET","BOLD","DIM","CYAN","GREEN","YELLOW","RED",
                  "MAGENTA","BLUE","WHITE","CLEAR_LINE","COL0"]:
            setattr(C, a, "")


def _enable_windows_ansi():
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            C.disable()


# ── Status Bar ─────────────────────────────────────────────────────────────────

def status_bar(model: str, thinking: bool, n_exchanges: int) -> str:
    think_str = (f"{C.GREEN}● think on{C.RESET}"
                 if thinking else f"{C.DIM}○ think off{C.RESET}")
    msgs = f"{C.DIM}{n_exchanges} exchange{'s' if n_exchanges != 1 else ''}{C.RESET}"
    bar  = f"{C.DIM}─────────────────────────────────────────────{C.RESET}"
    return f"{bar}\n  {C.BOLD}{C.CYAN}{model}{C.RESET}  │  {think_str}  │  {msgs}\n{bar}"


# ── Thinking Spinner ───────────────────────────────────────────────────────────

class Spinner:
    FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, active: bool):
        self._active = active
        self._stop   = False
        self._thread = None

    def start(self):
        if not self._active:
            return
        self._stop   = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        i = 0
        while not self._stop:
            f = self.FRAMES[i % len(self.FRAMES)]
            print(f"{C.DIM}{f} thinking…{C.RESET}", end=C.COL0, flush=True)
            time.sleep(0.08)
            i += 1

    def stop(self):
        if not self._active or self._thread is None:
            return
        self._stop = True
        self._thread.join()
        print(C.CLEAR_LINE + C.COL0, end="", flush=True)


# ── Typewriter Output ─────────────────────────────────────────────────────────

CHAR_DELAY = 0.007   # seconds between characters when buffer has queued chars

def typewriter(gen, enabled: bool) -> str:
    """
    Print a streaming generator smoothly.

    Producers push characters into a deque; the consumer drains it with a
    tiny inter-character delay only when the buffer has backlog — so fast
    network is instant and slow network never adds extra lag.
    """
    if not enabled:
        full = []
        for chunk in gen:
            print(chunk, end="", flush=True)
            full.append(chunk)
        return "".join(full)

    buf:   collections.deque = collections.deque()
    done   = threading.Event()
    parts: List[str] = []

    def produce():
        for chunk in gen:
            parts.append(chunk)
            buf.extend(chunk)
        done.set()

    t = threading.Thread(target=produce, daemon=True)
    t.start()

    while not done.is_set() or buf:
        if buf:
            print(buf.popleft(), end="", flush=True)
            if buf:
                time.sleep(CHAR_DELAY)
        else:
            time.sleep(0.004)

    t.join()
    return "".join(parts)


# ── Helpers ────────────────────────────────────────────────────────────────────

def print_banner(model: str, thinking: bool):
    print(f"""
{C.CYAN}{C.BOLD}╔══════════════════════════════════════════╗
║          Z.ai Terminal Chat              ║
╚══════════════════════════════════════════╝{C.RESET}""")
    print(status_bar(model, thinking, 0))
    print(f"\n  {C.DIM}/help for commands · /exit to quit{C.RESET}\n")


def print_help():
    cmds = [
        ("/help",             "Show this message"),
        ("/think [on|off]",   "Toggle chain-of-thought thinking (bare /think flips it)"),
        ("/model [name]",     f"Show or switch model  ({' / '.join(SUPPORTED_MODELS)})"),
        ("/clear",            "Wipe history and start a fresh conversation"),
        ("/history",          "Print full conversation history"),
        ("/save [file]",      "Save history to JSON (auto-named if no file given)"),
        ("/exit  /quit",      "Exit"),
    ]
    print(f"\n{C.CYAN}{C.BOLD}Commands:{C.RESET}")
    for cmd, desc in cmds:
        print(f"  {C.YELLOW}{cmd:<28}{C.RESET} {desc}")
    print()


def print_history(messages: List[Dict]):
    if not messages:
        print(f"  {C.DIM}(empty){C.RESET}\n")
        return
    print()
    for m in messages:
        if m["role"] == "user":
            print(f"{C.GREEN}{C.BOLD}You:{C.RESET} {m['content']}")
        else:
            print(f"{C.CYAN}{C.BOLD}GLM:{C.RESET} {m['content']}")
        print()


def save_chat(messages: List[Dict], path: str):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"saved_at": datetime.now().isoformat(),
                   "messages": messages}, f, indent=2, ensure_ascii=False)
    print(f"  {C.GREEN}✅ Saved → {path}{C.RESET}\n")


def fmt(s: float) -> str:
    return f"{s*1000:.0f}ms" if s < 1 else f"{s:.2f}s"


# ── Chat Loop ──────────────────────────────────────────────────────────────────

def chat_loop(model: str, thinking: bool, stream: bool, verbose: bool):
    _enable_windows_ansi()
    print_banner(model, thinking)

    try:
        client = ZAIDirect(model=model, verbose=verbose)
    except Exception as e:
        print(f"{C.RED}❌ {e}{C.RESET}")
        sys.exit(1)

    messages: List[Dict] = []
    chat_id   = str(uuid.uuid4())
    cur_model = model
    use_think = thinking

    print(f"  {C.DIM}Session {chat_id[:8]}…{C.RESET}\n")

    while True:
        # ── Prompt ────────────────────────────────────────────────────────────
        try:
            raw = input(f"{C.GREEN}{C.BOLD}You:{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n\n{C.DIM}Goodbye!{C.RESET}\n")
            break
        if not raw:
            continue

        # ── Commands ──────────────────────────────────────────────────────────
        if raw.startswith("/"):
            parts = raw.split(maxsplit=1)
            cmd   = parts[0].lower()
            arg   = parts[1].strip() if len(parts) > 1 else ""

            if cmd in ("/exit", "/quit"):
                print(f"\n{C.DIM}Goodbye!{C.RESET}\n")
                break

            elif cmd == "/help":
                print_help()

            elif cmd == "/think":
                if   arg.lower() in ("on",  "1", "true",  "yes"): use_think = True
                elif arg.lower() in ("off", "0", "false", "no"):  use_think = False
                else: use_think = not use_think   # bare /think flips
                label = f"{C.GREEN}ON{C.RESET}" if use_think else f"{C.YELLOW}OFF{C.RESET}"
                print(f"  Thinking mode → {label}\n")
                print(status_bar(cur_model, use_think, len(messages) // 2) + "\n")

            elif cmd == "/model":
                if not arg:
                    print(f"  Current : {C.GREEN}{cur_model}{C.RESET}")
                    print(f"  Options : {', '.join(SUPPORTED_MODELS)}\n")
                elif arg in SUPPORTED_MODELS:
                    cur_model = arg
                    client.default_model = arg
                    print(f"  {C.GREEN}✅ Switched → {C.BOLD}{cur_model}{C.RESET}\n")
                    print(status_bar(cur_model, use_think, len(messages) // 2) + "\n")
                else:
                    print(f"  {C.RED}Unknown model '{arg}'. Options: {', '.join(SUPPORTED_MODELS)}{C.RESET}\n")

            elif cmd == "/clear":
                messages.clear()
                chat_id = str(uuid.uuid4())
                print(f"  {C.YELLOW}🗑  Cleared — fresh session started.{C.RESET}\n")
                print(status_bar(cur_model, use_think, 0) + "\n")

            elif cmd == "/history":
                print_history(messages)

            elif cmd == "/save":
                # If user gives a bare filename, put it in sessions dir.
                # If user gives a full/relative path, respect it as-is.
                if arg:
                    fname = arg if os.sep in arg else os.path.join(SESSIONS_DIR, arg)
                else:
                    fname = os.path.join(
                        SESSIONS_DIR,
                        f"zai_chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    )
                try:
                    save_chat(messages, fname)
                except Exception as e:
                    print(f"  {C.RED}❌ {e}{C.RESET}\n")

            else:
                print(f"  {C.RED}Unknown command '{cmd}'. /help for options.{C.RESET}\n")

            continue

        # ── Send message ──────────────────────────────────────────────────────
        messages.append({"role": "user", "content": raw})

        # Sliding window — send only the last 60 messages (30 turns) to Z.ai.
        # Full history is preserved locally for /history and /save.
        WINDOW = 60
        send_messages = messages[-WINDOW:] if len(messages) > WINDOW else messages

        spinner = Spinner(active=use_think and stream)
        spinner.start()

        full  = ""
        start = time.time()

        try:
            if stream:
                gen = client.chat(
                    send_messages, model=cur_model, stream=True,
                    chat_id=chat_id, enable_thinking=use_think,
                )

                # Collect chunks from the generator until the first answer chunk
                # arrives, then stop the spinner cleanly in the main thread
                # before handing off to typewriter. This avoids the race where
                # spinner.stop() is called from the producer thread while the
                # spinner thread is still writing to the terminal.
                chunk_buffer = []
                for chunk in gen:
                    chunk_buffer.append(chunk)
                    break   # got first chunk — stop spinner now, in main thread

                spinner.stop()
                print(f"{C.CYAN}{C.BOLD}GLM:{C.RESET} ", end="", flush=True)

                # Re-attach remaining stream after the buffered first chunk
                full = typewriter(
                    itertools.chain(chunk_buffer, gen),
                    enabled=True,
                )

                if not full:
                    spinner.stop()   # nothing arrived at all

            else:
                full = client.chat(
                    send_messages, model=cur_model, stream=False,
                    chat_id=chat_id, enable_thinking=use_think,
                )
                spinner.stop()
                print(f"{C.CYAN}{C.BOLD}GLM:{C.RESET} ", end="", flush=True)
                # Even in no-stream mode, print word-by-word for readability
                words = full.split(" ")
                for i, w in enumerate(words):
                    print(w + ("" if i == len(words)-1 else " "), end="", flush=True)
                    time.sleep(0.012)

            elapsed = time.time() - start
            print(f"\n{C.DIM}  ▸ {fmt(elapsed)}  ·  {cur_model}  ·  "
                  f"{'think on' if use_think else 'think off'}{C.RESET}\n")

            if full:
                messages.append({"role": "assistant", "content": full})
                n = len(messages) // 2
                # Show window indicator if history exceeds window
                window_note = (
                    f"  {C.DIM}(sending last 30 of {n} turns){C.RESET}"
                    if n > 30 else ""
                )
                if n > 0 and n % 5 == 0:
                    print(status_bar(cur_model, use_think, n) + "\n")
                    if window_note:
                        print(window_note + "\n")
            else:
                print(f"  {C.YELLOW}⚠ Empty response.{C.RESET}\n")
                messages.pop()

        except KeyboardInterrupt:
            spinner.stop()
            elapsed = time.time() - start
            print(f"\n{C.YELLOW}  [interrupted · {fmt(elapsed)}]{C.RESET}\n")
            if full:
                messages.append({"role": "assistant", "content": full})
            else:
                messages.pop()

        except Exception as e:
            spinner.stop()
            elapsed = time.time() - start
            print(f"\n{C.RED}❌ {e}  [{fmt(elapsed)}]{C.RESET}\n")
            messages.pop()

    # ── Auto-save ─────────────────────────────────────────────────────────────
    client.close()
    if messages:
        fname = os.path.join(
            SESSIONS_DIR,
            f"zai_chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        try:
            save_chat(messages, fname)
            print(f"  {C.DIM}Log → {fname}{C.RESET}")
        except Exception:
            pass


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Z.ai Interactive Terminal Chat")
    p.add_argument("--model",     default="glm-5", choices=SUPPORTED_MODELS)
    p.add_argument("--think",     action="store_true", help="Start with thinking enabled (default: off)")
    p.add_argument("--no-stream", action="store_true", help="Disable streaming")
    p.add_argument("--verbose",   "-v", action="store_true")
    a = p.parse_args()

    chat_loop(
        model    = a.model,
        thinking = a.think,
        stream   = not a.no_stream,
        verbose  = a.verbose,
    )
