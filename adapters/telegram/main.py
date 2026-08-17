"""
Selo Telegram Operational Harness.

Primary control surface for Selo cryptographic accounting. Provides:
- Long-polling Telegram bot with guided command routing
- Built-in cron scheduler (daily close, reconciliation, health checks)
- SOP engine for structured multi-step workflows (issue payments, close days)
- Settlement watcher with deduplication and push alerts
- Progress streaming for long-running commands (ingest)

Start with:
    pip install python-dotenv apscheduler
    TELEGRAM_TOKEN=<token> TELEGRAM_ADMIN_IDS=<id> TELEGRAM_ALERTS_TO=<id> SELO_PATH=./target/release/selo-tool python adapters/telegram/main.py
"""

import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Load the repo's .env so the adapter and the CLI/agent share one source of
# secrets and one state directory. The repo root is two levels above this
# file (adapters/telegram/main.py).
try:
    from dotenv import load_dotenv

    _REPO_ROOT = Path(__file__).resolve().parent.parent.parent
    load_dotenv(_REPO_ROOT / ".env")
except ImportError:
    _REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Optional: APScheduler for built-in cron. Falls back to simple sleep-loop
# scheduling when not installed, so the adapter remains runnable without it.
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger

    HAS_APSCHEDULER = True
except ImportError:
    HAS_APSCHEDULER = False

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
SELO_PATH = os.environ.get("SELO_PATH", "./target/release/selo-tool")
ADMIN_IDS = set(
    int(x.strip())
    for x in os.environ.get("TELEGRAM_ADMIN_IDS", "").split(",")
    if x.strip()
)
ALERT_IDS = [
    int(x.strip())
    for x in os.environ.get("TELEGRAM_ALERTS_TO", "").split(",")
    if x.strip()
]
# State lives in the repo root by default, so the adapter, the CLI, and the
# ZeroClaw agent all read and write the same .selo_* files. Override with
# SELO_DATA_DIR only when a machine genuinely needs isolated state.
DATA_DIR = Path(os.environ.get("SELO_DATA_DIR", str(_REPO_ROOT)))
RECONCILIATION_INTERVAL = int(
    os.environ.get("SELO_RECONCILIATION_SECS", "60")
)
MERCHANT_PUBKEY = os.environ.get("SELO_MERCHANT", "")
FISCAL_YEAR = os.environ.get("SELO_FISCAL_YEAR", "2026")
# ZeroClaw gateway webhook for free-form LLM prompts. The adapter owns the
# Telegram token and renders the button GUI itself; text that is not a selo
# command is forwarded here and the reply is sent back to the chat.
ZEROCLAW_GATEWAY = os.environ.get(
    "ZEROCLAW_GATEWAY_URL", "http://127.0.0.1:42617"
)

# Ensure data directory exists.
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = DATA_DIR / ".selo_adapter_state.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)

# ---------------------------------------------------------------------------
# State persistence (dedup, SOP run log)
# ---------------------------------------------------------------------------

_run_lock = threading.Lock()


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"settled_signatures": {}, "sop_runs": {}}


def save_state(state):
    try:
        STATE_FILE.write_text(json.dumps(state, indent=2))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Telegram transport
# ---------------------------------------------------------------------------


def send_telegram(chat_id: int, text: str, parse_mode: str = "Markdown"):
    """Send a message, chunking if over Telegram's 4096-char limit."""
    if not TOKEN:
        return
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    for chunk in _chunk_text(text, 4000):
        payload = {"chat_id": chat_id, "text": chunk, "parse_mode": parse_mode}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 400 and parse_mode:
                payload.pop("parse_mode", None)
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    url, data=data, headers={"Content-Type": "application/json"}, method="POST"
                )
                try:
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        resp.read()
                    return
                except Exception as e2:
                    logging.error("sendMessage retry failed: %s", e2)
                    return
            logging.error("sendMessage failed: %s", e)
        except Exception as e:
            logging.error("sendMessage failed: %s", e)


def _chunk_text(text, size):
    if len(text) <= size:
        return [text]
    return [text[i : i + size] for i in range(0, len(text), size)]


def alert_all(text: str):
    """Push a message to every configured alert chat."""
    for cid in ALERT_IDS:
        send_telegram(cid, text)


def send_telegram_buttons(
    chat_id: int, text: str, buttons: list[list[tuple[str, str]]], parse_mode: str = "Markdown"
):
    """Send a message with an inline keyboard.

    buttons is a list of rows; each row is a list of (label, callback_data)
    pairs. Callback data should be ASCII (no Markdown parsing issues) and
    short.
    """
    if not TOKEN:
        return
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    keyboard = {
        "inline_keyboard": [
            [{"text": label, "callback_data": cb} for label, cb in row] for row in buttons
        ]
    }
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "reply_markup": keyboard,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        mid = body.get("result", {}).get("message_id")
        if mid:
            _menu_msgs[chat_id] = mid
    except Exception as e:
        logging.error("sendMessage(buttons) failed: %s", e)


def _edit_buttons(chat_id: int, message_id: int, text: str, buttons: list[list[tuple[str, str]]]):
    """Edit an existing inline-keyboard message in place."""
    if not TOKEN:
        return
    url = f"https://api.telegram.org/bot{TOKEN}/editMessageText"
    keyboard = {
        "inline_keyboard": [
            [{"text": label, "callback_data": cb} for label, cb in row] for row in buttons
        ]
    }
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": "Markdown",
        "reply_markup": keyboard,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        logging.error("editMessageText failed: %s", e)


def _clear_buttons(chat_id: int, message_id: int):
    """Remove the inline keyboard from a message without changing its text."""
    if not TOKEN:
        return
    url = f"https://api.telegram.org/bot{TOKEN}/editMessageReplyMarkup"
    payload = {"chat_id": chat_id, "message_id": message_id, "reply_markup": {}}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        logging.error("editMessageReplyMarkup failed: %s", e)


def _send_or_edit_menu(chat_id: int, text: str, buttons: list[list[tuple[str, str]]]):
    """Show a menu, editing the previous one in place when present.

    Navigation menus (list -> manage -> back to list) rewrite the same message
    instead of stacking new ones, so the chat does not fill with stale menus.
    """
    prev = _menu_msgs.get(chat_id)
    if prev is not None:
        _edit_buttons(chat_id, prev, text, buttons)
    else:
        send_telegram_buttons(chat_id, text, buttons)


# chat_id -> message_id of the most recent button menu, so a choice can
# clear its own keyboard and not leave stale clickable buttons behind.
_menu_msgs: dict[int, int] = {}


def answer_callback(callback_id: str, text: str = ""):
    """Acknowledge a callback query so Telegram clears the spinner."""
    if not TOKEN:
        return
    url = f"https://api.telegram.org/bot{TOKEN}/answerCallbackQuery"
    payload = {"callback_query_id": callback_id}
    if text:
        payload["text"] = text
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        logging.error("answerCallbackQuery failed: %s", e)


# ---------------------------------------------------------------------------
# selo-tool runner
# ---------------------------------------------------------------------------


def run_selo(args: list[str], timeout: int = 300) -> tuple[int, str]:
    """Execute selo-tool with streaming capture.

    Returns (exit_code, stdout). Stderr is merged into stdout for capture.
    The binary runs in DATA_DIR so state files are isolated.
    """
    # Probe .exe suffix on Windows.
    selo_path = SELO_PATH
    if sys.platform == "win32" and not os.path.exists(selo_path):
        if os.path.exists(selo_path + ".exe"):
            selo_path = selo_path + ".exe"

    cmd = [selo_path] + args
    logging.info("run: %s (cwd=%s)", " ".join(cmd), DATA_DIR)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(DATA_DIR),
            timeout=timeout,
        )
        raw = proc.stdout.strip()
        # Strip DEBUG: lines.
        lines = [ln for ln in raw.splitlines() if not ln.startswith("DEBUG:")]
        clean = "\n".join(lines).strip()
        if not clean and proc.stderr.strip():
            clean = proc.stderr.strip()
        return proc.returncode, clean
    except subprocess.TimeoutExpired:
        return -1, "Command timed out."
    except FileNotFoundError:
        return -1, f"selo-tool binary not found at '{selo_path}'. Build with 'cargo build --release --workspace'."
    except Exception as e:
        return -1, f"Execution error: {e}"


def run_selo_pretty(args: list[str], timeout: int = 300) -> str:
    """Run selo-tool and pretty-print JSON output in a code fence."""
    rc, out = run_selo(args, timeout)
    if rc != 0:
        return _friendly_error(out)
    # Try prettifying JSON.
    try:
        parsed = json.loads(out)
        pretty = json.dumps(parsed, indent=2)
        return f"```json\n{pretty}\n```"
    except (json.JSONDecodeError, ValueError):
        pass
    if not out:
        return "Command completed successfully with no output."
    return out


def run_selo_streaming(args: list[str], chat_id: int, timeout: int = 600) -> str:
    """Run a long selo-tool command, streaming progress updates to chat.

    Reads stdout line-by-line and collapses \r-progress frames (ingest)
    into periodic updates. Returns the final output.
    """
    selo_path = SELO_PATH
    if sys.platform == "win32" and not os.path.exists(selo_path):
        if os.path.exists(selo_path + ".exe"):
            selo_path = selo_path + ".exe"

    cmd = [selo_path] + args
    logging.info("streaming: %s", " ".join(cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(DATA_DIR),
        )
    except FileNotFoundError:
        send_telegram(chat_id, f"selo-tool binary not found at '{selo_path}'.")
        return ""

    lines: list[str] = []
    last_progress = ""
    frame_count = 0
    try:
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.rstrip("\n").rstrip("\r")
            if not line or line.startswith("DEBUG:"):
                continue
            # Collapse \r progress frames (ingest: "Processing tx [i/N]...")
            if line.startswith("Processing tx ["):
                frame_count += 1
                if frame_count % 25 == 0 or frame_count == 1:
                    if line != last_progress:
                        send_telegram(chat_id, f"`{line}`")
                        last_progress = line
            else:
                lines.append(line)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        send_telegram(chat_id, "Command timed out and was killed.")
    except Exception as e:
        proc.kill()
        send_telegram(chat_id, f"Streaming error: {e}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Command routing
# ---------------------------------------------------------------------------

# Destructive/administrative commands gated to ADMIN_IDS.
ADMIN_COMMANDS = {
    "close", "issue", "refund", "expire", "ingest", "anchor",
    "rules",
}
READONLY_COMMANDS = {
    "balance", "check", "confirm", "review", "backfill", "ptax",
    "blockhash", "export-html", "verify", "tax-report", "status",
    "record-sample",
}

HELP_TEXT = """*Selo Cryptographic Accounting Engine*

Send /start for the button menu - the easiest way to work with Selo. The
commands below do the same thing if you prefer typing.

*Quotes and settlement*
/issue `--amount <lamports> --recipient <pubkey> [--label "..."] [--message "..."]`
/check — Inspect store status and pending quotes
/confirm — Reconcile pending quotes against on-chain activity

*Ledger intelligence*
/ingest `<pubkey>` `[--all] [--limit <N>] [--since <date>] [--before <date>]`
/review `<pubkey>` — List unclassified counterparties
/balance `<address>` — Query account balance
/backfill `<pubkey>` `[--all]` — Scan transaction signatures
/rules `--add <pubkey> --name "..."]` — Manage counterparty rules

*Daily close and audit*
/close `--merchant <pubkey> --start <ts> --end <ts> [--output <path>]`
/verify `--root <hash>` — Verify local ledger against Poseidon root
/export-html `[--year <YEAR>] [--wallet <pubkey>] [--from <date>] [--to <date>] [--output <path>]` — Omit --year for all history
/tax-report — Generate local tax report

*Utilities*
/ptax — Fetch official BCB PTAX rate
/blockhash — Fetch network blockhash
/record-sample — Record sample acquisition using live BCB PTAX rate

Type `/status` for store and watcher health."""


def is_admin(chat_id: int) -> bool:
    return not ADMIN_IDS or chat_id in ADMIN_IDS


def dispatch(chat_id: int, text: str) -> Optional[str]:
    """Route a Telegram message to a selo-tool command.

    Returns a reply string, or None when the message should be dropped.
    """
    parts = text.split()
    if not parts:
        return None

    cmd = parts[0].lower().replace("@", "").lstrip("/")
    raw_args = text.split(maxsplit=1)
    args_str = raw_args[1] if len(raw_args) > 1 else ""
    # Parse quoted arguments so labels with spaces survive.
    args = _parse_args(args_str)

    # ---- Help / menu ----
    if cmd == "start":
        _main_menu(chat_id)
        return "Use the buttons below, or send /help for the full command list."
    if cmd == "help":
        return HELP_TEXT

    # ---- Status ----
    if cmd == "status":
        _, check_out = run_selo(["check"])
        state = load_state()
        settled_count = len(state.get("settled_signatures", {}))
        ingest_note = "Running" if chat_id in _jobs else "Idle"
        return (
            f"*Selo Status*\n\n{check_out}\n\n"
            f"Watcher: running (interval {RECONCILIATION_INTERVAL}s)\n"
            f"Ingestion: {ingest_note}\n"
            f"Known settled signatures: {settled_count}\n"
            f"Alert chats: {len(ALERT_IDS)}\n"
        )

    # ---- Admin gate ----
    if cmd in ADMIN_COMMANDS and not is_admin(chat_id):
        return "This command requires admin authorization. Your chat ID is not in TELEGRAM_ADMIN_IDS."

    # ---- Confirm token (gate destructive ops) ----
    if cmd == "yes":
        return _handle_confirm(chat_id, args)

    # ---- Standard command passthrough ----
    # Map chat-friendly command names to selo-tool subcommands.
    cmd_map = {
        "balance": ["balance"] + args,
        "check": ["check"],
        "confirm": ["confirm"],
        "expire": ["expire"],
        "ptax": ["ptax"],
        "blockhash": ["blockhash"],
        "tax-report": ["tax-report"],
        "record-sample": ["record-sample"],
        "review": ["review"] + args,
        "backfill": ["backfill"] + args,
        "verify": ["verify"] + args,
        "rules": ["rules"] + args,
        "anchor": ["anchor"] + args,
        "refund": ["refund"] + args,
    }

    if cmd in cmd_map:
        return run_selo_pretty(cmd_map[cmd])

    # ---- Long-running ingest (background, non-blocking) ----
    if cmd == "ingest":
        if not is_admin(chat_id):
            return "Ingestion requires admin authorization."
        return _start_ingest(chat_id, args)

    # ---- export-html (gated, produces file) ----
    if cmd in ("export-html", "exporthtml"):
        return run_selo_pretty(["export-html"] + args)

    # ---- Close (needs confirm gate) ----
    if cmd == "close":
        token = _make_confirm_token(chat_id, ["close"] + args)
        return (
            f"*Daily Close — Confirm*\n\n"
            f"Running: `selo-tool close {' '.join(args)}`\n\n"
            f"Reply `/yes {token}` to execute, or `/cancel` to abort.\n"
            f"This token expires in 2 minutes."
        )

    # ---- Issue (needs confirm gate) ----
    if cmd == "issue":
        token = _make_confirm_token(chat_id, ["issue"] + args)
        return (
            f"*Issue Payment Quote — Confirm*\n\n"
            f"Running: `selo-tool issue {' '.join(args)}`\n\n"
            f"Reply `/yes {token}` to execute, or `/cancel` to abort.\n"
            f"This token expires in 2 minutes."
        )

    return forward_to_llm(chat_id, text)


def forward_to_llm(chat_id: int, text: str) -> str:
    """POST a free-form prompt to the ZeroClaw selo agent via its webhook.

    Returns the agent reply, or a plain-language note when the gateway is
    down or the LLM request fails, so the button GUI keeps working on its own.
    """
    url = f"{ZEROCLAW_GATEWAY}/webhook?agent=selo"
    payload = json.dumps({"message": text}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return str(body.get("response", "")) or "The agent returned no reply."
    except Exception as e:
        logging.warning("LLM forward failed (chat %s): %s", chat_id, e)
        return (
            "The LLM is not reachable right now. Use the buttons or a / command "
            "to keep working."
        )


# ---- Confirm-token machinery ----

_pending_confirms: dict[str, tuple[int, list[str], float]] = {}
"""token -> (chat_id, args, expires_at)"""


def _make_confirm_token(chat_id: int, args: list[str]) -> str:
    import random

    token = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=4))
    _pending_confirms[token] = (chat_id, args, time.time() + 120)
    return token


def _handle_confirm(chat_id: int, args: list[str]) -> Optional[str]:
    if not args:
        return "Usage: `/yes <token>`"
    token = args[0]
    entry = _pending_confirms.pop(token, None)
    if entry is None:
        return "Unknown or expired confirmation token. Issue the command again."
    stored_chat, cmd_args, expires = entry
    if stored_chat != chat_id:
        return "This confirmation token belongs to a different chat."
    if time.time() > expires:
        return "Confirmation token expired. Issue the command again."
    result = run_selo_pretty(cmd_args)
    return result


# ---- Argument parser that respects quoted strings ----
def _parse_args(args_str: str) -> list[str]:
    """Split args respecting single and double quotes."""
    import shlex

    try:
        return shlex.split(args_str)
    except ValueError:
        return args_str.split()


# ---- Plain-language error translation ----
# Telegram operators are assumed non-technical, so raw Rust stack traces,
# RPC JSON, and exit codes are replaced with a short, actionable line. The
# underlying detail stays in the process log, not in the chat.

def _friendly_error(out: str) -> str:
    """Turn selo-tool failure output into a plain sentence."""
    if not out:
        return "Something went wrong, but the tool did not explain why. Please try again."
    low = out.lower()
    if "timed out" in low:
        return "The operation took too long and was stopped. Try a smaller date range."
    if "rpc error" in low or "transport error" in low:
        return "The Solana network was unreachable. Check the connection and try again."
    if "not a valid" in low or "wrong size" in low:
        return "That address does not look like a valid Solana wallet. Check it and try again."
    if "no ledger" in low or "not found" in low:
        return "There is no saved ledger for that wallet yet. Run ingest first."
    if "not configured" in low or "unconfigured" in low:
        return "No wallet is set up yet. Run /merchant or use /start."
    if "not allowed" in low or "not permitted" in low:
        return "This action is not allowed from this chat."
    # Fall back to the first meaningful line, stripped of noise.
    clean = [ln for ln in out.splitlines() if ln.strip() and not ln.startswith("DEBUG:")]
    if clean:
        first = clean[0].strip()
        if len(first) > 200:
            first = first[:200] + "..."
        return f"That could not be completed: {first}"
    return "That could not be completed. Please try again."


# ---------------------------------------------------------------------------
# Button menu + click-through wizard
# ---------------------------------------------------------------------------
# The operator-facing GUI: a main menu of inline buttons that launch guided
# flows. A flow asks one question at a time; the answer is captured from the
# next plain text message, so the operator never has to type a full command.
# Long-running actions (ingest, close) still confirm before they run.

_wizard: dict[int, dict] = {}
"""chat_id -> {flow, step, collected} for the active click-through wizard."""


def _main_menu(chat_id: int) -> str:
    """Build the main button menu for a chat."""
    send_telegram_buttons(
        chat_id,
        "*Selo - pick an action*",
        [
            [("Issue payment", "menu:issue")],
            [("Check pending quotes", "menu:check"), ("Confirm settlement", "menu:confirm")],
            [("Ingest a wallet", "menu:ingest"), ("Wallet balance", "menu:balance")],
            [("Manage wallets", "menu:wallets")],
            [("Daily close", "menu:close"), ("Export report", "menu:export")],
            [("Register a counterparty", "menu:rules"), ("PTAX rate", "menu:ptax")],
            [("Status", "menu:status"), ("Help", "menu:help")],
        ],
    )
    return ""


def _begin_wizard(chat_id: int, flow: str, step: str, prompt: str):
    _wizard[chat_id] = {"flow": flow, "step": step, "collected": {}}
    send_telegram(chat_id, prompt)


def _route_wizard_text(chat_id: int, text: str) -> Optional[str]:
    """Consume a plain text message as the answer to the active wizard step.

    Returns None if there is no active wizard (caller falls through to normal
    dispatch). Returns a string reply once a flow finishes, or "" when the
    flow is still collecting answers.
    """
    state = _wizard.get(chat_id)
    if not state:
        return None
    flow = state["flow"]
    collected = state["collected"]

    if flow == "issue":
        return _wizard_issue(chat_id, state, text)
    if flow == "ingest":
        return _wizard_ingest(chat_id, state, text)
    if flow == "balance":
        return _wizard_balance(chat_id, state, text)
    if flow == "close":
        return _wizard_close(chat_id, state, text)
    if flow == "export":
        return _wizard_export(chat_id, state, text)
    if flow == "rules":
        return _wizard_rules(chat_id, state, text)
    if flow == "wallets":
        return _wizard_wallets(chat_id, state, text)
    return None


def _wizard_issue(chat_id: int, state: dict, text: str) -> str:
    collected = state["collected"]
    step = state["step"]
    if step == "recipient":
        collected["recipient"] = text.strip()
        state["step"] = "amount"
        _wizard[chat_id] = state
        send_telegram(
            chat_id,
            "How much? Type an amount in SOL (for example `1.5`).\n"
            "Or send /cancel to back out.",
        )
        return ""
    if step == "amount":
        amt = text.strip()
        try:
            float(amt)
        except ValueError:
            send_telegram(chat_id, "That does not look like a number. Type the amount in SOL, for example `1.5`.")
            return ""
        collected["amount"] = amt
        state["step"] = "label"
        _wizard[chat_id] = state
        send_telegram(
            chat_id,
            "Add a short label so you can recognize this payment later "
            "(for example \"Website design\"). Type it, or send `skip` to leave it blank.",
        )
        return ""
    if step == "label":
        if text.strip().lower() not in ("skip", "-", "none"):
            collected["label"] = text.strip()
        state["step"] = "confirm"
        _wizard[chat_id] = state
        args = [
            "issue",
            "--recipient", collected.get("recipient", ""),
            "--sol", collected.get("amount", "0"),
        ]
        if collected.get("label"):
            args += ["--label", collected["label"]]
        token = _make_confirm_token(chat_id, args)
        send_telegram(
            chat_id,
            f"*Confirm payment quote*\n\n"
            f"Pay {collected['amount']} SOL to\n`{collected['recipient']}`\n"
            f"Label: {collected.get('label', '(none)')}\n\n"
            f"Reply /yes `{token}` to issue it, or /cancel to abort.",
        )
        _wizard.pop(chat_id, None)
        return ""
    return ""


def _wizard_ingest(chat_id: int, state: dict, text: str) -> str:
    collected = state["collected"]
    step = state["step"]
    if step == "address":
        collected["address"] = text.strip()
        state["step"] = "range"
        _wizard[chat_id] = state
        send_telegram_buttons(
            chat_id,
            "How much history should I fetch?",
            [
                [("Full history", "ingest:full")],
                [("Only this year", "ingest:year")],
                [("Cancel", "ingest:cancel")],
            ],
        )
        return ""
    return ""


def _wizard_balance(chat_id: int, state: dict, text: str) -> str:
    collected = state["collected"]
    step = state["step"]
    if step == "address":
        collected["address"] = text.strip()
        _wizard.pop(chat_id, None)
        return run_selo_pretty(["balance", collected["address"]])
    return ""


def _wizard_close(chat_id: int, state: dict, text: str) -> str:
    collected = state["collected"]
    step = state["step"]
    if step == "date":
        collected["date"] = text.strip()
        state["step"] = "confirm"
        _wizard[chat_id] = state
        now = int(time.time())
        day_start = now - (now % 86400)
        day_end = day_start + 86400
        args = ["close", "--start", str(day_start), "--end", str(day_end)]
        token = _make_confirm_token(chat_id, args)
        send_telegram(
            chat_id,
            f"*Confirm daily close*\n\n"
            f"Close today's ledger ({collected['date']}) and compute the "
            f"Poseidon commitment.\n\n"
            f"Reply /yes `{token}` to run it, or /cancel to abort.",
        )
        _wizard.pop(chat_id, None)
        return ""
    return ""


def _wizard_export(chat_id: int, state: dict, text: str) -> str:
    collected = state["collected"]
    step = state["step"]
    if step == "from":
        collected["from"] = text.strip()
        state["step"] = "to"
        _wizard[chat_id] = state
        send_telegram(
            chat_id,
            "Now type the end date as `YYYY-MM-DD`.\nSend /cancel to back out.",
        )
        return ""
    if step == "to":
        collected["to"] = text.strip()
        _wizard.pop(chat_id, None)
        wallet = collected.get("wallet", "")
        if not wallet:
            return "No wallet selected. Start the export again."
        return run_selo_pretty(
            ["export-html", "--wallet", wallet, "--from", collected["from"], "--to", collected["to"]]
        )
    return ""


def _wizard_rules(chat_id: int, state: dict, text: str) -> str:
    collected = state["collected"]
    step = state["step"]
    if step == "address":
        collected["address"] = text.strip()
        state["step"] = "name"
        _wizard[chat_id] = state
        send_telegram(
            chat_id,
            "What should this address be called? Type a label, for example "
            "`Marketplace` or `Design client`. Send /cancel to back out.",
        )
        return ""
    if step == "name":
        collected["name"] = text.strip()
        _wizard.pop(chat_id, None)
        return run_selo_pretty(["rules", "--add", collected["address"], "--name", collected["name"]])
    return ""


def _wizard_wallets(chat_id: int, state: dict, text: str) -> str:
    collected = state["collected"]
    step = state["step"]
    if step == "address":
        addr = text.strip()
        _wizard.pop(chat_id, None)
        return _wallet_manage_menu(chat_id, addr)
    if step == "newname":
        collected["newname"] = text.strip()
        _wizard.pop(chat_id, None)
        addr = collected.get("address", "")
        rc, out = run_selo(["rules", "--add", addr, "--name", collected["newname"]], timeout=15)
        if rc != 0:
            return _friendly_error(out)
        return f"Wallet `{addr}` is now labelled `{collected['newname']}`."
    return ""


def _wallet_buttons(chat_id: int) -> Optional[str]:
    """List every known wallet as a button, then route the tap to management.

    Known means either a ledger file on disk or a merchant-tracked wallet.
    Ledger files are discovered by name (`.selo_ledger_<pubkey>.json`), so a
    reset wallet whose content was cleared still shows up. Returns None when
    the list is empty (caller shows the fallback prompt).
    """
    base58 = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

    def is_pubkey(s):
        return (
            len(s) in (32, 43, 44)
            and all(c in base58 for c in s)
        )

    known: dict[str, str] = {}
    if DATA_DIR.is_dir():
        for path in DATA_DIR.glob(".selo_ledger_*.json"):
            pub = path.name[len(".selo_ledger_"):-len(".json")]
            known[pub] = pub
    rc, out = run_selo(["wallets"], timeout=20)
    if rc == 0:
        for line in out.splitlines():
            m = re.match(r"^\s*(\S{32,44})(?:\s+\(([^)]*)\))?", line)
            if m and is_pubkey(m.group(1)):
                pub = m.group(1)
                label = m.group(2) or pub
                if label != "Unknown Counterparty":
                    known[pub] = label
    rc2, out2 = run_selo(["merchant"], timeout=15)
    if rc2 == 0:
        for line in out2.splitlines():
            m = re.match(r"^\s*(?:primary|tracked)\s+(\S{32,44})\s+\(([^)]*)\)", line)
            if m and is_pubkey(m.group(1)) and m.group(1) not in known:
                known[m.group(1)] = m.group(2)
    if not known:
        return None
    rows = []
    for pub, label in sorted(known.items()):
        if label != pub and label != "Unknown Counterparty" and len(label) <= 28:
            text = f"{label} ({pub[:6]}...{pub[-4:]})"
        else:
            text = pub
        rows.append([(text, f"wallet:sel:{pub}")])
    rows.append([("Add a new wallet", "wallet:add")])
    rows.append([("Cancel", "ingest:cancel")])
    _send_or_edit_menu(
        chat_id,
        "Wallets I know about. Tap one to manage it, or add a new one.",
        rows,
    )
    return ""


def _wallet_manage_menu(chat_id: int, pubkey: str) -> str:
    """Show management actions for one wallet."""
    _wizard[chat_id] = {"flow": "wallets", "step": "manage", "collected": {"address": pubkey}}
    ledger = DATA_DIR / f".selo_ledger_{pubkey}.json"
    ingested = "yes" if ledger.exists() else "no"
    _send_or_edit_menu(
        chat_id,
        f"`{pubkey}`\nIngested: {ingested}",
        [
            [("Rename / label", "wallet:rename")],
            [("Reset ledger (re-ingest fresh)", "wallet:reset")],
            [("Remove from tracking", "wallet:untrack")],
            [("Delete wallet (ledger + untrack)", "wallet:delete")],
            [("Back to list", "wallet:list")],
        ],
    )
    return ""


def _ingested_wallets() -> dict[str, str]:
    """Wallet pubkey -> label for ledgers that actually have content.

    A ledger that was reset writes `{"wallets": {}}`, which is a file but not
    an ingested wallet. A ledger with a wallet entry is ingested. Labels come
    from the counterparty rules; a missing label shows the short pubkey.
    """
    ingested: dict[str, str] = {}
    if not DATA_DIR.is_dir():
        return ingested
    for path in DATA_DIR.glob(".selo_ledger_*.json"):
        pub = path.name[len(".selo_ledger_"):-len(".json")]
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        wallets = data.get("wallets") if isinstance(data, dict) else None
        if not wallets:
            continue
        if pub not in wallets:
            continue
        label = pub
        rc, out = run_selo(["rules"], timeout=15)
        if rc == 0:
            m = re.search(rf"^{re.escape(pub)} -> (.+)$", out, re.MULTILINE)
            if m:
                label = m.group(1)
        ingested[pub] = label
    return ingested


def _export_wallet_buttons(chat_id: int) -> Optional[str]:
    """List ingested wallets as buttons, each labelled with its country.

    Country is the reporting currency the wallet was ingested for. Phase 5
    (country support) is not shipped, so every wallet today reads as BRL, the
    single supported regime. When country support lands, this reads the
    persisted per-wallet country instead of the constant.
    """
    ingested = _ingested_wallets()
    if not ingested:
        return None
    rows = []
    for pub, label in sorted(ingested.items()):
        text = f"{label[:22]} ({pub[:6]}...{pub[-4:]}) - BRL"
        rows.append([(text, f"export:sel:{pub}")])
    rows.append([("Wallet not ingested? Ingest it", "export:need-ingest")])
    rows.append([("Cancel", "ingest:cancel")])
    _send_or_edit_menu(
        chat_id,
        "Export an audit report.\n\nPick the wallet (with its reporting "
        "country). Only ingested wallets are listed.",
        rows,
    )
    return ""


def _export_range_buttons(chat_id: int, pubkey: str) -> str:
    """Date-range options for one wallet's report."""
    _wizard[chat_id] = {
        "flow": "export",
        "step": "range",
        "collected": {"wallet": pubkey},
    }
    _send_or_edit_menu(
        chat_id,
        "Which period should the report cover?",
        [
            [("Full history", "export:full")],
            [("This year", "export:year")],
            [("Custom range (from/to)", "export:custom")],
            [("Back to wallets", "export:list")],
        ],
    )
    return ""


def handle_callback(chat_id: int, callback_data: str, callback_id: str) -> Optional[str]:
    """Route an inline-button tap to the matching action."""
    answer_callback(callback_id)
    if callback_data == "menu:help":
        return HELP_TEXT
    if callback_data == "menu:status":
        return dispatch(chat_id, "/status")
    if callback_data == "menu:check":
        return run_selo_pretty(["check"])
    if callback_data == "menu:confirm":
        return run_selo_pretty(["confirm"])
    if callback_data == "menu:issue":
        if not is_admin(chat_id):
            return "This requires admin authorization."
        _begin_wizard(
            chat_id, "issue", "recipient",
            "Issue a payment quote.\n\nFirst: whose wallet should receive it? "
            "Paste the Solana address (or a registered counterparty name).\n"
            "Send /cancel to back out.",
        )
        return ""
    if callback_data == "menu:ingest":
        if not is_admin(chat_id):
            return "This requires admin authorization."
        _begin_wizard(
            chat_id, "ingest", "address",
            "Ingest a wallet's transaction history.\n\nPaste the Solana address "
            "to scan (or a registered counterparty name).\nSend /cancel to back out.",
        )
        return ""
    if callback_data == "menu:balance":
        _begin_wizard(
            chat_id, "balance", "address",
            "Wallet balance.\n\nPaste the Solana address to look up.\n"
            "Send /cancel to back out.",
        )
        return ""
    if callback_data == "menu:close":
        if not is_admin(chat_id):
            return "This requires admin authorization."
        _begin_wizard(
            chat_id, "close", "date",
            "Daily close.\n\nType today's date (for example `2026-08-15`) to "
            "confirm which day to close.\nSend /cancel to back out.",
        )
        return ""
    if callback_data == "menu:export":
        reply = _export_wallet_buttons(chat_id)
        if reply is None:
            return (
                "No ingested wallets to export. Ingest a wallet first, then "
                "come back here."
            )
        return reply
    if callback_data == "export:need-ingest":
        _begin_wizard(
            chat_id, "ingest", "address",
            "Ingest a wallet's transaction history first.\n\nPaste the Solana "
            "address to scan.\nSend /cancel to back out.",
        )
        return ""
    if callback_data == "export:list":
        return _export_wallet_buttons(chat_id)
    if callback_data.startswith("export:sel:"):
        pubkey = callback_data[len("export:sel:"):]
        return _export_range_buttons(chat_id, pubkey)
    if callback_data == "export:full":
        addr = _wizard.get(chat_id, {}).get("collected", {}).get("wallet", "")
        _wizard.pop(chat_id, None)
        if not addr:
            return "No wallet selected. Start the export again."
        return run_selo_pretty(["export-html", "--wallet", addr])
    if callback_data == "export:year":
        addr = _wizard.get(chat_id, {}).get("collected", {}).get("wallet", "")
        _wizard.pop(chat_id, None)
        if not addr:
            return "No wallet selected. Start the export again."
        year = FISCAL_YEAR
        return run_selo_pretty(["export-html", "--wallet", addr, "--year", year])
    if callback_data == "export:custom":
        addr = _wizard.get(chat_id, {}).get("collected", {}).get("wallet", "")
        if not addr:
            return "No wallet selected. Start the export again."
        _wizard[chat_id] = {
            "flow": "export",
            "step": "from",
            "collected": {"wallet": addr},
        }
        send_telegram(
            chat_id,
            "Custom range.\n\nType the start date as `YYYY-MM-DD`, then the "
            "end date in the next message.\nSend /cancel to back out.",
        )
        return ""
    if callback_data == "ingest:full":
        addr = _wizard.get(chat_id, {}).get("collected", {}).get("address", "")
        if not addr:
            with _jobs_lock:
                running = chat_id in _jobs
            if running:
                return "An ingestion is already running for this chat. It posts progress here; wait for the completion message."
            return "Ingestion cancelled."
        _wizard.pop(chat_id, None)
        return _start_ingest(chat_id, [addr, "--all"])
    if callback_data == "ingest:year":
        addr = _wizard.get(chat_id, {}).get("collected", {}).get("address", "")
        if not addr:
            with _jobs_lock:
                running = chat_id in _jobs
            if running:
                return "An ingestion is already running for this chat. It posts progress here; wait for the completion message."
            return "Ingestion cancelled."
        _wizard.pop(chat_id, None)
        return _start_ingest(chat_id, [addr])
    if callback_data == "ingest:cancel":
        _wizard.pop(chat_id, None)
        return "Ingestion cancelled."
    if callback_data == "menu:wallets":
        if not is_admin(chat_id):
            return "This requires admin authorization."
        reply = _wallet_buttons(chat_id)
        if reply is None:
            return (
                "No wallets are known yet. Ingest one first, or send me an "
                "address to track."
            )
        return reply
    if callback_data == "wallet:add":
        _begin_wizard(
            chat_id, "wallets", "address",
            "Add a new wallet.\n\nPaste the Solana address to track.\n"
            "Send /cancel to back out.",
        )
        return ""
    if callback_data == "wallet:list":
        return _wallet_buttons(chat_id)
    if callback_data.startswith("wallet:sel:"):
        pubkey = callback_data[len("wallet:sel:"):]
        return _wallet_manage_menu(chat_id, pubkey)
    if callback_data == "wallet:rename":
        addr = _wizard.get(chat_id, {}).get("collected", {}).get("address", "")
        if not addr:
            return "No wallet selected. Start again with the Manage wallets button."
        _wizard[chat_id] = {
            "flow": "wallets",
            "step": "newname",
            "collected": {"address": addr},
        }
        send_telegram(
            chat_id,
            "What should this wallet be called? Type the new label.\n"
            "Send /cancel to back out.",
        )
        return ""
    if callback_data == "wallet:reset":
        addr = _wizard.get(chat_id, {}).get("collected", {}).get("address", "")
        _wizard.pop(chat_id, None)
        if not addr:
            return "No wallet selected. Start again with the Manage wallets button."
        ledger = DATA_DIR / f".selo_ledger_{addr}.json"
        if not ledger.exists():
            return "No saved ledger was found for that wallet. Nothing to reset."
        try:
            with open(ledger, "w", encoding="ascii") as f:
                f.write('{"wallets": {}}')
        except OSError as e:
            return f"Could not clear the ledger: {e}"
        ack = _start_ingest(chat_id, [addr, "--all"])
        return (
            f"Ledger for `{addr}` was cleared. {ack}"
        )
    if callback_data == "wallet:untrack":
        addr = _wizard.get(chat_id, {}).get("collected", {}).get("address", "")
        _wizard.pop(chat_id, None)
        if not addr:
            return "No wallet selected. Start again with the Manage wallets button."
        rc, out = run_selo(["merchant", "--remove", addr], timeout=15)
        if rc != 0:
            return _friendly_error(out)
        return f"Wallet `{addr}` was removed from tracking."
    if callback_data == "wallet:delete":
        addr = _wizard.get(chat_id, {}).get("collected", {}).get("address", "")
        _wizard.pop(chat_id, None)
        if not addr:
            return "No wallet selected. Start again with the Manage wallets button."
        ledger = DATA_DIR / f".selo_ledger_{addr}.json"
        if ledger.exists():
            ledger.unlink()
        rc, out = run_selo(["merchant", "--remove", addr], timeout=15)
        if rc != 0 and "was not tracked" not in out:
            return _friendly_error(out)
        return f"Wallet `{addr}` was deleted (ledger removed and untracked)."
    if callback_data == "menu:ptax":
        return run_selo_pretty(["ptax"])
    if callback_data == "menu:rules":
        if not is_admin(chat_id):
            return "This requires admin authorization."
        _begin_wizard(
            chat_id, "rules", "address",
            "Register a counterparty.\n\nPaste the Solana address you want to "
            "label (the review command lists addresses that need a label).\n"
            "Send /cancel to back out.",
        )
        return ""
    return "That option is not available."


def _cancel_wizard(chat_id: int) -> bool:
    """Clear any active wizard. Returns True if one was cancelled."""
    if chat_id in _wizard:
        _wizard.pop(chat_id, None)
        return True
    return False


# ---- Background jobs (ingest runs without blocking other commands) ----
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _start_ingest(chat_id: int, args: list[str]) -> str:
    """Launch ingest on a worker thread and return an immediate ack."""
    with _jobs_lock:
        if chat_id in _jobs:
            return "An ingestion is already running. Wait for it to finish or ask for /status."
        _jobs[chat_id] = {"kind": "ingest", "done": False}

    def worker():
        try:
            _stream_ingest(chat_id, args)
        finally:
            with _jobs_lock:
                _jobs.pop(chat_id, None)

    threading.Thread(target=worker, daemon=True, name=f"ingest-{chat_id}").start()
    return "Ingestion started in the background. I will post progress here. You can keep using other commands."


def _stream_ingest(chat_id: int, args: list[str]):
    """Run ingest, parsing SELO_PROGRESS lines into friendly progress posts."""
    selo_path = SELO_PATH
    if sys.platform == "win32" and not os.path.exists(selo_path):
        if os.path.exists(selo_path + ".exe"):
            selo_path = selo_path + ".exe"

    cmd = [selo_path, "ingest"] + args
    logging.info("ingest worker: %s", " ".join(cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(DATA_DIR),
        )
    except FileNotFoundError:
        send_telegram(chat_id, f"selo-tool binary not found at '{selo_path}'.")
        return

    summary: list[str] = []
    resumed = False
    last_progress_sent = 0.0
    try:
        for line in proc.stdout:
            line = line.rstrip("\n").rstrip("\r")
            if not line or line.startswith("DEBUG:"):
                continue
            m = re.match(r"SELO_PROGRESS (\d+)/(\d+) \(([\d.]+)%\) ~([\d.]+)/s ETA (\d+)s", line)
            if m:
                done, total, pct, rate, eta = m.groups()
                now = time.time()
                if now - last_progress_sent >= 15 or done == total:
                    last_progress_sent = now
                    eta_min = int(eta) // 60
                    eta_s = int(eta) % 60
                    eta_txt = f"{eta_min}m {eta_s}s" if eta_min else f"{eta_s}s"
                    send_telegram(
                        chat_id,
                        f"Ingesting: {done}/{total} signatures ({pct}%)\n"
                        f"About {eta_txt} remaining.",
                    )
                continue
            if "already processed" in line or "Resuming" in line:
                resumed = True
            if any(
                k in line
                for k in (
                    "already processed",
                    "dispose_fifo",
                    "Capital Gains Summary",
                    "Total proceeds",
                    "Total cost basis",
                    "Net gain/loss",
                    "Total Events:",
                    "Ingestion Summary",
                )
            ):
                summary.append(line)
        proc.wait()
        if proc.returncode != 0:
            send_telegram(chat_id, _friendly_error("".join(summary)))
        elif summary:
            lines = "\n".join(summary[-20:])
            if resumed:
                send_telegram(
                    chat_id,
                    f"Ingestion complete. No new activity found.\n\n{lines}",
                )
            else:
                send_telegram(chat_id, f"Ingestion complete.\n\n{lines}")
        else:
            send_telegram(chat_id, "Ingestion complete.")
    except Exception as e:
        logging.error("ingest worker error: %s", e)
        send_telegram(chat_id, _friendly_error(str(e)))


# ---------------------------------------------------------------------------
# Settlement watcher
# ---------------------------------------------------------------------------


def settlement_watcher(stop_event: threading.Event):
    """Background loop: run `selo-tool confirm` and push alerts on settlement."""
    logging.info("Settlement watcher started (interval=%ds)", RECONCILIATION_INTERVAL)
    state = load_state()
    settled = state.get("settled_signatures", {})

    while not stop_event.is_set():
        stop_event.wait(RECONCILIATION_INTERVAL)
        if stop_event.is_set():
            break
        if _run_lock.locked():
            logging.debug("Watcher skipped: selo-tool is busy")
            continue

        try:
            rc, out = run_selo(["confirm"], timeout=30)
            if rc != 0:
                continue
            # Parse "SETTLED via Tx: <sig>" lines.
            for line in out.splitlines():
                m = re.search(r"SETTLED via Tx:\s*(\S+)", line)
                if not m:
                    continue
                sig = m.group(1)
                if sig in settled:
                    continue
                settled[sig] = int(time.time())
                qm = re.search(r"Quote\s+\[([^\]]+)\]", line)
                qid = qm.group(1) if qm else "unknown"
                alert_all(f"Settlement confirmed\nQuote `{qid}` settled on chain.\nTx: `{sig}`")

            state["settled_signatures"] = settled
            save_state(state)
        except Exception as e:
            logging.error("Watcher error: %s", e)


# ---------------------------------------------------------------------------
# Scheduler (cron jobs)
# ---------------------------------------------------------------------------


def tracked_wallets() -> list[str]:
    """Wallets the daily close and reconciliation should follow.

    Reads the persisted merchant config through selo-tool merchant, so the
    cron follows the same tracked wallets the operator configured rather than
    a single SELO_MERCHANT env var. Falls back to SELO_MERCHANT for operators
    who have not adopted the merchant config yet.
    """
    rc, out = run_selo(["merchant"], timeout=15)
    if rc == 0:
        pubs = re.findall(r"^\s*(?:primary|tracked)\s+(\S{32,44})", out, re.MULTILINE)
        if pubs:
            return pubs
    if MERCHANT_PUBKEY:
        return [MERCHANT_PUBKEY]
    return []


def daily_close_job():
    """Scheduled daily close: build close, verify root, push report."""
    wallets = tracked_wallets()
    if not wallets:
        logging.warning("Daily close skipped: no tracked wallets configured.")
        return
    now = int(time.time())
    day_start = now - (now % 86400)
    day_end = day_start + 86400
    year = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y")

    logging.info("Running daily close for %d wallet(s): %d to %d", len(wallets), day_start, day_end)
    rc, out = run_selo(
        [
            "close",
            "--start", str(day_start),
            "--end", str(day_end),
            "--output", str(DATA_DIR / "close_record.txt"),
        ],
        timeout=120,
    )
    if rc == 0:
        # Extract every commitment from a multi-wallet close, or the one from
        # a single-wallet close.
        roots = re.findall(r"Commitment Base58:\s*(\S+)", out)
        root_list = "\n".join(f"`{r}`" for r in roots) if roots else "unknown"
        alert_all(f"Daily close anchored.\nPoseidon commitment(s):\n{root_list}")

        # Generate HTML report.
        rc2, _ = run_selo(
            [
                "export-html",
                "--year", year,
                "--output", str(DATA_DIR / f"report_{year}.html"),
            ],
            timeout=60,
        )
        if rc2 == 0:
            alert_all(f"Audit report generated: `report_{year}.html`")
    else:
        alert_all(f"Daily close failed:\n```\n{out[:1000]}\n```")


def health_check_job():
    """Hourly store status check, pushed to alert chats."""
    rc, out = run_selo(["check"], timeout=15)
    if rc == 0 and ALERT_IDS:
        # Only push if there are pending quotes.
        if "Pending" in out:
            alert_all(f"Hourly store check:\n```\n{out[:1500]}\n```")


def monthly_reconciliation_job():
    """Monthly full reconciliation: ingest recent, review, export report."""
    wallets = tracked_wallets()
    if not wallets:
        return
    now = datetime.fromtimestamp(time.time(), tz=timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0).strftime("%Y-%m-%d")
    year = now.strftime("%Y")

    alert_all(f"Monthly reconciliation started for {len(wallets)} wallet(s).")
    needs_review = False
    for wallet in wallets:
        rc, out = run_selo(
            [
                "ingest", wallet,
                "--since", month_start,
                "--all",
            ],
            timeout=600,
        )
        if rc != 0:
            alert_all(f"Reconciliation ingest failed for {wallet}:\n```\n{out[:800]}\n```")
            continue
        # Check for unclassified counterparties.
        rc2, review_out = run_selo(["review", wallet], timeout=30)
        needs_review = needs_review or "Needs Review" in review_out

    report_path = str(DATA_DIR / f"report_{year}_{now.strftime('%m')}.html")
    rc2, _ = run_selo(
        [
            "export-html",
            "--year", year,
            "--from", month_start,
            "--output", report_path,
        ],
        timeout=60,
    )
    msg = f"Monthly reconciliation complete.\nReport: `{report_path}`"
    if needs_review:
        msg += "\n\n*Action required:* unclassified counterparties need review.\nRun `/review` for details."
    alert_all(msg)


def setup_scheduler(stop_event: threading.Event):
    """Register cron jobs on the APScheduler, or fall back to a simple timer."""
    if not HAS_APSCHEDULER:
        logging.warning(
            "APScheduler not installed. Cron-based scheduling is disabled. "
            "Install with: pip install apscheduler"
        )
        # Simple fallback: just reconciliation on a thread.
        while not stop_event.is_set():
            stop_event.wait(RECONCILIATION_INTERVAL)
            if stop_event.is_set():
                break
            try:
                run_selo(["confirm"], timeout=30)
            except Exception:
                pass
        return

    scheduler = BackgroundScheduler(timezone="America/Sao_Paulo")
    scheduler.add_job(
        daily_close_job,
        CronTrigger.from_crontab("0 23 * * *"),
        id="daily_close",
        name="Daily Close",
        coalesce=True,
        max_instances=1,
    )
    if HAS_APSCHEDULER:
        scheduler.add_job(
            monthly_reconciliation_job,
            CronTrigger.from_crontab("0 6 1 * *"),
            id="monthly_reconciliation",
            name="Monthly Reconciliation",
            coalesce=True,
            max_instances=1,
        )
    scheduler.add_job(
        health_check_job,
        CronTrigger.from_crontab("0 * * * *"),
        id="health_check",
        name="Health Check",
        coalesce=True,
        max_instances=1,
    )
    scheduler.start()
    logging.info("Scheduler started with %d jobs.", len(scheduler.get_jobs()))

    # Wait until stopped.
    while not stop_event.is_set():
        stop_event.wait(5)
    scheduler.shutdown(wait=False)


# ---------------------------------------------------------------------------
# Telegram long-polling
# ---------------------------------------------------------------------------


def poll_telegram(stop_event: threading.Event):
    """Main long-polling listener for incoming Telegram messages."""
    if not TOKEN:
        logging.error("TELEGRAM_TOKEN is not set. Telegram listener disabled.")
        return

    logging.info("Telegram long-polling started.")
    offset = 0
    consecutive_errors = 0

    while not stop_event.is_set():
        url = f"https://api.telegram.org/bot{TOKEN}/getUpdates?offset={offset}&timeout=30"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                consecutive_errors = 0
                for result in data.get("result", []):
                    offset = result["update_id"] + 1

                    # Inline-button tap: route to the callback handler.
                    cb = result.get("callback_query")
                    if cb:
                        chat_id = cb.get("message", {}).get("chat", {}).get("id")
                        cb_data = cb.get("data", "")
                        cb_id = cb.get("id", "")
                        cb_msg_id = cb.get("message", {}).get("message_id")
                        if not chat_id or not cb_data:
                            continue
                        logging.info("[chat %s] callback: %s", chat_id, cb_data)
                        reply = handle_callback(chat_id, cb_data, cb_id)
                        # After a terminal choice, clear this menu's buttons so
                        # the tap target self-destructs instead of lingering.
                        if cb_msg_id and cb_data not in (
                            "menu:help",
                            "menu:status",
                            "menu:check",
                            "menu:confirm",
                            "menu:issue",
                            "menu:ingest",
                            "menu:balance",
                            "menu:close",
                            "menu:export",
                            "menu:rules",
                            "menu:wallets",
                            "wallet:list",
                            "export:list",
                        ):
                            _clear_buttons(chat_id, cb_msg_id)
                        if reply:
                            send_telegram(chat_id, reply)
                        continue

                    # Plain text message.
                    msg = result.get("message", {})
                    chat_id = msg.get("chat", {}).get("id")
                    text = msg.get("text", "").strip()
                    if not chat_id or not text:
                        continue

                    logging.info("[chat %s] %s", chat_id, text[:100])
                    # /cancel clears any active wizard.
                    if text.lower().lstrip("/") == "cancel":
                        if _cancel_wizard(chat_id):
                            reply = "Cancelled."
                        else:
                            reply = "Nothing to cancel."
                        send_telegram(chat_id, reply)
                        continue

                    # If a wizard is waiting, feed this text to it.
                    wizard_reply = _route_wizard_text(chat_id, text)
                    if wizard_reply is not None:
                        if wizard_reply:
                            with _run_lock:
                                pass
                            send_telegram(chat_id, wizard_reply)
                        continue

                    with _run_lock:
                        pass
                    reply = dispatch(chat_id, text)
                    if reply:
                        send_telegram(chat_id, reply)
        except Exception as e:
            consecutive_errors += 1
            logging.error("Poll error (consecutive=%d): %s", consecutive_errors, e)
            if consecutive_errors > 10:
                logging.critical("Too many consecutive poll errors. Sleeping 60s.")
                stop_event.wait(60)
                consecutive_errors = 0
            else:
                stop_event.wait(5)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def register_bot_commands():
    """Register the selo slash commands with Telegram, replacing the stale
    ZeroClaw tool menu that was left when the daemon owned the token."""
    if not TOKEN:
        return
    url = f"https://api.telegram.org/bot{TOKEN}/setMyCommands"
    commands = [
        {"command": "start", "description": "Show the button menu"},
        {"command": "help", "description": "Full command list"},
        {"command": "status", "description": "Store and watcher health"},
        {"command": "check", "description": "Inspect store status and pending quotes"},
        {"command": "confirm", "description": "Reconcile pending quotes on chain"},
        {"command": "balance", "description": "Query a wallet balance"},
        {"command": "ptax", "description": "Show the current PTAX rate"},
        {"command": "ingest", "description": "Ingest a wallet's history"},
        {"command": "review", "description": "List unclassified counterparties"},
        {"command": "export", "description": "Export an audit report"},
        {"command": "close", "description": "Run a daily close"},
    ]
    payload = json.dumps({"commands": commands}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        logging.info("Registered selo bot commands.")
    except Exception as e:
        logging.error("setMyCommands failed: %s", e)


def main():
    logging.info("=== Selo Telegram Operational Harness ===")
    logging.info("SELO_PATH: %s", SELO_PATH)
    logging.info("DATA_DIR: %s", DATA_DIR)
    logging.info("ADMIN_IDS: %s", ADMIN_IDS or "(none — all open)")
    logging.info("ALERT_IDS: %s", ALERT_IDS or "(none)")
    logging.info("MERCHANT: %s", MERCHANT_PUBKEY or "(not set)")
    logging.info("APScheduler: %s", "available" if HAS_APSCHEDULER else "not installed — cron disabled")

    register_bot_commands()

    stop = threading.Event()
    threads = [
        threading.Thread(target=settlement_watcher, args=(stop,), daemon=True, name="watcher"),
        threading.Thread(target=poll_telegram, args=(stop,), daemon=True, name="poll"),
        threading.Thread(target=setup_scheduler, args=(stop,), daemon=True, name="scheduler"),
    ]
    for t in threads:
        t.start()

    logging.info("All subsystems running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down...")
        stop.set()
        for t in threads:
            t.join(timeout=5)
        logging.info("Stopped.")


if __name__ == "__main__":
    main()
