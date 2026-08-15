## Selo Adapters

Channel adapters that bridge Selo into messaging platforms. The Telegram adapter
is the primary operational harness: it owns scheduling, SOP-driven workflows, and
settlement alerts. The WhatsApp adapter routes through ZeroClaw's webhook server.

### Telegram (primary operations harness)

The Telegram adapter is the main control surface for Selo. It provides:

- **Command routing**: All selo-tool subcommands available via `/` commands,
  with admin gating for destructive operations and confirm-token gates for
  close and issue.
- **Built-in cron**: Daily close at 23:00, hourly health checks, monthly
  reconciliation on the 1st at 06:00. No external crontab or ZeroClaw trigger
  needed.
- **Settlement watcher**: Runs `selo-tool confirm` every 60 seconds, with
  signature deduplication across restarts. Pushes alerts to configured chat
  IDs when a payment settles on chain.
- **Progress streaming**: Long-running ingest commands stream progress updates
  back to the chat so the operator can watch the backfill proceed.

Start it:

    pip install python-dotenv apscheduler
    TELEGRAM_TOKEN=<your-bot-token> \
    TELEGRAM_ADMIN_IDS=<your-chat-id> \
    TELEGRAM_ALERTS_TO=<chat-id> \
    SELO_PATH=./target/release/selo-tool \
    SELO_MERCHANT=<your-merchant-pubkey> \
    python adapters/telegram/main.py

Environment variables:

| Variable | Required | Purpose |
|---|---|---|
| `TELEGRAM_TOKEN` | Yes | Bot token from @BotFather |
| `TELEGRAM_ADMIN_IDS` | No | Comma-separated chat IDs allowed to run destructive commands |
| `TELEGRAM_ALERTS_TO` | No | Comma-separated chat IDs that receive settlement and scheduled-job alerts |
| `SELO_PATH` | Yes | Path to the selo-tool release binary |
| `SELO_MERCHANT` | No | Fallback merchant pubkey when no merchant config exists |
| `SELO_DATA_DIR` | No | Directory where selo-tool state files live (default: the repo root, so the adapter, CLI, and agent share one set of `.selo_*` files) |
| `SELO_FISCAL_YEAR` | No | Fiscal year for report generation (default: `2026`) |
| `SELO_RECONCILIATION_SECS` | No | Settlement check interval (default: `60`) |
| `HELIUS_API_KEY` | No | Helius RPC API key for dedicated Solana access |
| `SOLANA_RPC_URL` | No | Override the default mainnet RPC endpoint |

Tracked wallets come from the persisted merchant config, set with
`selo-tool merchant --set <pubkey> --name <label>`. The daily close and monthly
reconciliation follow every tracked wallet; `SELO_MERCHANT` is only a fallback
for operators who have not configured a merchant yet.

Per-machine overrides can go in `adapters/telegram/config.local.toml` (already
gitignored via the `*.local.toml` rule in `.gitignore`).

**Cron jobs** (requires `pip install apscheduler`):

| Job | Schedule | What it does |
|---|---|---|
| Daily close | 23:00 local | Runs `close` for every tracked wallet, extracts each Poseidon commitment, pushes the anchor memo, and generates an HTML audit report |
| Health check | Hourly | Runs `check` and pushes store status (if there are pending quotes) |
| Monthly reconciliation | 1st, 06:00 | Ingests recent transactions per tracked wallet, runs `review` for unclassified counterparties, exports a scoped HTML report, and flags items needing operator review |

If APScheduler is not installed, scheduling falls back to a simple
reconciliation loop that runs `confirm` on the configured interval.

**Confirm-token gates**: Destructive operations (`close`, `issue`) require a
second-step confirmation. The bot replies with a random 4-character token valid
for 2 minutes. The operator must reply `/yes <token>` to execute. This prevents
accidental anchors from a misfired command.

### WhatsApp (via ZeroClaw webhook)

WhatsApp integration is dispatched through ZeroClaw's webhook server to the
selo skill (`skills/selo/SKILL.toml`). It requires a Meta Cloud API account, a
public webhook URL, and the ZeroClaw runtime; the in-repo verification for the
selo skill is `tools/selo-skill-TEST.ps1` (or `selo-skill-TEST.sh`), which runs
the workspace test suite.
