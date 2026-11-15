# Selo - Security Review

**Target:** `github.com/blockballr/selo` at `5b49e87`
**Date:** 2026-11-15
**Scope:** source-first review of the security-relevant surfaces. Not a full multi-agent audit run.
**Method:** static source review, plus build and test execution already performed on the reviewed commit (301 tests pass, release binary builds).

## Coverage statement

This is a focused review, not an exhaustive audit. Surfaces reviewed:

- authorization and command dispatch in `adapters/telegram/main.py` (66 KB, the largest untrusted-input surface)
- process execution and argument handling
- signing-key material across `crates/`
- payment verification in `crates/selo-core/src/x402.rs`
- local state persistence and file permissions
- transport security (TLS) for RPC and price feeds

Not reviewed: the full accounting arithmetic in `basis.rs` and `settle.rs`, the Groth16 circuit constraints beyond the setup source, the ZeroClaw skill wiring under `skills/`, and deployment topology. No dynamic testing was performed against a running bot.

Coverage is partial. The absence of findings in an unreviewed area means nothing.

## Trust boundaries

1. Remote Telegram user -> bot process -> local `selo-tool` binary -> local ledger state.
2. Untrusted RPC endpoint response -> net-delta ingestion -> tax lot book.
3. Untrusted HTTPS price feeds (BCB PTAX, Jupiter, CoinGecko, Binance) -> fiat valuation.
4. Local filesystem -> ledger state (no integrity protection at rest).

Boundary 1 is the one with real defects.

## Confirmed findings

Every finding below was fixed on the reviewed branch after this review. The
remediation is recorded in the Status line under each heading and summarized
in [Remediation](#remediation).

### F1 - Authorization fails open when `TELEGRAM_ADMIN_IDS` is unset (High)

**Status:** Fixed. `is_admin` now denies when the allowlist is empty; opening the
bot requires an explicit `TELEGRAM_ALLOW_ALL` opt-in that logs a warning.

`adapters/telegram/main.py:446`

```python
def is_admin(chat_id: int) -> bool:
    return not ADMIN_IDS or chat_id in ADMIN_IDS
```

`ADMIN_IDS` is built from `TELEGRAM_ADMIN_IDS` (`main.py:57`). If the variable is empty or unset, `not ADMIN_IDS` is true and **every** chat that can reach the bot is treated as an administrator. The startup log states the condition plainly (`main.py:1704`):

```python
logging.info("ADMIN_IDS: %s", ADMIN_IDS or "(none — all open)")
```

`ADMIN_COMMANDS` (`main.py:405`) includes the operations that mutate state or produce payable artifacts:

```python
ADMIN_COMMANDS = { "close", "issue", "refund", "expire", "ingest", "anchor", "rules", }
```

Consequence: on a deployment that omits the variable, any Telegram user who finds the bot can create payment intents (`/issue` with an attacker-chosen recipient), stage refunds and period anchors, rewrite counterparty labeling rules, and trigger ingestion. The `/issue` path is the sharpest: it produces a Solana Pay intent that a counterparty is expected to pay.

Precondition: the operator does not set `TELEGRAM_ADMIN_IDS`. The code neither refuses to start nor warns as an error; it logs informational text and proceeds.

Severity is High rather than Medium because the failure is the *default* posture of the code, not a weakened control, and the affected resource is payment intent generation.

Smallest effective fix: refuse to start when `TELEGRAM_ADMIN_IDS` is empty, or make `is_admin` return `False` when the set is empty and require an explicit `--allow-all` flag for single-user local use. Add a regression test asserting empty config denies `close`, `issue`, and `refund`.

### F2 - Confirmation tokens are guessable and bound to the chat, not the user (Medium)

**Status:** Fixed. Tokens come from `secrets.choice`, are 8 characters, and are
bound to `(chat_id, user_id)`. A member of the same group can no longer spend
another member's pending confirmation.

`adapters/telegram/main.py:578`

```python
def _make_confirm_token(chat_id: int, args: list[str]) -> str:
    import random
    token = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=4))
    _pending_confirms[token] = (chat_id, args, time.time() + 120)
```

Two defects:

1. **`random` instead of `secrets`.** `random` is Mersenne Twister, seeded predictably and not a CSPRNG. A four-character token from a 36-character alphabet is 36^4 = 1,679,616 possibilities, which is small for an authorization token.
2. **Bound to `chat_id`, not `from_user.id`.** `_handle_confirm` (`main.py:589`) only checks `stored_chat != chat_id`. In a group chat every member shares one `chat_id`, so any member can consume another member's pending confirmation by sending `/yes <token>`.

Mitigating factors that keep this at Medium: the entry is consumed with `pop` (single use), it expires after 120 seconds, and a wrong token reveals nothing.

Impact: a second party in the same group approves a destructive action that the operator staged, for example a refund or an anchor.

Smallest effective fix: use `secrets.choice` with at least 8 characters, and bind the entry to `(chat_id, from_user.id)`, comparing both on confirm.

### F3 - `record-sample` is classified read-only but writes to the ledger (Medium)

**Status:** Fixed. `record-sample` moved to `ADMIN_COMMANDS` and out of
`READONLY_COMMANDS`, so it passes the admin gate.

`main.py:412`, `main.py:495`

```python
READONLY_COMMANDS = { ..., "record-sample" }
...
"record-sample": ["record-sample"],
```

`record-sample` records a sample acquisition at the live PTAX rate, which mutates the cost-basis book. Because it is in `READONLY_COMMANDS`, it bypasses the admin gate entirely. Under F1 this is unauthenticated; under a correct `ADMIN_IDS` configuration it is still available to every non-admin user who can reach the bot.

Impact: unauthenticated write into the accounting record the tool exists to protect. On a tax ledger, integrity is the product.

Smallest effective fix: move `record-sample` into `ADMIN_COMMANDS`, and audit the rest of `READONLY_COMMANDS` for writes (`export-html` also produces a file, see F4).

### F4 - Arbitrary file write through `--output` reachable from chat (Low)

**Status:** Fixed at the trust boundary. The adapter rejects an absolute path or
any path containing `..` in `--output` for `export-html` and `close`. The CLI
keeps unrestricted paths, which is correct for an operator at a terminal.

`main.py:511` forwards chat arguments straight to the binary:

```python
if cmd in ("export-html", "exporthtml"):
    return run_selo_pretty(["export-html"] + args)
```

and `crates/selo-tool/src/main.rs:1724` writes wherever that path points:

```rust
fs::write(&output, html_content)
```

There is no containment check and no canonicalization. Combined with F1, a remote user chooses the destination path, limited only by the privileges of the bot process.

Severity is Low because writing files is the command's legitimate purpose and the practical impact depends on the deployment account.

Smallest effective fix: resolve the path against a configured report directory and reject results that escape it.

### F5 - Local state has no permission hardening (Low)

**Status:** Fixed. State files are written through `write_private`, which opens
them `0600` on Unix. Ledger, rules, store and merchant config all route through
it.

`crates/selo-tool/src/main.rs:33`

```rust
const MERCHANT_FILE: &str = ".selo_merchant.json";
```

Searching the workspace for `set_mode`, `0o600`, `0o700`, or any `permissions(` call returns nothing. State is written with the process umask, typically `0644`, in the working directory. The ledger contains wallet addresses, amounts, counterparty labels, and business income data.

Impact: other local users on a shared host can read the accounting record. No cross-boundary network consequence.

Smallest effective fix: open state files with `0600` on Unix via `OpenOptions::extend` plus `PermissionsExt`.

### F6 - Full command lines are written to logs (Low)

**Status:** Fixed. `_redact` masks the value after `--rpc`, `--rpc-url` and
`--api-key`, and rewrites `api-key=` inside a URL, before any argv reaches the
log.

`main.py:304` and `main.py:357` log the joined argv:

```python
logging.info("run: %s (cwd=%s)", " ".join(cmd), DATA_DIR)
```

`crates/selo-tool/src/main.rs:658` constructs an RPC URL that embeds a provider key:

```rust
Ok(key) => format!("https://mainnet.helius-rpc.com/?api-key={}", key),
```

Any invocation that carries an RPC URL, a merchant address, or a label through argv lands in the adapter log verbatim, and a Helius key would land there in full.

Smallest effective fix: redact arguments matching `api-key=`, `--rpc`, and similar before logging.

## Non-findings (verified as claimed)

These were checked because they are the claims most likely to be false, and they hold:

- **No signing key exists in the repository.** No `Keypair`, no `secret_key`, no `sign_message` call outside test helpers. `fr_from_bytes_be` in `prove.rs` is field-element conversion, not key material. The T0 claim is accurate.
- **No OS command injection in the adapter.** Every `subprocess` call passes an argument list, never `shell=True`. `shlex.split` is used for user text.
- **Payment verification is defensively built.** `x402.rs` rejects non-integer amounts, requires the server to declare a fee payer, and `vtx::verify_and_sign` refuses any fee payer that is not our own wallet. The fee-payer-substitution attack is handled.
- **TLS is not weakened.** No `danger_accept_invalid_certs` or equivalent. `ureq` defaults apply.
- **The RPC seam is honest.** `selo-core` has no network dependency; `ureq` appears only in `selo-tool`.

## Known design gap, restated

The Groth16 setup in `crates/selo-core/src/prove.rs:259` uses `StdRng::seed_from_u64(0xC0FFEE)`. The proving key is therefore regenerable by anyone, and a proof produced by `prove` carries no assurance to a third party. This is documented in source comments and is a correctness gap, not a vulnerability in the deployed tool. It does invalidate any external claim of "ZK verification".

## Remediation

| Finding | Change | Verified by |
|---|---|---|
| F1 | `is_admin` fails closed; `TELEGRAM_ALLOW_ALL` is the explicit opt-in | `is_admin(123)` returns `False` with an empty allowlist |
| F2 | `secrets.choice`, 8 chars, bound to `(chat_id, user_id)` | a different user is refused; the token is single use |
| F3 | `record-sample` moved to `ADMIN_COMMANDS` | membership assertion on both sets |
| F4 | `_unsafe_output` rejects absolute and `..` paths from chat | absolute and traversal rejected, bare filename allowed |
| F5 | `write_private` opens state files `0600` on Unix | `cargo test --workspace`, release build |
| F6 | `_redact` masks API keys in argv before logging | `api-key=SECRET123` renders as `api-key=***` |

The Rust workspace still reports 296 core and 5 tool tests passing after these
changes.

## Priority

1. F1 - fail-open authorization. Fix before any multi-user deployment.
2. F3 - `record-sample` write bypass.
3. F2 - confirmation token strength and binding.
4. F4, F5, F6 - hardening.

## Scope limits

No execution against a live Telegram bot. F1 through F4 were established by source trace; the reachability of F1 depends on a bot deployment where `TELEGRAM_ADMIN_IDS` is unset, which the code permits but does not guarantee. F5 and F6 are source-confirmed.
