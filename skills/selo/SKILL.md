---
name: selo
description: >-
  Pure-Rust cryptographic accounting on Solana. Issue Solana Pay invoices,
  confirm on-chain settlement, ingest FIFO tax lots, run deterministic daily
  closes with Poseidon BN254 commitments, export self-verifying HTML audit
  reports, and verify a ledger against a published state root. Use whenever
  the user asks about payments, invoicing, settlement, tax lots, PTAX cost
  basis, daily closes, or audit verification.
version: 0.1.0
---

# Selo

Selo is a deterministic command-line accounting tool. It turns a Solana
wallet's transaction history into FIFO tax lots valued in BRL at the official
Banco Central do Brasil PTAX rate, closes each trading day into a
byte-identical canonical record, and commits the Poseidon BN254 merkle root
to chain as an SPL Memo. The core accounting engine is integer-exact and
I/O-free; all network transport lives in the tool.

## Binary

Invoke the release binary at `target/release/selo-tool` (add `.exe` on
Windows). Build it once with `cargo build --release --workspace`. Set
`SOLANA_RPC_URL` (a Helius endpoint with `?api-key=` is preferred) and
`HELIUS_API_KEY` in the environment. The tool reads `.selo_store.json`,
`.selo_rules.json`, and `.selo_ledger_<pubkey>.json` from the current working
directory, so run it from a directory that holds the operator's state.

## Security model

The model selects, code constructs. Never invent a price, a total, a
destination address, a signature, or a settlement. Prices come from the PTAX
feed and chain data; confirmation comes from parsing on-chain transactions.
Commands below take pubkeys and amounts from the operator, never guessed.

## Commands

### Payments and settlement

- `issue --amount <lamports> --recipient <pubkey> --label "<label>" [--message "<msg>"]`
  creates a Solana Pay payment-intent quote with a single-use reference key
  and an embedded amount tag. Output the `solana:` URI to the user.
- `check` prints the local store status: total, pending, settled, expired
  quotes.
- `confirm` scans the cluster for signatures against every pending quote's
  reference key and marks settled quotes. Safe to run repeatedly.
- `expire` marks past-expiry pending quotes as expired.
- `refund <quote_id> --merchant <pubkey> [--mint <mint>]` prepares an
  unsigned refund transaction for a settled quote. Requires the settlement
  to exist on chain.

### Ledger intelligence

- `ingest <pubkey> [--all] [--since <date>] [--before <date>]` fetches
  transaction history, parses net balance deltas per mint, classifies
  counterparties, and rebuilds the integer-exact FIFO lot book. Pass
  `--payments-as-expenses` to treat outbound payments (non-swap transfers to
  counterparties) as operating expenses instead of capital disposals.
  Checkpointed per signature; interrupted runs resume.
- `review <pubkey>` lists unclassified counterparties needing a rule.
- `rules --add <pubkey> --name "<name>"` registers a counterparty label.
- `backfill <pubkey> [--all]` lists historical signatures.
- `balance <pubkey-or-name>` queries lamport and stablecoin balances.
- `ptax` prints the live BCB PTAX rate and the historical baseline.

### Daily close and audit

- `close --merchant <pubkey> --start <unix> --end <unix> [--output <file>]`
  builds the deterministic daily close, computes the Poseidon BN254
  commitment, and prepares an unsigned anchor transaction for a human
  (T1) signature.
- `anchor --merchant <pubkey> --start <unix> --end <unix>
  --nonce-account <addr> --authority <addr>` builds the same close but uses
  a durable nonce so the unsigned payload never expires while awaiting
  signature.
- `export-html [--year <YYYY>] [--wallet <pubkey>] [--from <date>] [--to
  <date>] [--output <file>]` writes a standalone self-verifying audit report
  with an embedded Poseidon state root and browser-side integrity check.
- `verify --root <hash>` recomputes the local ledger's Poseidon state root
  and reports whether it matches the given anchor.
- `tax-report` prints the text tax-lot report for all ledgers on disk.

## Invocation conventions

- Run from the operator's data directory so the state files resolve.
- Prefer pubkeys already registered in the rules file; otherwise pass the
  pubkey and offer to register it.
- Never claim a quote is settled until `confirm` has found a signature on
  chain.
- After `ingest`, offer `export-html` so the user has a self-verifying
  statement, and surface any `! needs review` counterparties.
