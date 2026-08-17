## Selo Architecture Documentation

This document covers how Selo's cryptographic accounting engine works. It
explains the dependency-inversion architecture, the net-delta ingestion model,
FIFO tax lot accounting with PTAX fiat valuation, deterministic daily closes
with Poseidon Merkle commitments, durable-nonce anchoring, and the
self-verifying HTML audit report export. It also documents the integration
surface for ZeroClaw and standalone adapter-driven operation.

Selo's design choices -- separating pure business logic from network transport
via the `RpcSeam` trait, using Poseidon hashing over BN254 for Merkle tree
folding (with SHA-256 for domain-separated field elements), durable nonces for
anchor resilience, and browser-based SHA-256 integrity verification in exported
HTML reports -- were made for zero-knowledge circuit compatibility, regulatory
compliance, and robust audit defense.

### Design Principles

**Strict Dependency Inversion (Brain and Hands Pattern)**

All core accounting logic, FIFO tax lot state machines, transaction assembly,
and cryptographic hash commitments live exclusively inside `selo-core` (the
Brain) with zero network or I/O dependencies. Network transport (ureq), local
disk persistence, and CLI interaction reside strictly in `selo-tool` (the
Hands).

The inversion is enforced through the `RpcSeam` trait (`crates/selo-core/src/lib.rs`):

```rust
pub trait RpcSeam {
    fn get_balance(&self, address: &str) -> Result<u64, String>;
    fn get_latest_blockhash(&self) -> Result<String, String>;
    fn get_signatures(&self, address: &str) -> Result<Vec<String>, String>;
    fn get_signatures_paginated(&self, address: &str, before: Option<&str>, limit: usize) -> Result<Vec<String>, String>;
    fn get_transaction(&self, sig: &str) -> Result<Value, String>;
}
```

`AccountingEngine<T: RpcSeam>` wraps an RPC transport and exposes the full
engine API. Tests inject a stub `RpcSeam` that returns canned responses, so
all 296 selo-core tests run offline with no network dependency.

**Model-Excluded Money Path**

Autonomous agents or AI models can trigger intents, but they are physically
and cryptographically excluded from the money path. The engine uses a stock
release binary where the routing logic (who gets paid and how much) is
immutable. This prevents prompt injection or hallucination from altering
transaction destinations, amounts, or recipient addresses.

**Human-Anchored Finality (Tier 1)**

While data ingestion is autonomous, the transition of a ledger from pending to
immutable requires a human signature. The daily close produces an unsigned
transaction carrying the Poseidon commitment as an SPL Memo. A human (T1
custody) reviews and signs it. `prepare_anchor` in `close.rs` accepts an
optional `NonceState` parameter: when provided, the transaction uses a durable
nonce account's stored nonce as its blockhash and includes an
`AdvanceNonceAccount` instruction, so the unsigned payload does not expire while
waiting for human review.

**Deterministic Re-derivation and Valuation**

Identical inputs (chain transactions and quote logs) must yield identical
cryptographic states and Merkle roots every single time. To avoid oracle
drift, acquisitions and disposals are valued directly in local fiat currency
(BRL) using official Banco Central do Brasil PTAX exchange rates, avoiding
compound rounding errors from intermediate token hopping.

**Privacy by Default (the Identity Shield)**

Public indexers should never store customer personally identifiable
information. The close module's `reject_identity_shaped` function refuses to
process any SKU containing an `@` symbol or a run of 7 or more consecutive
digits. The anchored record is public through the Solana indexer, so customer
identity in it would be world readable and could not be withdrawn.

### System Architecture

The system is organized in four layers, matching the roadmap phases:

**PODA (Input Layer).** Solana RPC nodes provide transaction streams via
`getSignaturesForAddress` and `getTransaction`. The BCB SGS API (series 10813)
provides the daily USD/BRL PTAX rate. A Helius API key enables dedicated RPC
access; the tool falls back to the public mainnet endpoint when none is set.

**ALICERCE (Processing Layer).** JSON files on local disk serve as the store
(`.selo_store.json` for quotes, `.selo_rules.json` for counterparty mappings,
`.selo_ledger_<pubkey>.json` per wallet). The `RpcSeam` trait abstracts over
the ureq JSON-RPC transport. Reference key matching reconciles on-chain
activity against stored payment intents.

**VIRGILIA (Business Logic Layer).** Pure state machines for FIFO tax lot
accounting, PTAX fiat conversion at block time, and counterparty resolution
with auto-labeling against a pre-seeded registry. The settlement loop matches
open quotes against on-chain settlement events.

**SELO (Cryptographic Closing Layer).** Deterministic daily close compaction
into byte-identical canonical records, Poseidon BN254 Merkle root commitments,
durable-nonce anchor preparation, and self-verifying HTML report export.

### The Scan Phase

This phase starts with a target public key (root wallet or Associated Token
Account) and traverses the Solana cluster's transaction history using
paginated JSON-RPC calls (`getSignaturesForAddress`). The `Backfiller` in
`ledger.rs` pages through signatures with optional `--since` and `--before`
date filters, fetching each transaction via `getTransaction` and parsing its
events. The backfill is sequential (one RPC node, page by page), not parallel
across multiple providers.

### The Compile and Reconciliation Phase

This phase processes the ingested transaction signatures into structured
ledger events and tax lots. It evaluates net balance deltas at transaction
boundaries, matches payment intent reference keys against active quote logs,
computes Poseidon BN254 Merkle roots for daily trading windows, prepares
anchor transactions carrying SPL Memo instructions, and exports self-verifying
standalone HTML audit statements.

### Ledger Intelligence

The ledger engine processes raw blockchain state and converts it into
structured financial events.

**Event Types**

The `LedgerEvent` struct carries eight event kinds:

| Kind | Meaning |
|---|---|
| `Income` | Inbound transfer from a classified (known) counterparty |
| `Expense` | Outbound transfer to a classified counterparty |
| `Transfer` | Movement to or from an unclassified address |
| `Revenue` | Proceeds from a settled payment quote |
| `Payout` | Outbound payment against a quote |
| `FeePaid` | Network or protocol fee |
| `QuoteIssued` | A new payment intent was created |
| `QuoteSettled` | A payment intent was confirmed on chain |

**Counterparty Rules and Auto-Labeling**

Raw blockchain data consists of unreadable Base58 public keys. Selo maintains
a pre-seeded `CounterpartyRegistry` (`ledger.rs`) mapping major Solana
programs and mints (Jupiter v6, Raydium V4, Orca Whirlpool, Phoenix DEX,
USDC, USDT, PYUSD, Superteam Brazil Treasury, and the system programs) to
human-readable entity labels.

If an unknown address appears in a transaction, Selo flags it as
`! [Needs Review]`, prompting the operator to register a mapping rule via
`selo-tool rules --add <PUBKEY> --name "<Label>"`.

**Net-Delta Transaction Ingestion**

High-throughput Automated Market Makers (AMMs), liquidity pools, and perp
DEXes generate complex internal instruction noise. Selo bypasses this
complexity by evaluating economic reality strictly at the transaction
boundary.

For SOL transfers, the net delta is computed as:

```
net_delta = delta + fee
```

where `delta` is the wallet's SOL balance change and `fee` is the transaction
fee paid. Both are extracted from `getTransaction`'s `preBalances` and
`postBalances` arrays for the wallet's account index, plus the fee from the
transaction `meta`. For SPL token transfers, the delta is read from the
`preTokenBalances` and `postTokenBalances` arrays.

This is protocol-agnostic. A Meteora DLMM yield harvest, a Jupiter Perps PnL
settlement, a Drift funding payment, an Orca Whirlpool rebalance -- all of
them collapse to a single net delta per mint per transaction. No
instruction-level parsing, no protocol-specific code paths.

Events smaller than 1000 base units (below dust threshold) are filtered out.

**PTAX Fiat Valuation**

The cost basis formula is:

```
C_BRL = amount * PTAX_USD/BRL(T)
```

where `PTAX_USD/BRL(T)` is the BCB official rate for the transaction's block
time. The current implementation fetches the latest rate from the BCB SGS API
(series 10813) and also provides a hardcoded historical baseline of 5.0500
BRL/USD via `get_historical_ptax()`.

For volatile assets like SOL, `fetch_sol_brl_price()` in `ptax.rs` combines a
live SOL/USD price from Jupiter's free price API
(`https://lite-api.jup.ag/price/v3`) with the BCB USD/BRL PTAX rate, producing
a SOL/BRL price for oracle-derived cost basis entries. When either feed is
unreachable, the function falls back to historical defaults
(`DEFAULT_HISTORICAL_SOL_USD = 20.00` and `DEFAULT_HISTORICAL_PTAX = 5.0500`),
and the `is_live` flag in the return tuple lets the caller distinguish a live
price from a fallback.

**Ingest Checkpointing**

The `TaxLedger` struct carries a `processed_signatures: BTreeSet<String>`
field. During ingestion, each transaction's signature is saved to the ledger
immediately after processing. On the next run, already-processed signatures
are filtered out before fetching begins. A wallet with 12,000 transactions
that crashes at #7,231 resumes from #7,232, not from zero. This is essential
for high-volume DeFi wallets where a full re-ingest would take hours.

**Multi-Wallet Isolation**

`MultiWalletLedger` (`lots.rs`) holds a `BTreeMap<String, TaxLedger>`, keyed
by wallet public key. Each wallet's ledger is stored in a separate file
(`.selo_ledger_<pubkey>.json`). The `cumulative_ledger()` method merges all
wallet lots into a combined view for aggregate reporting.

### Deterministic Daily Closes and Merkle Commitments

The daily close (`close.rs`) turns a 24-hour trading window into a
byte-identical, checkable record.

**Domain Separation**

Every daily close begins with the domain tag `selo-close-v1`, which appears in
the header line, the anchor memo, and every leaf hash. Any change to field
order, separators, or hashing must change this tag, so two schemes cannot
produce interchangeable-looking numbers.

**Field Element Hashing (SHA-256)**

Leaves and the day header are hashed into BN254 field elements using SHA-256
with the first byte zeroed:

```rust
pub fn field_element(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out[0] = 0;
    out
}
```

The first byte is zeroed to keep the value inside the BN254 scalar field.

**Merkle Tree Folding (Poseidon over BN254)**

The field elements are then folded into a Merkle root using Poseidon hashing
over the BN254 scalar field with circom-compatible parameters
(`light-poseidon` crate, `new_circom(2)`). Poseidon is used here rather than
SHA-256 because it is efficient inside zk-SNARK circuits; a SHA-256 digest
inside a BN254 circuit would be ruinously expensive. The tree is balanced by
padding with an `empty_leaf()` when the leaf count is odd.

**The Commitment**

The final commitment is:

```
commitment = Poseidon(merkle_root, header_field_element)
```

This two-level construction -- leaves hashed with SHA-256 into field elements,
then folded with Poseidon -- separates domain concerns: SHA-256 provides
collision resistance for arbitrary input data, while Poseidon enables
efficient circuit proving of the tree structure.

**Canonical Record Format**

Lines are sorted deterministically by `(signature, sales_point, order_counter,
sku, quantity, unit_price, amount, mint)`. The canonical record is a
tab-separated text file: one header line, one line per sale, trailing newline.
Closing the same day twice with the same input produces byte-identical output.

**The Identity Shield**

Before any transaction line is hashed into the Merkle tree, the SKU identifier
is inspected by `reject_identity_shaped`. If a SKU contains an `@` symbol or a
run of 7 or more consecutive digits, the close immediately aborts. This
protects customer privacy on the public Solana indexer.

**Anchor Transaction Preparation**

`prepare_anchor` builds an unsigned transaction carrying a single SPL Memo
instruction. The memo text is the anchor memo string:

```
selo-close-v1 <merchant> <day_start> <day_end> <line_count> <commitment_base58>
```

The memo program ID is `MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`. The
transaction is unsigned by design: a human must sign and broadcast it. Once
broadcast, the Poseidon commitment is permanently etched into Solana's ledger
history via the SPL Memo Program.

### Durable-Nonce Anchor Transactions

The `nonce.rs` module provides the building blocks for durable-nonce
transactions. Instead of referencing a recent blockhash that expires within
150 blocks (about 60 seconds), a durable-nonce transaction replaces the
blockhash with the hash stored inside an on-chain Nonce Account. The
transaction uses an `AdvanceNonceAccount` instruction as its first
instruction, consuming the stored nonce hash and atomically generating a new
valid blockhash. This ensures that unsigned anchor payloads can be stored,
reviewed by compliance officers, and signed later without ever failing due to
an expired blockhash.

`prepare_anchor` in `close.rs` accepts an optional `&NonceState` parameter.
When provided, the function decodes the nonce account and authority addresses,
builds an `AdvanceNonceAccount` instruction (system program discriminant 4)
referencing the nonce account, the recent blockhashes sysvar, and the nonce
authority, and prepends it to the instruction list. The nonce account's stored
nonce value replaces the recent blockhash in the compiled message. The
`PreparedAnchor` struct carries a `durable_nonce_account: Option<String>` field
so callers can distinguish a nonce-backed anchor from a regular one. When no
nonce is provided, the function falls back to the regular blockhash path.

### Payment Intent and Settlement

Selo bridges point-of-sale invoicing and on-chain settlement via Solana Pay
and reference key matching.

**Solana Pay URIs and Single-Use Reference Keys**

Payment intents are generated as standard protocol URIs:

```
solana:<recipient>?amount=<sol>&reference=<ref_pubkey>&label=<encoded>&message=<encoded>
```

Every quote embeds a unique, single-use Base58 reference public key. Because
Solana runtimes index all account keys in a transaction, merchants can query
`getSignaturesForAddress(reference_pubkey)` to achieve keyless on-chain
settlement reconciliation without exposing hot private keys online.

**Amount Tagging**

Each quote carries a 4-digit tag embedded in the least significant digits of
the payment amount. The tag encodes the sales point ID and an order counter,
so the settlement amount itself identifies which order was paid without
needing a separate memo or lookup. The tag value is computed as:

```
tagged_amount = (unit_price * quantity) + tag_value
```

where `tag_value = sales_point * 100 + order_counter`. This survives rounding
and is decoded by matching the last digits of the settled amount against the
tag.

**Settlement Confirmation**

`selo-tool confirm` scans pending quotes, queries
`getSignaturesForAddress(reference_pubkey)` for each, and marks settled quotes
with the transaction signature. It runs autonomously (designed for cron-driven
reconciliation every 60 seconds) and pushes settlement alerts when a payment
lands on chain.

### Zero-Knowledge Compressed Account Support

The `zk.rs` module integrates with Light Protocol's Photon indexer for
compressed token accounts on Solana. It builds and parses requests for
`getCompressedAccountsByOwner`, `getCompressedTokenBalancesByOwnerV2`, and
`getCompressedAccountProof`, and verifies Merkle proofs by recomputing the
root from the leaf and proof path.

The verification uses the same Poseidon-over-BN254 hasher as the close module,
with sibling ordering matching Light Protocol's convention:

```
is_left = (leaf_index >> level) & 1 == 0
```

If the recomputed root matches the indexer's reported root, the balance is
cryptographically backed rather than merely asserted. If it does not match,
the error names both roots so the auditor can distinguish between a lying
indexer and a stale one.

### HTML Audit Report Export

The `generate_html_report` function in `format.rs` produces a standalone HTML
file with embedded CSS and no external dependencies. The report supports:

- **Per-wallet filtering**: `--wallet <pubkey>` loads and renders only that
  wallet's ledger.
- **Date range scoping**: `--from` and `--to` filter lots to a specific
  period, for monthly or quarterly reports.
- **Fiscal year grouping**: lots are grouped by year and month in an
  accordion-stack layout.
- **Design tokens**: CSS custom properties (`--selo-ink`, `--selo-paper`,
  `--selo-muted`, `--selo-rule`, `--wax`) with light and dark mode via
  `prefers-color-scheme`.
- **Sealed indicator**: the sealing wax red (`--wax: #B4381F`) is reserved
  for closed periods. Open periods render in muted tones.

The report carries an embedded integrity verification system. At generation
time, all lot records are serialized to a canonical JSON array (sorted by lot
ID), and a SHA-256 hash of that JSON is computed and embedded alongside the
data in a `<script type="application/json">` tag. On page load, a JavaScript
routine reads the embedded lot data, recomputes SHA-256 via the Web Crypto API
(`window.crypto.subtle.digest('SHA-256', ...)`), and compares the result against
the recorded hash. A green VERIFIED badge appears if they match; a red TAMPERED
badge appears if they differ, with both the computed and claimed hash prefixes
shown for manual inspection. The Poseidon BN254 state root is also displayed in
the report footer for on-chain anchoring reference; full Poseidon re-derivation
remains available offline via `selo-tool verify --root <hash>`.

### ZeroClaw and Adapter Integration

Selo integrates with ZeroClaw as a skill, not a plugin. The skill definition
in `skills/selo/SKILL.toml` exposes subcommands (issue, confirm, check, close,
ingest, verify) that ZeroClaw dispatches to the stock selo-tool release
binary.

Channel adapters live in `adapters/`:
- **Telegram**: a Python long-polling bot that serves as the primary
  operational interface, with a button menu and click-through wizard for
  non-technical operators, built-in cron scheduling for the daily close and
  periodic reconciliation, SOP-driven guided workflows, and a settlement
  watcher that pushes real-time alerts. The adapter owns the Telegram bot
  token and renders the button GUI itself, so the interface works without any
  LLM. Free-form text that is not a selo command is forwarded to the ZeroClaw
  gateway webhook (`POST /webhook?agent=selo`) and the agent's reply is sent
  back to the chat. The ZeroClaw daemon's own Telegram channel is disabled so
  both sides do not compete for the same token.
- **WhatsApp**: routed through ZeroClaw's webhook server (requires Meta Cloud
  API and a public webhook URL).

The adapter owns scheduling and the Telegram token; ZeroClaw provides the
LLM forwarding surface via its gateway webhook and the WhatsApp webhook
surface. See `adapters/README.md` for the full setup and runbook.
