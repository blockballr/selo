# SELO · Accounting Engine

Selo is a pure-Rust, transport-agnostic accounting engine designed for the Solana ecosystem. It provides the "Brain" (core logic) for reconciling transactions and managing stablecoin accounting, independent of the underlying network transport.

---

## Core Architectural Philosophy

1. **Strict Dependency Inversion:** Pure business logic and state transitions live exclusively inside `selo-core` with **zero network or I/O dependencies**. Network transport, storage drivers, and CLI interaction reside strictly in `selo-tool`.
2. **Brain & Hands Pattern:** The "Brain" (`selo-core`) processes identification, and categorization. The "Hands" (`selo-tool`) handle the network I/O, local disk persistence, and UI rendering.

---

## System Architecture Schematic

```text
+-------------------------------------------------------------------------+
|                                selo-tool                                |
|             (CLI Binary, Ureq RPC Transport, Local Stores)              |
+------------------------------------+------------------------------------+
                                     |
                                     | Implements RpcSeam (Live I/O)
                                     v
+-------------------------------------------------------------------------+
|                                selo-core                                |
|                   (Pure Business Logic, State Machine)              |
+------------------------------------+------------------------------------+
```

---

## Master Roadmap & Phases

The development of Selo is structured into **4 Master Phases**:

```text
 ┌───────────────┐      ┌───────────────────┐      ┌──────────────────┐      ┌───────────────┐
 │ Phase 1: Poda │ ───► │ Phase 2: Alicerce │ ───► │Phase 3: Virgilia │ ───► │ Phase 4: Selo │
 └───────────────┘      └───────────────────┘      └──────────────────┘      └───────────────┘
```

---

- [x] **Phase 1: Poda** (Stages 1-3) *(Milestone Tagged: `poda-phase`)* — Workspace cleanup & crate separation

- [x] **Phase 2: Alicerce** (Stages 4-5) *(Milestone Tagged: `alicerce-phase`)* — Foundational infrastructure & persistence (.selo_store.json)

- [ ] **Phase 3: Virgilia** (Stages 6-9) *(Active Phase)* — Ledger Intelligence & Actuation:

- **Stage 6:** Solana Pay URIs & PDA derivation

- **Stage 7:** Automated on-chain reconciliation engine

- **Stage 8:** Categorization engine & counterparty auto-labeling

- **Stage 9:** Durable Nonce Anchoring, Quote Closing & Refund Logic.

- [ ] **Phase 4: Selo**

---

## Developer Quickstart & CLI Guide

### 1. Execute Offline Workspace Tests

Run all unit and integration tests using the offline `MockRpc` harness:

```powershell
cargo test --workspace
```

### 2. Payment Intent & Reconciliation


```powershell
# Issue a payment intent:
cargo run -p selo-tool -- issue --amount 500000000 --recipient <PUBKEY> --label "Invoice #001"

# Scan cluster for settlements:
cargo run -p selo-tool -- confirm
```

### 3. Inspect Persistence Store

Check active quotes stored in `.selo_store.json`:

```powershell
cargo run -p selo-tool -- check
```

### Ledger Intelligence (Ingestion & Labeling)

```powershell
# Add a counterparty rule:
cargo run -p selo-tool -- rules --add <PUBKEY> --name "Jupiter Aggregator"

# Ingest and classify wallet history:
cargo run -p selo-tool -- ingest <PUBKEY>
```

### 5. Fetch Network State via Live RPC

Query live cluster data:

```powershell
# Fetch balance for a wallet:
cargo run -p selo-tool -- balance --pubkey <SOL_PUBKEY>

# Fetch current cluster blockhash:
cargo run -p selo-tool -- blockhash
```

---

## License

Dual-licensed under Apache 2.0 / MIT.
