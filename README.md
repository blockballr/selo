# SELO

---

##  Core Architectural Philosophy

1. **Strict Dependency Inversion:** Pure business logic and state transitions live exclusively inside `selo-core` with **zero network or I/O dependencies**. Network transport, storage drivers, and CLI interaction reside strictly in `selo-tool`.
2. **Dual Ingestion Pathways:** Selo handles both **Pathway A (Intent-driven / Solana Pay quotes)** and **Pathway B (Direct / Unstructured blockchain transfers)** as first-class citizens.

---

##  System Architecture Schematics

###  Crate & Dependency Inversion Schematic

```text
+-------------------------------------------------------------------------+
|                               selo-tool                                 |
|               (CLI Binary, ureq Transport, store_io.rs)                 |
+------------------------------------+------------------------------------+
                                     |
                                     | Implements RpcSeam (Live I/O)
                                     v
+-------------------------------------------------------------------------+
|                               selo-core                                 |
|            (Pure Business Logic, State Machine, Tax Lots)               |
+------------------------------------+------------------------------------+
                                     |
                                     | Offline Verification
                                     v
                        +--------------------------+
                        |     MockRpc Harness      |
                        |       (lib.rs)           |
                        +--------------------------+
```
---

##  Master Roadmap & Phases

The development of Selo is structured into **4 Master Phases**:

```text
 ┌───────────────┐      ┌───────────────────┐      ┌──────────────────┐      ┌───────────────┐
 │ Phase 1: Poda │ ───► │ Phase 2: Alicerce │ ───► │Phase 3: Virgilia │ ───► │ Phase 4: Selo │
 └───────────────┘      └───────────────────┘      └──────────────────┘      └───────────────┘
```

- [x] **Phase 1: Poda** — Repository pruning, workspace cleanup, and strict crate separation (`selo-core` vs. `selo-tool`).
- [x] **Phase 2: Alicerce** *(Milestone Tagged: `alicerce-phase`)* — Foundational infrastructure & persistence:
  - **Stage 1:** Workspace architecture & crate split.
  - **Stage 2:** `RpcSeam` trait abstraction & `MockRpc` offline harness.
  - **Stage 3:** Live network RPC transport implementation via `ureq`.
  - **Stage 4:** Basic CLI command dispatching.
  - **Stage 5:** Local state persistence (`.selo_store.json`), `issue`, and `check` CLI routing.
- [ ] **Phase 3: Virgilia** *(Active Phase)* — Payment intent & automated reconciliation:
- [ ] **Phase 4: Selo** 

---

##  Developer Quickstart & CLI Guide

### 1. Execute Offline Workspace Tests
Run all unit and integration tests using the offline `MockRpc` harness:

```powershell
cargo test --workspace
```

### 2. Create a Payment Quote (`selo-tool`)
Issue a new payment record locally:

```powershell
cargo run -p selo-tool -- issue --amount 500000000 --recipient <SOL_PUBKEY> --label "Invoice #001"
```

### 3. Inspect Persistence Store
Check active quotes stored in `.selo_store.json`:

```powershell
cargo run -p selo-tool -- check
```

### 4. Fetch Network State via Live RPC
Query live cluster data:

```powershell
# Fetch balance for a wallet:
cargo run -p selo-tool -- balance --pubkey <SOL_PUBKEY>

# Fetch current cluster blockhash:
cargo run -p selo-tool -- blockhash
```

---

##  License

Dual-licensed under Apache 2.0 / MIT.
