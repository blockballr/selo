## SELO · Pure-Rust Cryptographic Accounting & ZK Audit Engine

 Selo is a pure-Rust, transport-agnostic cryptographic accounting engine built specifically for stablecoin income reporting, multi-wallet FIFO tax lot tracking, air-gapped auditor verification, and deterministic daily closes on Solana.

## Core Architectural Philosophy

Strict Dependency Inversion: Pure business logic, tax lot state machines, and ZK commitment math live exclusively inside selo-core with zero network or I/O dependencies. Network transport, storage drivers, and CLI interaction reside strictly in selo-tool.

Brain & Hands Pattern: The "Brain" (selo-core) processes identification, DLMM net-deltas, PTAX fiat valuations, and Poseidon Merkle trees. The "Hands" (selo-tool) handle Solana JSON-RPC I/O via ureq, local disk persistence, and monochrome split-seal report rendering.


## System Architecture Schematic

```powershell
+-------------------------------------------------------------------------+
|                                selo-tool                                |
|             (CLI Binary, Ureq RPC Transport, Local Stores)              |
+------------------------------------+------------------------------------+
                                     |
                                     | Implements RpcSeam (Live I/O)
                                     v
+-------------------------------------------------------------------------+
|                                selo-core                                |
|             (Pure Business Logic, FIFO Tax Lots, Poseidon ZK)           |
+------------------------------------+------------------------------------+
```

---

## Master Roadmap & Phases

- [x] **Phase 1: Poda (Stages 1-3)** — Workspace cleanup & crate separation (selo-core & selo-tool)

- [x] **Phase 2: Alicerce (Stages 4-5)** — Foundational RPC infrastructure (RpcSeam & ureq) & persistence

- [x] **Phase 3: Virgilia (Stages 6-9)** — Ledger Intelligence, Solana Pay URIs, PDA derivation, and counterparty auto-labeling

- [x] **Phase 4: Selo (Stages 10-12)** — Deterministic Daily Closes, Poseidon BN254 Commitments, Identity Shield, and Self-Verifying HTML Audit Reports
  
---

## Developer Quickstart & CLI Command Reference

### 1. Execute Offline Workspace Tests

```powershell
# Run all unit and integration tests across the workspace:

cargo test --workspace
```

### 2. Query Account Balance & Counterparty Resolution

Selo supports human-readable counterparty names across all wallet inputs:

```powershell
# Query balance using a registered counterparty name or pubkey

cargo run -p selo-tool -- balance "Relayer"
```

### 3. Payment Intent & On-Chain Reconciliation

```powershell
# Issue a payment intent quote with single-use reference key:

cargo run -p selo-tool -- issue --amount 500000000 --recipient <PUBKEY> --label "Design Work"
```

### Scan cluster for settlements matching stored reference keys:

```powershell
cargo run -p selo-tool -- confirm
```

### 4. Ledger Intelligence (Ingestion & Counterparty Review)

```powershell
# Manage counterparty mapping rules:
cargo run -p selo-tool -- rules --add <PUBKEY> --name "Client Escrow"
```

### Ingest transaction history and record tax lots:

```powershell
cargo run -p selo-tool -- ingest <PUBKEY> --all
```

###  Surface unclassified counterparty addresses needing review:

```powershell
cargo run -p selo-tool -- review <PUBKEY>
```

### 5. Deterministic Daily Close & ZK Commitment

```powershell
# Build a byte-identical daily trading close with Poseidon Merkle commitment:

cargo run -p selo-tool -- close --merchant <MERCHANT_PUBKEY> --start 1750000000 --end 1750086400 --output daily_audit.txt
```

### 6. Standalone HTML Audit Report Export & Verification

```powershell
# Export self-verifying standalone HTML audit report:

cargo run -p selo-tool -- export-html --year 2026 --output audit_statement.html
```

### Verify local tax ledger against cryptographic Poseidon BN254 root:

```powershell
cargo run -p selo-tool -- verify --root 0x09be3021160dce395ebe3617c382a8adba...
```

### License

Dual-licensed under Apache 2.0 / MIT