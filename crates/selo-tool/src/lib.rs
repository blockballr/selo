//! Native command-line accounting tool: `selo-tool`.
//!
//! This crate holds the CLI defined in `main.rs`: a native Rust binary that
//! drives the accounting engine. It owns all network transport (Solana
//! JSON-RPC via ureq, PTAX and SOL price feeds), local disk persistence, and
//! monochrome split-seal report rendering. The pure business logic lives in
//! `selo-core`; this crate is the hands that move it.
