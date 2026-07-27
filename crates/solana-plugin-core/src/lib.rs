//! Pure Solana JSON-RPC logic for the ZeroClaw plugin suite.
//!
//! Everything here is I/O-free by design: request builders return JSON
//! strings, response parsers take JSON strings, and the transfer module
//! turns inputs into signed transaction bytes without touching the
//! network. The WASM component glue in each plugin crate owns the HTTP
//! call and nothing else, so all behavior is provable with plain
//! `cargo test` on the host.

pub mod address;
pub mod airdrop;
pub mod basis;
pub mod catalog;
pub mod close;
pub mod config;
pub mod format;
pub mod jupiter;
pub mod ledger;
pub mod message;
pub mod pda;
pub mod priority;
pub mod quote;
pub mod quotelog;
pub mod refund;
pub mod rpc;
pub mod settle;
pub mod simulate;
pub mod token;
pub mod transfer;
pub mod tx;
pub mod vtx;
pub mod x402;
pub mod zk;
