//! Selo's core: the money path, as pure Solana logic with no I/O in it.
//!
//! Everything here is I/O-free by design: request builders return JSON
//! strings, response parsers take JSON strings, and the transfer module
//! turns inputs into signed transaction bytes without touching the
//! network. Whichever surface calls this crate owns the HTTP call and
//! nothing else, so all behavior is provable with plain `cargo test` on
//! the host, with no live network in any test.
//!
//! Today the only caller is the wasm32-wasip2 component in this
//! workspace, but nothing here may assume how it is being called.

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
