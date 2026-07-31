//! Selo's core: the money path, as pure Solana logic with no I/O in it.
//!
//! Everything here is I/O-free by design. An `RpcSeam` trait is used to
//! define our network requirements, allowing the implementation to be
//! swapped out for testing.

pub mod address;
pub mod airdrop;
pub mod basis;
pub mod catalog;
// pub mod close;
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
// pub mod zk;
