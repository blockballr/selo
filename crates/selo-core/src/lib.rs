//! Selo's core the money path, as pure Solana logic with no I/O
//!
//! The central accounting logic engine.
//! designed to be transport-agnostic
//!
//! Everything here is I/O-free by design. An `RpcSeam` trait is used to
//! define our network requirements, allowing the implementation to be
//! swapped out for testing

pub trait RpcSeam {
    fn get_balance(&self, address: &str) -> Result<u64, String>;
    fn get_latest_blockhash(&self) -> Result<String, String>;
    fn get_signatures(&self, address: &str) -> Result<Vec<String>, String>;
    fn get_transaction(&self, sig: &str) -> Result<serde_json::Value, String>;
}

pub mod address;
pub mod airdrop;
pub mod basis;
pub mod brain;
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
