//! Selo's core the money path, as pure Solana logic with no I/O
//!
//! The central accounting logic engine.
//! designed to be transport-agnostic
//!
//! Everything here is I/O-free by design. An `RpcSeam` trait is used to
//! define our network requirements, allowing the implementation to be
//! swapped out for testing

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
pub mod nonce;
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
pub mod solana_pay;
pub mod store;

pub use brain::*;
pub use store::*;

use serde_json::Value;

/// the interface for blockchain data access.
/// this allows the core logic to remain pure and I/O-free.
pub trait RpcSeam {
    fn get_balance(&self, address: &str) -> Result<u64, String>;
    fn get_latest_blockhash(&self) -> Result<String, String>;
    fn get_signatures(&self, address: &str) -> Result<Vec<String>, String>;
    fn get_transaction(&self, sig: &str) -> Result<Value, String>;
}

/// the main entry point container pairing the engine logic with an RPC transport.
pub struct AccountingEngine<T: RpcSeam> {
    pub rpc: T,
}

impl<T: RpcSeam> AccountingEngine<T> {
    pub fn new(rpc: T) -> Self {
        Self { rpc }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// mock RPC implementation for pure offline testing of the RpcSeam trait
    struct MockRpc;

    impl RpcSeam for MockRpc {
        fn get_balance(&self, address: &str) -> Result<u64, String> {
            if address == "test_addr" {
                Ok(1_000_000)
            } else {
                Err("Account not found".to_string())
            }
        }

        fn get_latest_blockhash(&self) -> Result<String, String> {
            Ok("4vJ9ju1bJJE96FWSXTmyv2C33f119x318NqA41A7JmyS".to_string())
        }

        fn get_signatures(&self, _address: &str) -> Result<Vec<String>, String> {
            Ok(vec!["sig123".to_string()])
        }

        fn get_transaction(&self, _sig: &str) -> Result<serde_json::Value, String> {
            Ok(json!({"slot": 12345}))
        }
    }

    #[test]
    fn test_accounting_engine_with_mock_rpc() {
        let engine = AccountingEngine::new(MockRpc);

        let balance = engine.rpc.get_balance("test_addr").unwrap();
        assert_eq!(balance, 1_000_000);

        let hash = engine.rpc.get_latest_blockhash().unwrap();
        assert_eq!(hash, "4vJ9ju1bJJE96FWSXTmyv2C33f119x318NqA41A7JmyS");
    }

    #[test]
    fn test_quote_action_via_engine() {
        let engine = AccountingEngine::new(MockRpc);
        let args = brain::QuoteArgs {
            sku: "SKU-SOL-100".to_string(),
            quantity: 5,
            now_unix: 1700000000,
        };

        let result = brain::action_quote(&engine.rpc, &args).unwrap();
        assert!(result.contains("SKU-SOL-100"));
    }
}
