pub mod address;
pub mod basis;
pub mod catalog;
pub mod close;
pub mod config;
pub mod format;
pub mod jupiter;
pub mod ledger;
pub mod lots;
pub mod message;
pub mod nonce;
pub mod pda;
pub mod priority;
pub mod ptax;
pub mod quote;
pub mod quotelog;
pub mod refund;
pub mod rpc;
pub mod settle;
pub mod simulate;
pub mod solana_pay;
pub mod store;
pub mod token;
pub mod transfer;
pub mod tx;
pub mod vtx;
pub mod x402;
pub mod zk;
use serde_json::Value;

/// the interface for blockchain data access.
/// this allows the core logic to remain pure and I/O-free.
pub trait RpcSeam {
    fn get_balance(&self, address: &str) -> Result<u64, String>;
    fn get_latest_blockhash(&self) -> Result<String, String>;

    fn get_signatures(&self, address: &str) -> Result<Vec<String>, String> {
        self.get_signatures_paginated(address, None, 25)
    }

    fn get_signatures_paginated(
        &self,
        address: &str,
        _before: Option<&str>,
        _limit: usize,
    ) -> Result<Vec<String>, String> {
        self.get_signatures(address)
    }

    fn get_transaction(&self, sig: &str) -> Result<Value, String>;

    /// Fetch a raw account, returned as the JSON-RPC `result` value. Used
    /// by the durable-nonce anchor path to read a nonce account's stored
    /// state. Defaults to an error so transports that never need it stay
    /// tiny; the real HTTP transport overrides it.
    fn get_account_info(&self, _address: &str) -> Result<Value, String> {
        Err("this transport does not implement get_account_info".to_string())
    }
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
    #[allow(dead_code)]
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

    #[cfg(test)]
    mod tests {
        use super::*;

        struct MockRpc;

        impl RpcSeam for MockRpc {
            fn get_balance(&self, _address: &str) -> Result<u64, String> {
                Ok(1_500_000_000)
            }

            fn get_latest_blockhash(&self) -> Result<String, String> {
                Ok("MockBlockhash1111111111111111111111111111".to_string())
            }

            fn get_transaction(&self, _sig: &str) -> Result<Value, String> {
                Ok(serde_json::json!({}))
            }
        }

        #[test]
        fn test_accounting_engine_rpc_seam() {
            let engine = AccountingEngine::new(MockRpc);
            let balance = engine
                .rpc
                .get_balance("7Xw19aK4mQ2vB8pY3zN6jR5wL8kQ9tM4sP2vX1yZ3kL9")
                .unwrap();
            assert_eq!(balance, 1_500_000_000);

            let blockhash = engine.rpc.get_latest_blockhash().unwrap();
            assert!(blockhash.contains("MockBlockhash"));
        }
    }
}
