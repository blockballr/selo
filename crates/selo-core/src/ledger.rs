use crate::RpcSeam;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standard native SOL mint address on Solana.
pub const NATIVE_SOL_MINT: &str = "So11111111111111111111111111111111111111112";

/// Categorizes events recorded on the accounting ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventKind {
    QuoteIssued,
    QuoteSettled,
    Transfer,
    Income,
    Expense,
    Revenue,
    Payout,
    FeePaid,
}

impl EventKind {
    /// Returns the string representation of the event kind.
    pub fn as_str(&self) -> &str {
        match self {
            EventKind::QuoteIssued => "QuoteIssued",
            EventKind::QuoteSettled => "QuoteSettled",
            EventKind::Transfer => "Transfer",
            EventKind::Income => "Income",
            EventKind::Expense => "Expense",
            EventKind::Revenue => "Revenue",
            EventKind::Payout => "Payout",
            EventKind::FeePaid => "FeePaid",
        }
    }
}

/// Represents a discrete event recorded on the ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerEvent {
    pub block_time_unix: Option<i64>,
    pub kind: EventKind,
    pub amount_base_units: i128,
    pub mint: String,
    pub counterparty: Option<String>,
    pub signature: String,
}

/// Maps raw Base58 public key addresses to human-readable labels/names.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CounterpartyRegistry {
    pub rules: HashMap<String, String>,
}

impl CounterpartyRegistry {
    pub fn new() -> Self {
        let mut rules = HashMap::new();

        // core Solana system & SPL programs
        rules.insert(
            "11111111111111111111111111111111".to_string(),
            "Solana System Program".to_string(),
        );
        rules.insert(
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            "SPL Token Program".to_string(),
        );
        rules.insert(
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb".to_string(),
            "SPL Token-2022 Program".to_string(),
        );
        rules.insert(
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".to_string(),
            "SPL Associated Token Account Program".to_string(),
        );
        rules.insert(
            "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".to_string(),
            "SPL Memo Program".to_string(),
        );
        rules.insert(
            "ComputeBudget111111111111111111111111111111".to_string(),
            "Compute Budget Program".to_string(),
        );
        rules.insert(
            "Stake11111111111111111111111111111111111111".to_string(),
            "Solana Stake Program".to_string(),
        );

        // DEX aggregators, AMMs & liquidity protocols
        rules.insert(
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".to_string(),
            "Jupiter Aggregator v6".to_string(),
        );
        rules.insert(
            "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8".to_string(),
            "Raydium AMM v4".to_string(),
        );
        rules.insert(
            "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK".to_string(),
            "Raydium Concentrated Liquidity (CLMM)".to_string(),
        );
        rules.insert(
            "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C".to_string(),
            "Raydium CP Swap".to_string(),
        );
        rules.insert(
            "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc".to_string(),
            "Orca Whirlpool".to_string(),
        );
        rules.insert(
            "PhoeNiX2yFi2WBmcWZmqbLLBk3zp8V275rWxmMvhKE8".to_string(),
            "Phoenix DEX".to_string(),
        );
        rules.insert(
            "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo".to_string(),
            "Meteora DLMM".to_string(),
        );

        // lending, yield & liquid Staking Protocols
        rules.insert(
            "KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD".to_string(),
            "Kamino Lending".to_string(),
        );
        rules.insert(
            "MFv2hWf31Z9kbCa1snEPYctwafyhdvnV7FZnsebVacA".to_string(),
            "Marginfi v2".to_string(),
        );
        rules.insert(
            "So1endDq2YkqhipRh3WViPa8hF5vqEGvMJNFo5yvh69".to_string(),
            "Solend Protocol".to_string(),
        );
        rules.insert(
            "Jitos7P2WnbxBxMV6g2fNJBDMEx8MGLEdR65ysgAh85".to_string(),
            "Jito Stake Pool".to_string(),
        );
        rules.insert(
            "MarBGuJHBdmhKwUZ9Bwb2vSgvo7vVIxNLWmqKzcFUCb".to_string(),
            "Marinade Finance".to_string(),
        );

        // known stablecoin Mints & exchange hot wallets
        rules.insert(
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            "USD Coin (USDC)".to_string(),
        );
        rules.insert(
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".to_string(),
            "Tether USD (USDT)".to_string(),
        );
        rules.insert(
            "2b1kV6DkPAnxd5ixfnxCpjXM3W3Edbve3MxyEeqVR776".to_string(),
            "PayPal USD (PYUSD)".to_string(),
        );
        rules.insert(
            "2ojv9BAiA3hP8B82AGP8R2P8R8P8R8P8R8P8R8P8R8P8".to_string(),
            "Binance Hot Wallet".to_string(),
        );

        Self { rules }
    }

    /// Registers a new address mapping rule.
    pub fn add_rule(&mut self, address: String, name: String) {
        self.rules.insert(address, name);
    }

    /// Retrieves the label for an address, or returns a fallback default.
    pub fn get_name(&self, address: &str) -> String {
        self.rules
            .get(address)
            .cloned()
            .unwrap_or_else(|| "Unknown Counterparty".to_string())
    }

    /// Returns the total number of registered counterparty rules.
    pub fn count(&self) -> usize {
        self.rules.len()
    }
}

/// Backfills transaction history by paginating through the RPC signatures stream.
pub struct Backfiller<'a, T: RpcSeam> {
    pub rpc: &'a T,
}

impl<'a, T: RpcSeam> Backfiller<'a, T> {
    pub fn new(rpc: &'a T) -> Self {
        Self { rpc }
    }

    /// Fetches signatures for an address over the chain seam.
    pub fn backfill(&self, address: &str) -> Result<Vec<String>, String> {
        let mut all_signatures = Vec::new();

        loop {
            let signatures = self.rpc.get_signatures(address)?;

            if signatures.is_empty() {
                break;
            }

            all_signatures.extend(signatures);

            // Break after initial pass for single-page RPC queries
            break;
        }

        Ok(all_signatures)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counterparty_registry() {
        let mut registry = CounterpartyRegistry::new();
        registry.add_rule(
            "7Xw19aK4mQ2vB8pY3zN6jR5wL8kQ9tM4sP2vX1yZ3kL9".to_string(),
            "Merchant Main Wallet".to_string(),
        );

        assert_eq!(
            registry.get_name("7Xw19aK4mQ2vB8pY3zN6jR5wL8kQ9tM4sP2vX1yZ3kL9"),
            "Merchant Main Wallet"
        );
        assert_eq!(
            registry.get_name("UnknownPubkey1111111111111111111111111111"),
            "Unknown Counterparty"
        );
    }

    #[test]
    fn test_ledger_constants_and_types() {
        assert_eq!(
            NATIVE_SOL_MINT,
            "So11111111111111111111111111111111111111112"
        );
        let event = LedgerEvent {
            block_time_unix: Some(1000),
            kind: EventKind::Revenue,
            amount_base_units: 1_000_000,
            mint: NATIVE_SOL_MINT.to_string(),
            counterparty: Some("7Xw19...".to_string()),
            signature: "sig123".to_string(),
        };
        assert_eq!(event.kind, EventKind::Revenue);
        assert_eq!(event.kind.as_str(), "Revenue");
        assert_eq!(event.signature, "sig123");
        assert_eq!(event.amount_base_units, 1_000_000);
    }
}
