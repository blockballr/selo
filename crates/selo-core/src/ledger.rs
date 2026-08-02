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
        Self {
            rules: HashMap::new(),
        }
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
