use crate::RpcSeam;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Standard native SOL mint address on Solana.
pub const NATIVE_SOL_MINT: &str = "So11111111111111111111111111111111111111112";

/// Categorizes events recorded on the accounting ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerEvent {
    pub block_time_unix: Option<i64>,
    pub kind: EventKind,
    pub amount_base_units: i128,
    pub mint: String,
    pub counterparty: Option<String>,
    pub counterparty_address: Option<String>,
    pub signature: String,
    pub is_classified: bool,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub fn get_name_or_address(&self, pubkey: &str) -> String {
        self.rules.get(pubkey).cloned().unwrap_or_else(|| {
            // DEBUG: calc safe slice length (min of address length or 8)
            let len = std::cmp::min(pubkey.len(), 8);
            format!("{}...", &pubkey[..len])
        })
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

pub fn parse_transaction_events(
    signature: &str,
    tx_data: &Value,
    target_wallet: &str,
    registry: &CounterpartyRegistry,
) -> Vec<LedgerEvent> {
    let mut events = Vec::new();

    let block_time = tx_data.get("blockTime").and_then(|v| v.as_i64());
    let transaction = match tx_data.get("transaction") {
        Some(tx) => tx,
        None => return events,
    };

    let message = match transaction.get("message") {
        Some(msg) => msg,
        None => return events,
    };

    let account_keys: Vec<String> = message
        .get("accountKeys")
        .and_then(|keys| keys.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|k| {
                    if let Some(s) = k.as_str() {
                        Some(s.to_string())
                    } else if let Some(obj) = k.as_object() {
                        obj.get("pubkey")
                            .and_then(|p| p.as_str())
                            .map(|s| s.to_string())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let wallet_idx = match account_keys.iter().position(|k| k == target_wallet) {
        Some(idx) => idx,
        None => return events,
    };

    let mut primary_counterparty_address = None;
    let mut primary_counterparty_label = None;
    let mut is_classified = false;

    // skip infrastructure keys if better label exists
    let skip_keys = vec![
        "11111111111111111111111111111111",             // system program
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  // token program
        "ComputeBudget111111111111111111111111111111",  // compute budget
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", // AToken
    ];

    // first pass: find business-logic program (Meteora, Jupiter, etc.)
    for key in &account_keys {
        if key != target_wallet && !skip_keys.contains(&key.as_str()) {
            let label = registry.get_name(key);
            if label != "Unknown Counterparty" {
                primary_counterparty_address = Some(key.clone());
                primary_counterparty_label = Some(label);
                is_classified = true;
                break;
            }
        }
    }

    // second pass: If none, fall back to generic
    if !is_classified {
        for key in &account_keys {
            if key == "11111111111111111111111111111111" {
                continue;
            }

            if key != target_wallet {
                let label = registry.get_name_or_address(key);
                if label != "Unknown Counterparty" {
                    primary_counterparty_address = Some(key.clone());
                    primary_counterparty_label = Some(label);
                    is_classified = true;
                    break;
                }
            }
        }
    }

    if primary_counterparty_label.is_none() {
        if let Some(ref addr) = primary_counterparty_address {
            let label = registry.get_name(addr);
            if label != "Unknown Counterparty" {
                is_classified = true;
            }
            primary_counterparty_label = Some(label);
        }
    }

    let meta = match tx_data.get("meta") {
        Some(m) => m,
        None => return events,
    };

    if let (Some(pre_balances), Some(post_balances)) = (
        meta.get("preBalances").and_then(|v| v.as_array()),
        meta.get("postBalances").and_then(|v| v.as_array()),
    ) {
        if let (Some(pre), Some(post)) = (
            pre_balances.get(wallet_idx).and_then(|v| v.as_i64()),
            post_balances.get(wallet_idx).and_then(|v| v.as_i64()),
        ) {
            let delta = post as i128 - pre as i128;
            let fee = if wallet_idx == 0 {
                meta.get("fee").and_then(|v| v.as_i64()).unwrap_or(0) as i128
            } else {
                0
            };

            let net_delta = delta + fee;

            if net_delta.abs() > 1000 {
                let kind = if net_delta > 0 {
                    if is_classified {
                        EventKind::Income
                    } else {
                        EventKind::Transfer
                    }
                } else {
                    if is_classified {
                        EventKind::Expense
                    } else {
                        EventKind::Transfer
                    }
                };

                events.push(LedgerEvent {
                    block_time_unix: block_time,
                    kind,
                    amount_base_units: net_delta.abs(),
                    mint: NATIVE_SOL_MINT.to_string(),
                    counterparty: primary_counterparty_label.clone(),
                    counterparty_address: primary_counterparty_address.clone(),
                    signature: signature.to_string(),
                    is_classified,
                });
            }

            if fee > 0 && wallet_idx == 0 {
                events.push(LedgerEvent {
                    block_time_unix: block_time,
                    kind: EventKind::FeePaid,
                    amount_base_units: fee,
                    mint: NATIVE_SOL_MINT.to_string(),
                    counterparty: Some("Solana Network Fee".to_string()),
                    counterparty_address: Some("11111111111111111111111111111111".to_string()),
                    signature: signature.to_string(),
                    is_classified: true,
                });
            }
        }
    }

    events
}

pub fn parse_spl_token_events(
    signature: &str,
    tx_data: &Value,
    target_wallet: &str,
    target_mint: &str,
    registry: &CounterpartyRegistry,
) -> Vec<LedgerEvent> {
    let mut events = Vec::new();
    let meta = match tx_data.get("meta") {
        Some(m) => m,
        None => return events,
    };

    //DEBUG: USDG mint address
    // if let Some(post) = meta.get("postTokenBalances").and_then(|v| v.as_array()) {
    //     for balance in post {
    //         if let Some(mint) = balance.get("mint").and_then(|v| v.as_str()) {
    //             if mint != "So11111111111111111111111111111111111111112" {
    //                 println!("DEBUG: Found Mint in tx {}: {}", &signature[..8], mint);
    //             }
    //         }
    //     }
    // }

    let empty_vec: Vec<Value> = Vec::new();

    if let (Some(pre), Some(post)) = (meta.get("preTokenBalances"), meta.get("postTokenBalances")) {
        // use &empty_vec instead of &vec![]
        let pre_arr = pre.as_array().unwrap_or(&empty_vec);
        let post_arr = post.as_array().unwrap_or(&empty_vec);

        let get_balance = |arr: &Vec<Value>| -> u128 {
            arr.iter()
                .find(|b| {
                    b.get("owner").and_then(|v| v.as_str()) == Some(target_wallet)
                        && b.get("mint").and_then(|v| v.as_str()) == Some(target_mint)
                })
                .and_then(|b| b.get("uiTokenAmount").and_then(|a| a.get("amount")))
                .and_then(|a| a.as_str())
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0)
        };

        let pre_bal = get_balance(pre_arr);
        let post_bal = get_balance(post_arr);
        let delta = post_bal as i128 - pre_bal as i128;

        // println!(
        //     "DEBUG: Checking Mint {} for Wallet {}",
        //     target_mint, target_wallet
        // );
        // println!("DEBUG: Pre-bal: {}, Post-bal: {}", pre_bal, post_bal);

        if delta != 0 {
            events.push(LedgerEvent {
                block_time_unix: tx_data.get("blockTime").and_then(|v| v.as_i64()),
                kind: if delta > 0 {
                    EventKind::Income
                } else {
                    EventKind::Expense
                },
                amount_base_units: delta.abs(),
                mint: target_mint.to_string(),
                counterparty: Some(registry.get_name_or_address("Unknown")), // Fallback handled by logic
                counterparty_address: Some(target_wallet.to_string()),
                signature: signature.to_string(),
                is_classified: true,
            });
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_event_serialization() {
        let event = LedgerEvent {
            block_time_unix: Some(1000),
            kind: EventKind::Income,
            amount_base_units: 100,
            mint: NATIVE_SOL_MINT.to_string(),
            counterparty: Some("Test Counterparty".to_string()),
            counterparty_address: Some("11111111111111111111111111111111".to_string()),
            signature: "sig_123".to_string(),
            is_classified: true,
        };

        assert_eq!(event.kind, EventKind::Income);
        assert!(event.is_classified);
    }

    #[test]
    fn test_counterparty_registry() {
        let mut registry = CounterpartyRegistry::new();
        assert_eq!(
            registry.get_name("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"),
            "Jupiter Aggregator v6"
        );

        registry.add_rule("custom_pubkey".to_string(), "Custom Vendor".to_string());
        assert_eq!(registry.get_name("custom_pubkey"), "Custom Vendor");
        assert_eq!(registry.get_name("unmapped_key"), "Unknown Counterparty");
    }

    #[test]
    fn test_parse_transaction_events() {
        let registry = CounterpartyRegistry::new();
        let wallet = "WalletA11111111111111111111111111111111111";
        let jup = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4";

        let tx_data = serde_json::json!({
            "blockTime": 1722638400,
            "transaction": {
                "message": {
                    "accountKeys": [wallet, jup]
                }
            },
            "meta": {
                "fee": 5000,
                "preBalances": [1000000000, 500000000],
                "postBalances": [1500000000, 499995000]
            }
        });

        let events = parse_transaction_events("sig_test_123", &tx_data, wallet, &registry);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, EventKind::Income);
        assert_eq!(events[0].amount_base_units, 500005000);
        assert_eq!(
            events[0].counterparty,
            Some("Jupiter Aggregator v6".to_string())
        );
        assert!(events[0].is_classified);

        assert_eq!(events[1].kind, EventKind::FeePaid);
        assert_eq!(events[1].amount_base_units, 5000);
    }
}
