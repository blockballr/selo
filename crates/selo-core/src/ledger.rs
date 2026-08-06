//! Tracks cost basis, counterparty rules, and backfilling over RpcSeam.

use crate::RpcSeam;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Standard native SOL mint address on Solana.
pub const NATIVE_SOL_MINT: &str = "So11111111111111111111111111111111111111112";

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
            "Token-2022 Program".to_string(),
        );
        rules.insert(
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL".to_string(),
            "Associated Token Program".to_string(),
        );
        rules.insert(
            "ComputeBudget111111111111111111111111111111".to_string(),
            "Compute Budget Program".to_string(),
        );
        rules.insert(
            "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".to_string(),
            "Jupiter Aggregator v6".to_string(),
        );
        rules.insert(
            "gasTzr94Pmp4Gf8vknQnqxeYxdgwFjbgdJa4msYRpnB".to_string(),
            "Jupiter Gas Wallet".to_string(),
        );
        rules.insert(
            "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8".to_string(),
            "Raydium Liquidity Pool V4".to_string(),
        );
        rules.insert(
            "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc".to_string(),
            "Orca Whirlpool Program".to_string(),
        );
        rules.insert(
            "PhoeNiXZ8ByJGLkxNfZRnkUfjvmuYqLR89jjFHGqdXY".to_string(),
            "Phoenix DEX".to_string(),
        );
        rules.insert(
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            "USDC Mint".to_string(),
        );
        rules.insert(
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB".to_string(),
            "USDT Mint".to_string(),
        );
        rules.insert(
            "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo".to_string(),
            "PYUSD Mint".to_string(),
        );
        rules.insert(
            "STBR3W8ztr2h6K8p2zN6jR5wL8kQ9tM4sP2vX1yZ3kL9".to_string(),
            "Superteam Brazil Treasury".to_string(),
        );
        rules.insert(
            "STBRValidator111111111111111111111111111111".to_string(),
            "Superteam Brazil Validator".to_string(),
        );
        Self { rules }
    }

    pub fn add_rule(&mut self, pubkey: String, name: String) {
        self.rules.insert(pubkey, name);
    }

    pub fn get_name(&self, pubkey: &str) -> String {
        if let Some(name) = self.rules.get(pubkey) {
            return name.clone();
        }
        // automatically catch any relayer or gas account starting with "gas"
        if pubkey.starts_with("gas") {
            return "Gas Wallet / Relayer".to_string();
        }
        "Unknown Counterparty".to_string()
    }

    pub fn format_address(&self, pubkey: &str) -> String {
        if pubkey.len() > 8 {
            format!("{}...", &pubkey[..8])
        } else {
            pubkey.to_string()
        }
    }

    pub fn count(&self) -> usize {
        self.rules.len()
    }
    /// find a registered counterparty address by its human-readable name (case-insensitive).
    pub fn find_address_by_name(&self, name_query: &str) -> Option<String> {
        let query_lower = name_query.trim().to_lowercase();
        if query_lower.is_empty() {
            return None;
        }

        // 1. Try exact case-insensitive match first
        for (addr, name) in &self.rules {
            if name.to_lowercase() == query_lower {
                return Some(addr.clone());
            }
        }

        // 2. Fallback to substring / partial match
        for (addr, name) in &self.rules {
            if name.to_lowercase().contains(&query_lower) {
                return Some(addr.clone());
            }
        }

        None
    }
}

#[derive(Debug, Clone)]
pub struct Backfiller<'a, T: RpcSeam> {
    pub rpc: &'a T,
}

impl<'a, T: RpcSeam> Backfiller<'a, T> {
    pub fn new(rpc: &'a T) -> Self {
        Self { rpc }
    }

    pub fn backfill(&self, address: &str) -> Result<Vec<String>, String> {
        self.backfill_advanced(address, None, None, None, true)
    }

    pub fn backfill_with_limit(
        &self,
        address: &str,
        limit: Option<usize>,
    ) -> Result<Vec<String>, String> {
        self.backfill_advanced(address, limit, None, None, false)
    }

    pub fn backfill_advanced(
        &self,
        address: &str,
        limit: Option<usize>,
        since: Option<&str>,
        before: Option<&str>,
        all: bool,
    ) -> Result<Vec<String>, String> {
        let mut all_signatures = Vec::new();
        let mut before_sig: Option<String> = None;

        let effective_limit = if all || since.is_some() || before.is_some() {
            limit
        } else {
            limit.or(Some(50))
        };

        let since_ts = since.and_then(parse_date_to_timestamp);
        let before_ts = before.and_then(parse_date_to_timestamp);

        loop {
            if let Some(l) = effective_limit {
                if all_signatures.len() >= l {
                    break;
                }
            }

            let batch_size = match effective_limit {
                Some(l) => std::cmp::min(1000, l - all_signatures.len()),
                None => 1000,
            };

            let batch =
                self.rpc
                    .get_signatures_paginated(address, before_sig.as_deref(), batch_size)?;
            if batch.is_empty() {
                break;
            }

            let last_sig = match batch.last() {
                Some(sig) => sig.clone(),
                None => break,
            };

            if since_ts.is_some() || before_ts.is_some() {
                for sig in batch {
                    let mut include = true;
                    if let Ok(tx_data) = self.rpc.get_transaction(&sig) {
                        if let Some(bt) = tx_data.get("blockTime").and_then(|v| v.as_i64()) {
                            if let Some(s) = since_ts {
                                if bt < s {
                                    include = false;
                                }
                            }
                            if let Some(b) = before_ts {
                                if bt > b {
                                    include = false;
                                }
                            }
                        }
                    }
                    if include {
                        all_signatures.push(sig);
                    }
                }
            } else {
                all_signatures.extend(batch);
            }

            before_sig = Some(last_sig);

            if all_signatures.len() >= 50_000 && effective_limit.is_none() {
                break;
            }
        }

        if let Some(l) = effective_limit {
            if all_signatures.len() > l {
                all_signatures.truncate(l);
            }
        }

        Ok(all_signatures)
    }
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn parse_date_to_timestamp(date_str: &str) -> Option<i64> {
    let trimmed = date_str.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(ts) = trimmed.parse::<i64>() {
        return Some(ts);
    }

    let parts: Vec<&str> = trimmed.split('T').collect();
    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();

    let (year, month, day) = match date_parts.len() {
        3 => (date_parts[0], date_parts[1], date_parts[2]),
        2 => (date_parts[0], date_parts[1], 1),
        1 => (date_parts[0], 1, 1),
        _ => return None,
    };

    if year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 {
        return None;
    }

    let mut days: u64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    let days_in_months = [
        0,
        31,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    for m in 1..month {
        days += days_in_months[m as usize];
    }

    days += day - 1;
    Some((days * 86400) as i64)
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

    // Programs and mints that should NEVER be treated as counterparties
    let ignore_as_cp = vec![
        "11111111111111111111111111111111",
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        "ComputeBudget111111111111111111111111111111",
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", // USDC Mint
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", // USDT Mint
        "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo", // PYUSD Mint
        target_wallet,
    ];

    // 1. First check if a known protocol (like Jupiter, Raydium, Orca) is in the transaction
    for key in &account_keys {
        if !ignore_as_cp.contains(&key.as_str()) {
            let label = registry.get_name(key);
            if label != "Unknown Counterparty" {
                primary_counterparty_address = Some(key.clone());
                primary_counterparty_label = Some(label);
                is_classified = true;
                break;
            }
        }
    }

    // 2. If no known protocol, look for an external user wallet address
    if primary_counterparty_address.is_none() {
        for key in &account_keys {
            if !ignore_as_cp.contains(&key.as_str()) {
                primary_counterparty_address = Some(key.clone());
                primary_counterparty_label = Some(registry.format_address(key));
                break;
            }
        }
    }

    let meta = match tx_data.get("meta") {
        Some(m) => m,
        None => return events,
    };

    // Allowed asset mints: SOL, USDC, USDT, PYUSD/USDG
    let allowed_mints = vec![
        NATIVE_SOL_MINT,
        "So11111111111111111111111111111111111111112",
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", // USDC
        "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", // USDT
        "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo", // PYUSD / USDG
    ];

    // Native SOL Delta
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

    // SPL Token Deltas (Strictly filtered to allowed stablecoins & SOL)
    let empty_vec: Vec<Value> = Vec::new();
    if let (Some(pre), Some(post)) = (meta.get("preTokenBalances"), meta.get("postTokenBalances")) {
        let pre_arr = pre.as_array().unwrap_or(&empty_vec);
        let post_arr = post.as_array().unwrap_or(&empty_vec);

        let mut mints = std::collections::HashSet::new();
        for b in pre_arr {
            if b.get("owner").and_then(|v| v.as_str()) == Some(target_wallet) {
                if let Some(m) = b.get("mint").and_then(|v| v.as_str()) {
                    if allowed_mints.contains(&m) {
                        mints.insert(m.to_string());
                    }
                }
            }
        }
        for b in post_arr {
            if b.get("owner").and_then(|v| v.as_str()) == Some(target_wallet) {
                if let Some(m) = b.get("mint").and_then(|v| v.as_str()) {
                    if allowed_mints.contains(&m) {
                        mints.insert(m.to_string());
                    }
                }
            }
        }

        let get_balance = |arr: &Vec<Value>, target_mint: &str| -> u128 {
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

        for mint in mints {
            let pre_bal = get_balance(pre_arr, &mint);
            let post_bal = get_balance(post_arr, &mint);
            let delta = post_bal as i128 - pre_bal as i128;

            if delta != 0 {
                let kind = if delta > 0 {
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
                    amount_base_units: delta.abs(),
                    mint,
                    counterparty: primary_counterparty_label.clone(),
                    counterparty_address: primary_counterparty_address.clone(),
                    signature: signature.to_string(),
                    is_classified,
                });
            }
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
    fn test_registry_separation() {
        let registry = CounterpartyRegistry::new();
        let formatted = registry.format_address("88888888888888888888888888888888888888888888");
        assert_eq!(formatted, "88888888...");
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
