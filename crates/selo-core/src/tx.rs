//! Transaction lookup: `getTransaction` request building, response
//! parsing, and a summary structure rendering can present to the model.

use serde_json::{json, Value};

use crate::rpc::parse_result_value;

/// A per-account SOL balance change extracted from transaction meta.
#[derive(Debug, Clone, PartialEq)]
pub struct BalanceChange {
    pub account: String,
    pub delta_lamports: i128,
}

/// The distilled view of a confirmed transaction.
#[derive(Debug, Clone)]
pub struct TxSummary {
    pub signature: String,
    pub slot: u64,
    pub block_time_unix: Option<i64>,
    /// None means the transaction succeeded; Some carries the error as
    /// the RPC reported it.
    pub error: Option<String>,
    pub fee_lamports: u64,
    pub fee_payer: String,
    pub compute_units: Option<u64>,
    pub balance_changes: Vec<BalanceChange>,
    /// Tail of the program log, only kept for failed transactions.
    pub log_tail: Vec<String>,
}

/// Validate that `s` is a plausible transaction signature: base58, 64 bytes.
pub fn validate_signature(s: &str) -> Result<String, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("signature is empty".to_string());
    }
    let bytes = bs58::decode(trimmed)
        .into_vec()
        .map_err(|_| format!("'{trimmed}' is not valid base58"))?;
    if bytes.len() != 64 {
        return Err(format!(
            "'{trimmed}' decodes to {} bytes, a transaction signature is 64",
            bytes.len()
        ));
    }
    Ok(trimmed.to_string())
}

/// Build a `getTransaction` request for `signature`.
pub fn tx_request(signature: &str) -> Result<String, String> {
    let sig = validate_signature(signature)?;
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            sig,
            { "encoding": "jsonParsed", "maxSupportedTransactionVersion": 0 }
        ]
    })
    .to_string())
}

/// Parse a `getTransaction` response. `Ok(None)` means the node does not
/// have the transaction, which callers should phrase as "not found on
/// this cluster or outside the node's retention window", not as an error.
pub fn parse_tx(signature: &str, body: &str) -> Result<Option<TxSummary>, String> {
    let result = parse_result_value(body)?;
    if result.is_null() {
        return Ok(None);
    }

    let slot = result
        .get("slot")
        .and_then(Value::as_u64)
        .ok_or_else(|| "getTransaction result missing slot".to_string())?;
    let block_time_unix = result.get("blockTime").and_then(Value::as_i64);
    let meta = result
        .get("meta")
        .ok_or_else(|| "getTransaction result missing meta".to_string())?;

    let error = match meta.get("err") {
        None | Some(Value::Null) => None,
        Some(e) => Some(e.to_string()),
    };
    let fee_lamports = meta.get("fee").and_then(Value::as_u64).unwrap_or(0);
    let compute_units = meta.get("computeUnitsConsumed").and_then(Value::as_u64);

    // jsonParsed account keys are objects carrying pubkey plus flags.
    let account_keys: Vec<String> = result
        .pointer("/transaction/message/accountKeys")
        .and_then(Value::as_array)
        .map(|keys| {
            keys.iter()
                .filter_map(|k| {
                    k.get("pubkey")
                        .and_then(Value::as_str)
                        .or_else(|| k.as_str())
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();
    let fee_payer = account_keys.first().cloned().unwrap_or_default();

    let pre = meta
        .get("preBalances")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let post = meta
        .get("postBalances")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut balance_changes = Vec::new();
    for (i, account) in account_keys.iter().enumerate() {
        let before = pre.get(i).and_then(Value::as_u64).unwrap_or(0) as i128;
        let after = post.get(i).and_then(Value::as_u64).unwrap_or(0) as i128;
        if after != before {
            balance_changes.push(BalanceChange {
                account: account.clone(),
                delta_lamports: after - before,
            });
        }
    }

    let log_tail = if error.is_some() {
        meta.get("logMessages")
            .and_then(Value::as_array)
            .map(|logs| {
                logs.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .map(|logs| {
                let keep = 5.min(logs.len());
                logs[logs.len() - keep..].to_vec()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    Ok(Some(TxSummary {
        signature: signature.trim().to_string(),
        slot,
        block_time_unix,
        error,
        fee_lamports,
        fee_payer,
        compute_units,
        balance_changes,
        log_tail,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // 64 bytes of base58; a syntactically valid signature.
    fn valid_sig() -> String {
        bs58::encode([9u8; 64]).into_string()
    }

    #[test]
    fn signature_validation() {
        assert!(validate_signature(&valid_sig()).is_ok());
        assert!(validate_signature("").is_err());
        // 32 bytes is an address, not a signature.
        assert!(validate_signature("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").is_err());
        assert!(validate_signature("not!base58").is_err());
    }

    #[test]
    fn request_shape() {
        let sig = valid_sig();
        let req = tx_request(&sig).unwrap();
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "getTransaction");
        assert_eq!(v["params"][0], sig.as_str());
        assert_eq!(v["params"][1]["maxSupportedTransactionVersion"], 0);
    }

    #[test]
    fn null_result_is_not_found() {
        let body = r#"{"jsonrpc":"2.0","result":null,"id":1}"#;
        assert!(parse_tx(&valid_sig(), body).unwrap().is_none());
    }

    fn success_body() -> String {
        r#"{"jsonrpc":"2.0","result":{
            "slot": 12345,
            "blockTime": 1750000000,
            "meta": {
                "err": null,
                "fee": 5000,
                "computeUnitsConsumed": 450,
                "preBalances": [1000000000, 500, 1],
                "postBalances": [999895000, 100500, 1],
                "logMessages": ["Program 11111111111111111111111111111111 invoke [1]",
                                "Program 11111111111111111111111111111111 success"]
            },
            "transaction": { "message": { "accountKeys": [
                {"pubkey": "PayerAddr", "signer": true, "writable": true},
                {"pubkey": "DestAddr", "signer": false, "writable": true},
                {"pubkey": "11111111111111111111111111111111", "signer": false, "writable": false}
            ]}}
        },"id":1}"#
            .to_string()
    }

    #[test]
    fn parses_successful_transfer() {
        let summary = parse_tx(&valid_sig(), &success_body()).unwrap().unwrap();
        assert_eq!(summary.slot, 12345);
        assert_eq!(summary.error, None);
        assert_eq!(summary.fee_lamports, 5000);
        assert_eq!(summary.fee_payer, "PayerAddr");
        assert_eq!(summary.compute_units, Some(450));
        assert_eq!(summary.balance_changes.len(), 2);
        assert_eq!(summary.balance_changes[0].account, "PayerAddr");
        assert_eq!(summary.balance_changes[0].delta_lamports, -105000);
        assert_eq!(summary.balance_changes[1].delta_lamports, 100000);
        // Successful transactions carry no log tail.
        assert!(summary.log_tail.is_empty());
    }

    #[test]
    fn failed_tx_keeps_error_and_log_tail() {
        let body = success_body()
            .replace(r#""err": null"#, r#""err": {"InstructionError":[0,"Custom"]}"#);
        let summary = parse_tx(&valid_sig(), &body).unwrap().unwrap();
        let err = summary.error.expect("error should be set");
        assert!(err.contains("InstructionError"));
        assert_eq!(summary.log_tail.len(), 2);
    }
}
