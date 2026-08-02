//! JSON-RPC request builders and response parsers.
//!
//! Builders validate their inputs and return the request body as a JSON
//! string. Parsers accept the raw response body and surface RPC-level
//! errors as `Err(String)` messages suitable for showing to the model.

use serde_json::{json, Value};

use crate::address::validate_pubkey;

/// SPL Token program id, the owner-filter for `getTokenAccountsByOwner`.
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

/// One SPL token holding parsed from `getTokenAccountsByOwner`.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenBalance {
    pub mint: String,
    pub amount_raw: String,
    pub decimals: u8,
    pub ui_amount: String,
}

/// Build a `getBalance` request for `address`.
pub fn balance_request(address: &str) -> Result<String, String> {
    let addr = validate_pubkey(address)?;
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [addr]
    })
    .to_string())
}

/// Build a `getTokenAccountsByOwner` request for `owner`, filtered to the
/// classic SPL Token program, parsed encoding.
pub fn token_accounts_request(owner: &str) -> Result<String, String> {
    let addr = validate_pubkey(owner)?;
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            addr,
            { "programId": TOKEN_PROGRAM_ID },
            { "encoding": "jsonParsed" }
        ]
    })
    .to_string())
}

/// Parse a response body into its `result` value, surfacing JSON-RPC
/// error objects as readable messages. Shared by every parser in the
/// suite, including the transfer and tx modules.
pub fn parse_result_value(body: &str) -> Result<Value, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|e| format!("RPC response is not JSON: {e}"))?;
    if let Some(err) = value.get("error") {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = err
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        return Err(format!("RPC error {code}: {message}"));
    }
    value
        .get("result")
        .cloned()
        .ok_or_else(|| "RPC response has neither result nor error".to_string())
}

/// Parse a `getBalance` response into lamports.
pub fn parse_balance(body: &str) -> Result<u64, String> {
    parse_result_value(body)?
        .get("value")
        .and_then(Value::as_u64)
        .ok_or_else(|| "getBalance result.value is missing or not an integer".to_string())
}

/// Parse a `getTokenAccountsByOwner` (jsonParsed) response into holdings.
/// Zero-balance accounts are kept; rendering decides what to show.
pub fn parse_token_accounts(body: &str) -> Result<Vec<TokenBalance>, String> {
    let result = parse_result_value(body)?;
    let accounts = result
        .get("value")
        .and_then(Value::as_array)
        .ok_or_else(|| "getTokenAccountsByOwner result.value is not an array".to_string())?;

    let mut balances = Vec::with_capacity(accounts.len());
    for account in accounts {
        let info = account
            .pointer("/account/data/parsed/info")
            .ok_or_else(|| "token account missing parsed info".to_string())?;
        let mint = info
            .get("mint")
            .and_then(Value::as_str)
            .ok_or_else(|| "token account missing mint".to_string())?
            .to_string();
        let token_amount = info
            .get("tokenAmount")
            .ok_or_else(|| "token account missing tokenAmount".to_string())?;
        let amount_raw = token_amount
            .get("amount")
            .and_then(Value::as_str)
            .unwrap_or("0")
            .to_string();
        let decimals = token_amount
            .get("decimals")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u8;
        let ui_amount = token_amount
            .get("uiAmountString")
            .and_then(Value::as_str)
            .unwrap_or("0")
            .to_string();
        balances.push(TokenBalance {
            mint,
            amount_raw,
            decimals,
            ui_amount,
        });
    }
    Ok(balances)
}

/// integration test
#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    #[test]
    fn balance_request_is_wellformed() {
        let req = balance_request(OWNER).unwrap();
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "getBalance");
        assert_eq!(v["params"][0], OWNER);
    }

    #[test]
    fn balance_request_rejects_bad_address() {
        assert!(balance_request("nope!").is_err());
    }

    #[test]
    fn token_request_filters_on_token_program() {
        let req = token_accounts_request(OWNER).unwrap();
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "getTokenAccountsByOwner");
        assert_eq!(v["params"][1]["programId"], TOKEN_PROGRAM_ID);
        assert_eq!(v["params"][2]["encoding"], "jsonParsed");
    }

    #[test]
    fn parses_balance() {
        let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":1500000000},"id":1}"#;
        assert_eq!(parse_balance(body).unwrap(), 1_500_000_000);
    }

    #[test]
    fn surfaces_rpc_error() {
        let body = r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid param"},"id":1}"#;
        let err = parse_balance(body).unwrap_err();
        assert!(err.contains("-32602"));
        assert!(err.contains("Invalid param"));
    }

    #[test]
    fn rejects_non_json() {
        assert!(parse_balance("<html>rate limited</html>").is_err());
    }

    #[test]
    fn parses_token_accounts() {
        let body = r#"{
            "jsonrpc": "2.0",
            "result": { "context": {"slot": 1}, "value": [
                { "pubkey": "acc1", "account": { "data": { "parsed": { "info": {
                    "mint": "So11111111111111111111111111111111111111112",
                    "tokenAmount": {
                        "amount": "2500000",
                        "decimals": 6,
                        "uiAmountString": "2.5"
                    }
                }}}}}
            ]},
            "id": 1
        }"#;
        let tokens = parse_token_accounts(body).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].mint, "So11111111111111111111111111111111111111112");
        assert_eq!(tokens[0].ui_amount, "2.5");
        assert_eq!(tokens[0].decimals, 6);
    }

    #[test]
    fn empty_token_list_is_ok() {
        let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":[]},"id":1}"#;
        assert!(parse_token_accounts(body).unwrap().is_empty());
    }
}
