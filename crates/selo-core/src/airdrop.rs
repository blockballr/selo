//! Devnet and testnet airdrop requests.
//!
//! `requestAirdrop` exists only on the test clusters; mainnet nodes
//! reject it. Rather than let the agent discover that through an opaque
//! RPC error, this module refuses up front when the configured endpoint
//! looks like mainnet, and says why.

use serde_json::{json, Value};

use crate::address::validate_pubkey;
use crate::rpc::parse_result_value;

/// Devnet's airdrop faucet caps a single request at 2 SOL. Asking for
/// more fails at the node, so the ceiling is enforced here with a
/// message that explains the limit.
pub const MAX_AIRDROP_LAMPORTS: u64 = 2_000_000_000;

/// Refuse airdrops against an endpoint that looks like mainnet.
///
/// This is a heuristic on the URL, not proof of cluster identity, so it
/// is a guard against the common mistake rather than a security control.
pub fn ensure_test_cluster(rpc_url: &str) -> Result<(), String> {
    let lower = rpc_url.to_ascii_lowercase();
    if lower.contains("devnet") || lower.contains("testnet") || lower.contains("localhost") {
        return Ok(());
    }
    if lower.contains("mainnet") {
        return Err(format!(
            "the configured RPC endpoint ({rpc_url}) is mainnet, which has no \
             airdrop faucet; point the plugin's rpc_url config at \
             https://api.devnet.solana.com to use this tool"
        ));
    }
    Err(format!(
        "cannot confirm the configured RPC endpoint ({rpc_url}) is devnet or \
         testnet; airdrops only exist on test clusters, so set the plugin's \
         rpc_url config to an endpoint whose host names the cluster"
    ))
}

/// Build a `requestAirdrop` request.
pub fn airdrop_request(address: &str, lamports: u64) -> Result<String, String> {
    let addr = validate_pubkey(address)?;
    if lamports == 0 {
        return Err("airdrop amount is zero lamports".to_string());
    }
    if lamports > MAX_AIRDROP_LAMPORTS {
        return Err(format!(
            "requested {lamports} lamports exceeds the {MAX_AIRDROP_LAMPORTS} \
             lamport (2 SOL) faucet limit for a single airdrop"
        ));
    }
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "requestAirdrop",
        "params": [addr, lamports]
    })
    .to_string())
}

/// Parse a `requestAirdrop` response into the funding signature.
pub fn parse_airdrop(body: &str) -> Result<String, String> {
    parse_result_value(body)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "requestAirdrop result is not a signature string".to_string())
}

/// Build a `getBalance` style confirmation is not needed here; callers
/// reuse `rpc::balance_request`. This helper only exists to keep the
/// airdrop tool's RPC surface in one module.
pub fn confirm_request(signature: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignatureStatuses",
        "params": [[signature], { "searchTransactionHistory": false }]
    })
    .to_string()
}

/// Parse `getSignatureStatuses` into the confirmation status string, if
/// the node has one yet.
pub fn parse_confirmation(body: &str) -> Result<Option<String>, String> {
    let result = parse_result_value(body)?;
    let first = result
        .pointer("/value/0")
        .ok_or_else(|| "getSignatureStatuses result missing value".to_string())?;
    if first.is_null() {
        return Ok(None);
    }
    if let Some(err) = first.get("err") {
        if !err.is_null() {
            return Err(format!("airdrop transaction failed: {err}"));
        }
    }
    Ok(first
        .get("confirmationStatus")
        .and_then(Value::as_str)
        .map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    #[test]
    fn allows_test_clusters() {
        assert!(ensure_test_cluster("https://api.devnet.solana.com").is_ok());
        assert!(ensure_test_cluster("https://api.testnet.solana.com").is_ok());
        assert!(ensure_test_cluster("http://localhost:8899").is_ok());
    }

    #[test]
    fn refuses_mainnet_by_name() {
        let err = ensure_test_cluster("https://api.mainnet-beta.solana.com").unwrap_err();
        assert!(err.contains("no airdrop faucet"));
        assert!(err.contains("devnet"));
    }

    #[test]
    fn refuses_ambiguous_endpoint() {
        // A private RPC whose host names no cluster: refuse rather than
        // risk firing a mainnet request.
        let err = ensure_test_cluster("https://rpc.example.com/abc123").unwrap_err();
        assert!(err.contains("cannot confirm"));
    }

    #[test]
    fn builds_request() {
        let req = airdrop_request(ADDR, 1_000_000_000).unwrap();
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "requestAirdrop");
        assert_eq!(v["params"][0], ADDR);
        assert_eq!(v["params"][1], 1_000_000_000u64);
    }

    #[test]
    fn enforces_faucet_limit_and_zero() {
        assert!(airdrop_request(ADDR, 0).is_err());
        assert!(airdrop_request(ADDR, MAX_AIRDROP_LAMPORTS).is_ok());
        let err = airdrop_request(ADDR, MAX_AIRDROP_LAMPORTS + 1).unwrap_err();
        assert!(err.contains("faucet limit"));
    }

    #[test]
    fn parses_signature() {
        let body = r#"{"jsonrpc":"2.0","result":"5AirdropSig","id":1}"#;
        assert_eq!(parse_airdrop(body).unwrap(), "5AirdropSig");
    }

    #[test]
    fn surfaces_faucet_exhaustion() {
        let body = r#"{"jsonrpc":"2.0","error":{"code":429,
            "message":"airdrop request limit reached"},"id":1}"#;
        let err = parse_airdrop(body).unwrap_err();
        assert!(err.contains("limit reached"));
    }

    #[test]
    fn confirmation_states() {
        let pending = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":[null]},"id":1}"#;
        assert_eq!(parse_confirmation(pending).unwrap(), None);

        let done = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},
            "value":[{"slot":5,"confirmations":null,"err":null,
            "confirmationStatus":"finalized"}]},"id":1}"#;
        assert_eq!(
            parse_confirmation(done).unwrap(),
            Some("finalized".to_string())
        );

        let failed = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},
            "value":[{"slot":5,"err":{"InstructionError":[0,"Custom"]},
            "confirmationStatus":"processed"}]},"id":1}"#;
        assert!(parse_confirmation(failed).is_err());
    }
}
