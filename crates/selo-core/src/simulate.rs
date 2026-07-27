//! Transaction simulation: the dry run behind the transfer tool.
//!
//! `simulateTransaction` runs a signed transaction against the node's
//! current bank and reports what would happen without submitting it.
//! This is what lets an agent check a spend before committing to it,
//! and it is the reason the transfer path was written as separable
//! build, sign, and send steps rather than one function.

use serde_json::{json, Value};

use crate::rpc::parse_result_value;

/// The outcome of a simulated transaction.
#[derive(Debug, Clone)]
pub struct Simulation {
    /// None means the transaction would succeed.
    pub error: Option<String>,
    pub compute_units: Option<u64>,
    pub logs: Vec<String>,
}

impl Simulation {
    pub fn would_succeed(&self) -> bool {
        self.error.is_none()
    }
}

/// Build a `simulateTransaction` request for a base64 transaction.
///
/// Signature verification is off and the simulation runs against the
/// current bank, which keeps a dry run cheap and avoids failing on a
/// blockhash that is merely recent rather than current.
pub fn simulate_request(tx_base64: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "simulateTransaction",
        "params": [
            tx_base64,
            {
                "encoding": "base64",
                "commitment": "processed",
                "sigVerify": false,
                "replaceRecentBlockhash": true
            }
        ]
    })
    .to_string()
}

/// Parse a `simulateTransaction` response.
pub fn parse_simulation(body: &str) -> Result<Simulation, String> {
    let result = parse_result_value(body)?;
    let value = result
        .get("value")
        .ok_or_else(|| "simulateTransaction result missing value".to_string())?;

    let error = match value.get("err") {
        None | Some(Value::Null) => None,
        Some(e) => Some(e.to_string()),
    };
    let compute_units = value.get("unitsConsumed").and_then(Value::as_u64);
    let logs = value
        .get("logs")
        .and_then(Value::as_array)
        .map(|l| {
            l.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    Ok(Simulation {
        error,
        compute_units,
        logs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_disables_sigverify_and_replaces_blockhash() {
        let req = simulate_request("dGVzdA==");
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "simulateTransaction");
        assert_eq!(v["params"][1]["encoding"], "base64");
        assert_eq!(v["params"][1]["sigVerify"], false);
        assert_eq!(v["params"][1]["replaceRecentBlockhash"], true);
    }

    #[test]
    fn parses_successful_simulation() {
        let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{
            "err":null,"unitsConsumed":450,
            "logs":["Program 11111111111111111111111111111111 invoke [1]",
                    "Program 11111111111111111111111111111111 success"]}},"id":1}"#;
        let sim = parse_simulation(body).unwrap();
        assert!(sim.would_succeed());
        assert_eq!(sim.compute_units, Some(450));
        assert_eq!(sim.logs.len(), 2);
    }

    #[test]
    fn parses_failed_simulation() {
        let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{
            "err":{"InstructionError":[0,{"Custom":1}]},"unitsConsumed":200,
            "logs":["Program 11111111111111111111111111111111 failed: insufficient lamports"]}},"id":1}"#;
        let sim = parse_simulation(body).unwrap();
        assert!(!sim.would_succeed());
        assert!(sim.error.unwrap().contains("InstructionError"));
        assert!(sim.logs[0].contains("insufficient lamports"));
    }

    #[test]
    fn missing_value_errors() {
        assert!(parse_simulation(r#"{"jsonrpc":"2.0","result":{},"id":1}"#).is_err());
    }
}
