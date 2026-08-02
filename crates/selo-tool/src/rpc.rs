use selo_core::RpcSeam;
use serde_json::{json, Value};

pub struct ToolRpc {
    pub rpc_url: String,
}

impl ToolRpc {
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.to_string(),
        }
    }
    /// helper: perform JSON-RPC POST requests using ureq
    fn post(&self, payload: Value) -> Result<Value, String> {
        let response = ureq::post(&self.rpc_url)
            .header("Content-Type", "application/json")
            .send_json(payload)
            .map_err(|e| format!("HTTP transport error: {}", e))?;

        let res: Value = response
            .into_body()
            .read_json()
            .map_err(|e| format!("JSON parsing error: {}", e))?;

        if let Some(err) = res.get("error") {
            return Err(format!("Solana RPC error: {}", err));
        }

        Ok(res)
    }
}

impl RpcSeam for ToolRpc {
    fn get_balance(&self, pubkey: &str) -> Result<u64, String> {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [pubkey]
        });

        let res = self.post(payload)?;
        res["result"]["value"]
            .as_u64()
            .ok_or_else(|| "Failed to parse balance from RPC response".to_string())
    }

    fn get_latest_blockhash(&self) -> Result<String, String> {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": []
        });

        let res = self.post(payload)?;
        res["result"]["value"]["blockhash"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "Failed to parse blockhash from RPC response".to_string())
    }

    fn get_signatures(&self, address: &str) -> Result<Vec<String>, String> {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [address, { "limit": 25 }]
        });

        let res = self.post(payload)?;
        let items = res["result"]
            .as_array()
            .ok_or_else(|| "Failed to parse signatures array from RPC response".to_string())?;

        let sigs = items
            .iter()
            .filter_map(|item| item["signature"].as_str().map(|s| s.to_string()))
            .collect();

        Ok(sigs)
    }

    fn get_transaction(&self, sig: &str) -> Result<Value, String> {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                sig,
                {
                    "encoding": "json",
                    "maxSupportedTransactionVersion": 0
                }
            ]
        });

        let res = self.post(payload)?;
        Ok(res["result"].clone())
    }
}
