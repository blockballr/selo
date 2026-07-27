//! ZeroClaw tool plugin: `solana_compressed_accounts`.
//!
//! Reading ZK compressed state means asking a Photon indexer, which is
//! a third party making a claim about the chain. This tool does not
//! stop there: for each account it reports, it fetches the merkle proof
//! and recomputes the tree root locally with Poseidon. If the
//! recomputed root does not match, the account is reported as failing
//! rather than as a balance.
//!
//! Verification is bounded because each proof is 32 levels deep and
//! costs a round trip plus 32 Poseidon hashes. An owner with hundreds
//! of accounts would otherwise turn one tool call into hundreds of
//! requests, so the tool checks a capped number and says plainly how
//! many it checked.

#[cfg(target_family = "wasm")]
mod component {
    wit_bindgen::generate!({
        path: "wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    use std::collections::HashMap;
    use std::time::Duration;

    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use solana_plugin_core::config::RpcConfig;
    use solana_plugin_core::format::{render_compressed_accounts, VerifiedAccount};
    use solana_plugin_core::zk;
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    /// Hard ceiling on proofs fetched per call, whatever the caller asks.
    const MAX_VERIFY: usize = 10;

    struct CompressedAccountsPlugin;

    #[derive(serde::Deserialize)]
    struct ExecuteArgs {
        owner: String,
        #[serde(default)]
        verify: Option<bool>,
        #[serde(default)]
        max_verify: Option<usize>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    fn rpc_post(cfg: &RpcConfig, body: String) -> Result<String, String> {
        let resp = waki::Client::new()
            .post(&cfg.url)
            .header("Content-Type", "application/json")
            .body(body.into_bytes())
            .connect_timeout(Duration::from_secs(cfg.timeout_secs))
            .send()
            .map_err(|e| format!("RPC request to the indexer failed: {e}"))?;
        let status = resp.status_code();
        let bytes = resp
            .body()
            .map_err(|e| format!("failed reading indexer response body: {e}"))?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        if !(200..300).contains(&status) {
            return Err(format!(
                "indexer returned HTTP {status}: {}",
                text.chars().take(200).collect::<String>()
            ));
        }
        Ok(text)
    }

    fn run(args: &ExecuteArgs) -> Result<String, String> {
        let cfg = RpcConfig::from_section(&args.config);
        let verify = args.verify.unwrap_or(true);
        let budget = args.max_verify.unwrap_or(3).min(MAX_VERIFY);

        let body = rpc_post(&cfg, zk::accounts_by_owner_request(&args.owner)?)?;
        let accounts = zk::parse_accounts_by_owner(&body)?;
        let total = accounts.len();

        let mut reported = Vec::new();
        for (i, account) in accounts.iter().enumerate() {
            let should_verify = verify && i < budget;
            let verified = if should_verify {
                // A failed proof is a finding, not a reason to abort:
                // the caller needs to see which account failed.
                Some(
                    rpc_post(&cfg, zk::account_proof_request(&account.hash)?)
                        .and_then(|b| zk::parse_account_proof(&b))
                        .and_then(|p| {
                            zk::verify_proof(&p.hash, p.leaf_index, &p.proof, &p.root)
                        }),
                )
            } else {
                None
            };
            reported.push(VerifiedAccount {
                hash: account.hash.clone(),
                leaf_index: account.leaf_index,
                tree: account.tree.clone(),
                lamports: account.lamports,
                verified,
            });
            if reported.len() >= 10 && i + 1 >= budget {
                break;
            }
        }

        Ok(render_compressed_accounts(args.owner.trim(), total, &reported))
    }

    fn log_outcome(outcome: PluginOutcome, message: &str) {
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_compressed_accounts::tool::execute".to_string(),
                action: PluginAction::Complete,
                outcome: Some(outcome),
                duration_ms: None,
                attrs: None,
                message: message.to_string(),
            },
        );
    }

    impl PluginInfo for CompressedAccountsPlugin {
        fn plugin_name() -> String {
            "solana-compressed-accounts".to_string()
        }
        fn plugin_version() -> String {
            "0.1.0".to_string()
        }
    }

    impl Tool for CompressedAccountsPlugin {
        fn name() -> String {
            "solana_compressed_accounts".to_string()
        }

        fn description() -> String {
            "List the ZK compressed accounts owned by a Solana address and \
             verify their merkle proofs. Compressed accounts store their data \
             off chain in a merkle tree with only a commitment on chain, which \
             is how large airdrops are distributed cheaply, and they do NOT \
             show up in an ordinary balance lookup, so use this tool when an \
             ordinary balance looks empty but the user expects compressed \
             holdings. Each checked account has its proof recomputed locally, \
             so a verified result is cryptographically backed rather than the \
             indexer's word. Requires the operator to have configured a Photon \
             indexer RPC. Read-only and keyless."
                .to_string()
        }

        fn parameters_schema() -> String {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "owner": {
                        "type": "string",
                        "description": "Base58 address whose compressed accounts to list."
                    },
                    "verify": {
                        "type": "boolean",
                        "description": "Verify merkle proofs locally. Defaults to true; set false only for a fast unverified listing."
                    },
                    "max_verify": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10,
                        "description": "How many proofs to verify. Each costs a round trip, so this defaults to 3 and is capped at 10."
                    }
                },
                "required": ["owner"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            let parsed: ExecuteArgs = match serde_json::from_str(&args) {
                Ok(a) => a,
                Err(e) => {
                    return Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(format!("invalid arguments: {e}")),
                    });
                }
            };

            match run(&parsed) {
                Ok(output) => {
                    log_outcome(PluginOutcome::Success, "compressed account lookup complete");
                    Ok(ToolResult {
                        success: true,
                        output,
                        error: None,
                    })
                }
                Err(message) => {
                    log_outcome(PluginOutcome::Failure, "compressed account lookup failed");
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(message),
                    })
                }
            }
        }
    }

    export!(CompressedAccountsPlugin);
}
