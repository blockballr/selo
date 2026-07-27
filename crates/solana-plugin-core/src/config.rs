//! Plugin config resolved from the host's jailed `__config` section.
//!
//! The host hands plugins a flat string-to-string map, and only when the
//! manifest declares `config_read`. An empty map is not an edge case, it
//! is the default: it is exactly what arrives when the operator has not
//! configured the plugin. Every field therefore parses with a safe
//! fallback, and the defaults must produce read-only, harmless behavior.

use std::collections::HashMap;

/// Public mainnet RPC. Rate-limited but safe and free; operators point
/// `rpc_url` at their own endpoint for real use.
pub const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

/// Default per-request timeout in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Resolved RPC settings for one tool call.
pub struct RpcConfig {
    pub url: String,
    pub timeout_secs: u64,
}

impl RpcConfig {
    /// Build from the injected `__config` section. Absent, empty, or
    /// unparseable keys fall back to defaults.
    ///
    /// Keys: `rpc_url` (endpoint URL), `timeout_secs` (integer seconds).
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let url = section
            .get("rpc_url")
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        let timeout_secs = section
            .get("timeout_secs")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        Self { url, timeout_secs }
    }
}

/// Default per-call spend ceiling for the transfer tool: 0.1 SOL.
pub const DEFAULT_MAX_LAMPORTS: u64 = 100_000_000;

/// Spend policy for the transfer tool, resolved from the same jailed
/// config section. The ceiling exists so a confused or manipulated model
/// cannot drain the configured wallet in one call; operators raise it
/// deliberately via `max_lamports`.
pub struct TransferPolicy {
    pub max_lamports: u64,
}

impl TransferPolicy {
    /// Key: `max_lamports` (integer). Absent or unparseable falls back
    /// to the conservative default.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let max_lamports = section
            .get("max_lamports")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_MAX_LAMPORTS);
        Self { max_lamports }
    }

    /// Enforce the ceiling with a message that tells the model exactly
    /// what was refused and how the operator can change it.
    pub fn check(&self, lamports: u64) -> Result<(), String> {
        if lamports > self.max_lamports {
            return Err(format!(
                "transfer of {lamports} lamports exceeds the configured ceiling of {} \
                 lamports; the operator can raise it via the max_lamports config key",
                self.max_lamports
            ));
        }
        Ok(())
    }
}


/// Jupiter's free tier host. The paid `api.jup.ag` host needs an API
/// key, so operators with one point `jupiter_base_url` at it instead.
pub const DEFAULT_JUPITER_BASE_URL: &str = "https://lite-api.jup.ag";

/// Default slippage tolerance for a quote, 50 bps (0.5 percent).
pub const DEFAULT_SLIPPAGE_BPS: u64 = 50;

/// Jupiter settings resolved from the jailed config section.
pub struct JupiterConfig {
    pub base_url: String,
    pub timeout_secs: u64,
    pub default_slippage_bps: u64,
}

impl JupiterConfig {
    /// Keys: `jupiter_base_url`, `timeout_secs`, `default_slippage_bps`.
    /// All optional; an empty section quotes against the free host.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let base_url = section
            .get("jupiter_base_url")
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| DEFAULT_JUPITER_BASE_URL.to_string());
        let timeout_secs = section
            .get("timeout_secs")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        let default_slippage_bps = section
            .get("default_slippage_bps")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&v| v > 0 && v <= 10_000)
            .unwrap_or(DEFAULT_SLIPPAGE_BPS);
        Self { base_url, timeout_secs, default_slippage_bps }
    }
}


/// Default per-call token ceiling, in whole display units: 100 tokens.
/// Deliberately conservative, since one call should not be able to move
/// a meaningful balance without the operator opting in.
pub const DEFAULT_MAX_TOKEN_UI_AMOUNT: u64 = 100;

/// Spend policy for the SPL token transfer tool.
///
/// A single lamport ceiling cannot work across mints, because a base
/// unit means something different for every decimals value. The limit
/// is therefore expressed in whole display units and converted against
/// the mint's own decimals at check time.
pub struct TokenPolicy {
    pub max_ui_amount: u64,
}

impl TokenPolicy {
    /// Key: `max_token_ui_amount` (whole tokens, integer).
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let max_ui_amount = section
            .get("max_token_ui_amount")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_MAX_TOKEN_UI_AMOUNT);
        Self { max_ui_amount }
    }

    /// Enforce the ceiling against an amount in the mint's base units.
    pub fn check(&self, base_units: u64, decimals: u8) -> Result<(), String> {
        let ceiling = (self.max_ui_amount as u128)
            .saturating_mul(10u128.saturating_pow(decimals as u32));
        if base_units as u128 > ceiling {
            return Err(format!(
                "transfer of {base_units} base units exceeds the configured ceiling of {} whole tokens; the operator can raise it via the max_token_ui_amount config key",
                self.max_ui_amount
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_section_yields_defaults() {
        let cfg = RpcConfig::from_section(&HashMap::new());
        assert_eq!(cfg.url, DEFAULT_RPC_URL);
        assert_eq!(cfg.timeout_secs, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn explicit_values_win() {
        let section = HashMap::from([
            ("rpc_url".to_string(), "https://example.com/rpc".to_string()),
            ("timeout_secs".to_string(), "30".to_string()),
        ]);
        let cfg = RpcConfig::from_section(&section);
        assert_eq!(cfg.url, "https://example.com/rpc");
        assert_eq!(cfg.timeout_secs, 30);
    }

    #[test]
    fn garbage_timeout_falls_back() {
        let section = HashMap::from([
            ("timeout_secs".to_string(), "soon".to_string()),
        ]);
        let cfg = RpcConfig::from_section(&section);
        assert_eq!(cfg.timeout_secs, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn blank_url_falls_back() {
        let section = HashMap::from([("rpc_url".to_string(), "  ".to_string())]);
        let cfg = RpcConfig::from_section(&section);
        assert_eq!(cfg.url, DEFAULT_RPC_URL);
    }

    #[test]
    fn transfer_policy_defaults_and_enforces() {
        let policy = TransferPolicy::from_section(&HashMap::new());
        assert_eq!(policy.max_lamports, DEFAULT_MAX_LAMPORTS);
        assert!(policy.check(DEFAULT_MAX_LAMPORTS).is_ok());
        let err = policy.check(DEFAULT_MAX_LAMPORTS + 1).unwrap_err();
        assert!(err.contains("max_lamports"));
    }

    #[test]
    fn transfer_policy_reads_override() {
        let section = HashMap::from([("max_lamports".to_string(), "5000000000".to_string())]);
        let policy = TransferPolicy::from_section(&section);
        assert_eq!(policy.max_lamports, 5_000_000_000);
        assert!(policy.check(1_000_000_000).is_ok());
    }

    #[test]
    fn jupiter_defaults_and_overrides() {
        let cfg = JupiterConfig::from_section(&HashMap::new());
        assert_eq!(cfg.base_url, DEFAULT_JUPITER_BASE_URL);
        assert_eq!(cfg.default_slippage_bps, DEFAULT_SLIPPAGE_BPS);

        let section = HashMap::from([
            ("jupiter_base_url".to_string(), "https://api.jup.ag".to_string()),
            ("default_slippage_bps".to_string(), "100".to_string()),
        ]);
        let cfg = JupiterConfig::from_section(&section);
        assert_eq!(cfg.base_url, "https://api.jup.ag");
        assert_eq!(cfg.default_slippage_bps, 100);
    }

    #[test]
    fn nonsense_slippage_falls_back() {
        for bad in ["0", "20000", "lots"] {
            let section = HashMap::from([("default_slippage_bps".to_string(), bad.to_string())]);
            assert_eq!(
                JupiterConfig::from_section(&section).default_slippage_bps,
                DEFAULT_SLIPPAGE_BPS
            );
        }
    }

    #[test]
    fn token_policy_scales_with_decimals() {
        let policy = TokenPolicy::from_section(&HashMap::new());
        assert_eq!(policy.max_ui_amount, DEFAULT_MAX_TOKEN_UI_AMOUNT);
        // 100 USDC at 6 decimals is exactly the ceiling.
        assert!(policy.check(100_000_000, 6).is_ok());
        assert!(policy.check(100_000_001, 6).is_err());
        // The same ceiling in a 9 decimal mint is a different raw number.
        assert!(policy.check(100_000_000_000, 9).is_ok());
        assert!(policy.check(100_000_000_001, 9).is_err());
    }

    #[test]
    fn token_policy_override_and_fallback() {
        let section = HashMap::from([("max_token_ui_amount".to_string(), "5".to_string())]);
        assert_eq!(TokenPolicy::from_section(&section).max_ui_amount, 5);
        for bad in ["0", "-3", "many"] {
            let section = HashMap::from([("max_token_ui_amount".to_string(), bad.to_string())]);
            assert_eq!(
                TokenPolicy::from_section(&section).max_ui_amount,
                DEFAULT_MAX_TOKEN_UI_AMOUNT
            );
        }
    }

    #[test]
    fn token_policy_survives_absurd_decimals() {
        let policy = TokenPolicy::from_section(&HashMap::new());
        // Must saturate rather than overflow.
        assert!(policy.check(u64::MAX, 255).is_ok());
    }
}
