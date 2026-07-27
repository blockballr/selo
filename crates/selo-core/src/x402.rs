//! x402 agent payments on Solana: the `exact` scheme.
//!
//! Parses and validates the server's `402` requirements, selects a payable
//! option, and encodes the `X-PAYMENT` envelope. Building and signing the
//! transaction is deliberately elsewhere; see the note at the foot.
//!
//! Field names follow `specs/schemes/exact/scheme_exact_svm.md`.

use serde::Deserialize;

/// The version the `X-PAYMENT` envelope advertises. The SVM exact scheme is
/// defined under x402 version 1.
pub const X402_VERSION: u32 = 1;

/// A single payment option from a `402` response's `accepts` array.
///
/// Only the fields the client needs to build and price the transfer are
/// modelled; unknown fields are ignored so a server adding metadata does not
/// break parsing.
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentRequirements {
    /// Payment scheme. Only `"exact"` is handled here.
    pub scheme: String,
    /// CAIP-2 network id, e.g. `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`
    /// (mainnet genesis hash). Used to refuse options for another chain.
    pub network: String,
    /// Token amount in base units, as a decimal string. A string because the
    /// value can exceed what a JSON number represents exactly.
    #[serde(rename = "maxAmountRequired", alias = "amount")]
    pub amount: String,
    /// SPL token mint the payment must be denominated in.
    pub asset: String,
    /// The server's wallet: the recipient of the transfer.
    #[serde(rename = "payTo")]
    pub pay_to: String,
    /// How long the server will wait for settlement, in seconds.
    #[serde(rename = "maxTimeoutSeconds", default)]
    pub max_timeout_seconds: Option<u64>,
    /// Scheme-specific extras. For SVM exact this carries the fee payer.
    #[serde(default)]
    pub extra: Option<PaymentExtra>,
}

/// The `extra` object of an SVM exact requirement.
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentExtra {
    /// Public key of the account that pays the transaction fee, typically the
    /// facilitator. It MUST NOT appear in any instruction's account list, so
    /// that the fee payer cannot be made to fund the transfer itself.
    #[serde(rename = "feePayer")]
    pub fee_payer: Option<String>,
    /// Optional seller reference string, at most 256 bytes, emitted as a memo.
    #[serde(default)]
    pub memo: Option<String>,
}

/// The whole body of a `402` response we care about.
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentRequired {
    #[serde(default)]
    pub accepts: Vec<PaymentRequirements>,
}

impl PaymentRequirements {
    /// The parsed base-unit amount. Kept as a string on the wire; validated
    /// here so a malformed amount is caught before a transaction is built.
    pub fn amount_base_units(&self) -> Result<u64, String> {
        self.amount
            .parse::<u64>()
            .map_err(|_| format!("payment amount is not a base-unit integer: {:?}", self.amount))
    }

    /// The fee payer the transaction must use, or an error if the server did
    /// not name one. The exact scheme requires it.
    pub fn fee_payer(&self) -> Result<&str, String> {
        self.extra
            .as_ref()
            .and_then(|e| e.fee_payer.as_deref())
            .filter(|f| !f.is_empty())
            .ok_or_else(|| "exact-scheme requirement is missing extra.feePayer".to_string())
    }

    /// The optional memo, trimmed of nothing (memos are byte-exact), rejected
    /// if it exceeds the 256-byte ceiling the scheme sets.
    pub fn memo(&self) -> Result<Option<&str>, String> {
        match self.extra.as_ref().and_then(|e| e.memo.as_deref()) {
            Some(m) if m.len() > 256 => Err(format!(
                "memo exceeds the 256-byte scheme limit ({} bytes)",
                m.len()
            )),
            other => Ok(other),
        }
    }
}

/// Parse a `402` body and choose the option this client can pay.
///
/// A payable option is `exact` scheme, on the requested `network`, and in
/// `asset` when given. First match wins, matching how servers order
/// `accepts` by preference, so this never silently pays in another token.
pub fn select_exact(
    body: &str,
    network: &str,
    asset: Option<&str>,
) -> Result<PaymentRequirements, String> {
    let parsed: PaymentRequired = serde_json::from_str(body)
        .map_err(|e| format!("402 body is not valid payment-required JSON: {e}"))?;
    if parsed.accepts.is_empty() {
        return Err("402 response carried no payment options".to_string());
    }
    parsed
        .accepts
        .into_iter()
        .find(|r| {
            r.scheme == "exact"
                && r.network == network
                && asset.is_none_or(|a| r.asset == a)
        })
        .ok_or_else(|| {
            match asset {
                Some(a) => format!(
                    "no exact-scheme option on {network} paying in {a}; the server may want a \
                     different token or chain"
                ),
                None => format!("no exact-scheme option on {network}"),
            }
        })
}

/// Build the value of the `X-PAYMENT` request header.
///
/// The header is the base64 of a JSON envelope wrapping the base64
/// partially-signed transaction. Two layers of base64 are intentional: the
/// inner one is the scheme's transaction encoding, the outer one lets the
/// whole JSON envelope ride in a single header line.
pub fn encode_x_payment_header(
    scheme: &str,
    network: &str,
    transaction_base64: &str,
) -> String {
    use base64::Engine;
    let envelope = serde_json::json!({
        "x402Version": X402_VERSION,
        "scheme": scheme,
        "network": network,
        "payload": { "transaction": transaction_base64 },
    });
    base64::engine::general_purpose::STANDARD.encode(envelope.to_string().as_bytes())
}

// Design note: build_payment_transaction (next increment)
// ------------------------------------------------------
// Composes a v0 (versioned) message with a FOREIGN fee payer and returns the
// base64 partially-signed transaction plus the string to sign. Unlike
// `vtx::verify_and_sign`, which refuses any fee payer that is not our wallet,
// the exact scheme requires `extra.feePayer` (the facilitator) at account
// index 0. The message therefore declares two required signatures, the
// facilitator at slot 0 and our token owner at its slot; we sign only our
// slot and leave the facilitator's 64 bytes zero. Instruction layout is
// fixed by the spec: ComputeBudget SetComputeUnitLimit, SetComputeUnitPrice
// (both from `priority`), then SPL TransferChecked (from `token`), with the
// fee payer absent from every instruction's account list. Correctness will
// be checked by simulating the assembled bytes on mainnet with the
// facilitator signature stubbed, exactly as the swap-execute signing path was
// verified, rather than by asserting against a captured fixture.

#[cfg(test)]
mod tests {
    use super::*;

    const MAINNET: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn body() -> String {
        serde_json::json!({
            "accepts": [
                {
                    "scheme": "exact",
                    "network": MAINNET,
                    "maxAmountRequired": "1000000",
                    "asset": USDC,
                    "payTo": "3XMrhbv2r3 K",
                    "maxTimeoutSeconds": 60,
                    "extra": { "feePayer": "FAciLitAtoR11111111111111111111111111111111", "memo": "order-42" }
                }
            ]
        })
        .to_string()
    }

    #[test]
    fn selects_matching_exact_option() {
        let r = select_exact(&body(), MAINNET, Some(USDC)).unwrap();
        assert_eq!(r.scheme, "exact");
        assert_eq!(r.amount_base_units().unwrap(), 1_000_000);
        assert_eq!(r.fee_payer().unwrap(), "FAciLitAtoR11111111111111111111111111111111");
        assert_eq!(r.memo().unwrap(), Some("order-42"));
    }

    #[test]
    fn refuses_wrong_asset() {
        let err = select_exact(&body(), MAINNET, Some("So11111111111111111111111111111111111111112"))
            .unwrap_err();
        assert!(err.contains("different token"), "{err}");
    }

    #[test]
    fn refuses_wrong_network() {
        let err = select_exact(&body(), "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Some(USDC))
            .unwrap_err();
        assert!(err.contains("no exact-scheme option"), "{err}");
    }

    #[test]
    fn missing_fee_payer_is_an_error() {
        let b = serde_json::json!({
            "accepts": [{
                "scheme": "exact", "network": MAINNET, "maxAmountRequired": "5",
                "asset": USDC, "payTo": "x"
            }]
        })
        .to_string();
        let r = select_exact(&b, MAINNET, Some(USDC)).unwrap();
        assert!(r.fee_payer().is_err());
    }

    #[test]
    fn rejects_oversized_memo() {
        let big = "m".repeat(257);
        let b = serde_json::json!({
            "accepts": [{
                "scheme": "exact", "network": MAINNET, "maxAmountRequired": "5",
                "asset": USDC, "payTo": "x",
                "extra": { "feePayer": "F", "memo": big }
            }]
        })
        .to_string();
        let r = select_exact(&b, MAINNET, Some(USDC)).unwrap();
        assert!(r.memo().is_err());
    }

    #[test]
    fn empty_accepts_is_an_error() {
        let err = select_exact(r#"{"accepts":[]}"#, MAINNET, None).unwrap_err();
        assert!(err.contains("no payment options"), "{err}");
    }

    #[test]
    fn non_integer_amount_rejected() {
        let b = serde_json::json!({
            "accepts": [{
                "scheme": "exact", "network": MAINNET, "maxAmountRequired": "1.5",
                "asset": USDC, "payTo": "x", "extra": { "feePayer": "F" }
            }]
        })
        .to_string();
        let r = select_exact(&b, MAINNET, Some(USDC)).unwrap();
        assert!(r.amount_base_units().is_err());
    }

    #[test]
    fn x_payment_header_is_base64_json_envelope() {
        use base64::Engine;
        let header = encode_x_payment_header("exact", MAINNET, "QUJD");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(header.as_bytes())
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(v["x402Version"], X402_VERSION);
        assert_eq!(v["scheme"], "exact");
        assert_eq!(v["network"], MAINNET);
        assert_eq!(v["payload"]["transaction"], "QUJD");
    }
}
