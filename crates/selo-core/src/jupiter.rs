//! Jupiter API request building and response parsing.
//!
//! Two endpoints on the free `lite-api.jup.ag` host, both verified
//! against live responses: the v3 price endpoint, which returns a map
//! keyed by mint, and the v1 swap quote endpoint, which returns the
//! routed amounts plus the AMMs the route crosses. Quoting only; this
//! module never builds a swap transaction and nothing here can spend.

use serde_json::Value;

/// Well-known mints, so a tool can accept "SOL" or "USDC" instead of
/// requiring the user to paste a base58 mint address.
pub const KNOWN_MINTS: &[(&str, &str, u8)] = &[
    ("SOL", "So11111111111111111111111111111111111111112", 9),
    ("WSOL", "So11111111111111111111111111111111111111112", 9),
    ("USDC", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", 6),
    ("USDT", "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", 6),
    ("JUP", "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN", 6),
    ("BONK", "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", 5),
    ("JITOSOL", "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn", 9),
];

/// Resolve a user-supplied token reference to a mint address. Accepts a
/// known symbol (case insensitive) or a base58 mint passed through.
pub fn resolve_mint(token: &str) -> Result<String, String> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err("token is empty".to_string());
    }
    for (symbol, mint, _) in KNOWN_MINTS {
        if trimmed.eq_ignore_ascii_case(symbol) {
            return Ok((*mint).to_string());
        }
    }
    crate::address::validate_pubkey(trimmed).map_err(|e| {
        format!(
            "'{trimmed}' is not a known token symbol and not a valid mint address: {e}"
        )
    })
}

/// Decimals for a known symbol or mint, when the caller needs to convert
/// a human amount into base units before quoting.
pub fn known_decimals(token: &str) -> Option<u8> {
    let trimmed = token.trim();
    KNOWN_MINTS
        .iter()
        .find(|(symbol, mint, _)| trimmed.eq_ignore_ascii_case(symbol) || trimmed == *mint)
        .map(|(_, _, decimals)| *decimals)
}

/// One token's price data from the v3 price endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenPrice {
    pub mint: String,
    pub usd_price: f64,
    pub decimals: u8,
    pub price_change_24h: Option<f64>,
    pub liquidity: Option<f64>,
}

/// Build the price endpoint URL for one or more mints.
pub fn price_url(base: &str, mints: &[String]) -> String {
    format!("{}/price/v3?ids={}", base.trim_end_matches('/'), mints.join(","))
}

/// Parse the price response, a JSON object keyed by mint address. Mints
/// Jupiter does not know are simply absent from the map rather than
/// being errors, so the caller reports them as unpriced.
pub fn parse_prices(body: &str) -> Result<Vec<TokenPrice>, String> {
    let value: Value = serde_json::from_str(body)
        .map_err(|e| format!("Jupiter price response is not JSON: {e}"))?;
    if let Some(err) = value.get("error").and_then(Value::as_str) {
        return Err(format!("Jupiter price API error: {err}"));
    }
    let map = value
        .as_object()
        .ok_or_else(|| "Jupiter price response is not a JSON object".to_string())?;

    let mut prices = Vec::with_capacity(map.len());
    for (mint, entry) in map {
        let usd_price = match entry.get("usdPrice").and_then(Value::as_f64) {
            Some(p) => p,
            None => continue,
        };
        prices.push(TokenPrice {
            mint: mint.clone(),
            usd_price,
            decimals: entry.get("decimals").and_then(Value::as_u64).unwrap_or(0) as u8,
            price_change_24h: entry.get("priceChange24h").and_then(Value::as_f64),
            liquidity: entry.get("liquidity").and_then(Value::as_f64),
        });
    }
    prices.sort_by(|a, b| a.mint.cmp(&b.mint));
    Ok(prices)
}

/// A routed swap quote.
#[derive(Debug, Clone)]
pub struct SwapQuote {
    pub input_mint: String,
    pub output_mint: String,
    pub in_amount: String,
    pub out_amount: String,
    /// Worst-case output after slippage tolerance.
    pub min_out_amount: String,
    pub slippage_bps: u64,
    pub price_impact_pct: Option<f64>,
    pub usd_value: Option<f64>,
    /// AMM labels the route crosses, in order.
    pub route_labels: Vec<String>,
}

/// Build the swap quote URL. `amount` is in the input mint's base units.
pub fn quote_url(
    base: &str,
    input_mint: &str,
    output_mint: &str,
    amount: u64,
    slippage_bps: u64,
) -> String {
    format!(
        "{}/swap/v1/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}",
        base.trim_end_matches('/'),
        input_mint,
        output_mint,
        amount,
        slippage_bps
    )
}

/// Parse a swap quote response.
pub fn parse_quote(body: &str) -> Result<SwapQuote, String> {
    let value: Value = serde_json::from_str(body)
        .map_err(|e| format!("Jupiter quote response is not JSON: {e}"))?;
    // Jupiter reports "no route" and bad input as an error field rather
    // than an HTTP failure, so surface it as the model-facing reason.
    if let Some(err) = value.get("error").and_then(Value::as_str) {
        return Err(format!("Jupiter could not quote this swap: {err}"));
    }

    let field = |name: &str| -> Result<String, String> {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("Jupiter quote response missing {name}"))
    };

    let route_labels = value
        .get("routePlan")
        .and_then(Value::as_array)
        .map(|steps| {
            steps
                .iter()
                .filter_map(|s| {
                    s.pointer("/swapInfo/label")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(SwapQuote {
        input_mint: field("inputMint")?,
        output_mint: field("outputMint")?,
        in_amount: field("inAmount")?,
        out_amount: field("outAmount")?,
        min_out_amount: field("otherAmountThreshold").unwrap_or_default(),
        slippage_bps: value.get("slippageBps").and_then(Value::as_u64).unwrap_or(0),
        // These arrive as JSON strings, not numbers.
        price_impact_pct: value
            .get("priceImpactPct")
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok()),
        usd_value: value
            .get("swapUsdValue")
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok()),
        route_labels,
    })
}

/// The transaction Jupiter builds for a quote, plus what it tells us
/// about how it will behave.
#[derive(Debug, Clone)]
pub struct SwapTransaction {
    /// Base64 serialized v0 transaction, unsigned.
    pub transaction_base64: String,
    pub last_valid_block_height: Option<u64>,
    pub prioritization_fee_lamports: Option<u64>,
    pub compute_unit_limit: Option<u64>,
}

/// URL for the swap build endpoint.
pub fn swap_url(base: &str) -> String {
    format!("{}/swap/v1/swap", base.trim_end_matches('/'))
}

/// Build the swap request body.
///
/// The quote must be passed back verbatim as Jupiter returned it. Any
/// edit would either be rejected or, worse, silently produce a route
/// that is not the one that was quoted, so the raw text is embedded
/// rather than a reconstruction from parsed fields.
pub fn swap_request_body(raw_quote_json: &str, user_pubkey: &str) -> Result<String, String> {
    let quote: Value = serde_json::from_str(raw_quote_json)
        .map_err(|e| format!("stored quote is not valid JSON: {e}"))?;
    let user = crate::address::validate_pubkey(user_pubkey)?;
    Ok(serde_json::json!({
        "quoteResponse": quote,
        "userPublicKey": user,
        // Lets a SOL swap work without the caller managing wrapped SOL.
        "wrapAndUnwrapSol": true,
    })
    .to_string())
}

/// Parse the swap build response.
///
/// Jupiter simulates the transaction before returning it, so a
/// non-empty `simulationError` is a refusal: the swap would fail if
/// submitted, and sending it would only burn a fee.
pub fn parse_swap_response(body: &str) -> Result<SwapTransaction, String> {
    let value: Value = serde_json::from_str(body)
        .map_err(|e| format!("Jupiter swap response is not JSON: {e}"))?;
    if let Some(err) = value.get("error").and_then(Value::as_str) {
        return Err(format!("Jupiter could not build this swap: {err}"));
    }
    match value.get("simulationError") {
        None | Some(Value::Null) => {}
        Some(e) => {
            let detail = e
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| e.to_string());
            return Err(format!("Jupiter simulated this swap and it would fail: {detail}"));
        }
    }
    let transaction_base64 = value
        .get("swapTransaction")
        .and_then(Value::as_str)
        .ok_or_else(|| "Jupiter swap response has no swapTransaction".to_string())?
        .to_string();
    Ok(SwapTransaction {
        transaction_base64,
        last_valid_block_height: value.get("lastValidBlockHeight").and_then(Value::as_u64),
        prioritization_fee_lamports: value
            .get("prioritizationFeeLamports")
            .and_then(Value::as_u64),
        compute_unit_limit: value.get("computeUnitLimit").and_then(Value::as_u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOL_MINT: &str = "So11111111111111111111111111111111111111112";
    const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    #[test]
    fn resolves_symbols_case_insensitively() {
        assert_eq!(resolve_mint("SOL").unwrap(), SOL_MINT);
        assert_eq!(resolve_mint("sol").unwrap(), SOL_MINT);
        assert_eq!(resolve_mint(" usdc ").unwrap(), USDC_MINT);
    }

    #[test]
    fn passes_through_raw_mints() {
        assert_eq!(resolve_mint(USDC_MINT).unwrap(), USDC_MINT);
    }

    #[test]
    fn rejects_unknown_garbage() {
        let err = resolve_mint("notatoken!").unwrap_err();
        assert!(err.contains("not a known token symbol"));
    }

    #[test]
    fn decimals_lookup() {
        assert_eq!(known_decimals("SOL"), Some(9));
        assert_eq!(known_decimals(USDC_MINT), Some(6));
        assert_eq!(known_decimals("nope"), None);
    }

    #[test]
    fn builds_urls() {
        let url = price_url("https://lite-api.jup.ag", &[SOL_MINT.to_string()]);
        assert_eq!(url, format!("https://lite-api.jup.ag/price/v3?ids={SOL_MINT}"));
        // A trailing slash on the configured base must not double up.
        let url = price_url("https://lite-api.jup.ag/", &[SOL_MINT.to_string()]);
        assert!(url.starts_with("https://lite-api.jup.ag/price/v3"));

        let q = quote_url("https://lite-api.jup.ag", SOL_MINT, USDC_MINT, 100_000_000, 50);
        assert!(q.contains("inputMint=So1111"));
        assert!(q.contains("amount=100000000"));
        assert!(q.contains("slippageBps=50"));
    }

    // Captured from a live lite-api.jup.ag response.
    const PRICE_BODY: &str = r#"{"So11111111111111111111111111111111111111112":{
        "createdAt":"2024-06-05T08:55:25.527Z","liquidity":664519635.45,
        "usdPrice":77.48839495211013,"blockId":434629553,"decimals":9,
        "priceChange24h":-0.9783456433451198}}"#;

    #[test]
    fn parses_price() {
        let prices = parse_prices(PRICE_BODY).unwrap();
        assert_eq!(prices.len(), 1);
        assert_eq!(prices[0].mint, SOL_MINT);
        assert!((prices[0].usd_price - 77.488394).abs() < 0.001);
        assert_eq!(prices[0].decimals, 9);
        assert!(prices[0].price_change_24h.unwrap() < 0.0);
    }

    #[test]
    fn unknown_mint_is_absent_not_error() {
        let prices = parse_prices("{}").unwrap();
        assert!(prices.is_empty());
    }

    #[test]
    fn price_entry_without_usdprice_is_skipped() {
        let body = r#"{"SomeMint":{"decimals":6}}"#;
        assert!(parse_prices(body).unwrap().is_empty());
    }

    #[test]
    fn swap_request_embeds_quote_verbatim() {
        let quote = r#"{"inputMint":"a","outAmount":"5","routePlan":[{"x":1}]}"#;
        let body = swap_request_body(quote, USDC_MINT).unwrap();
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["userPublicKey"], USDC_MINT);
        assert_eq!(v["wrapAndUnwrapSol"], true);
        // The quote is nested whole, not flattened or rebuilt.
        assert_eq!(v["quoteResponse"]["outAmount"], "5");
        assert_eq!(v["quoteResponse"]["routePlan"][0]["x"], 1);
    }

    #[test]
    fn swap_request_rejects_bad_inputs() {
        assert!(swap_request_body("not json", USDC_MINT).is_err());
        assert!(swap_request_body("{}", "not-an-address").is_err());
    }

    #[test]
    fn parses_swap_response() {
        // Field shape captured from a live lite-api.jup.ag swap build.
        let body = r#"{"swapTransaction":"AQAAdGVzdA==","lastValidBlockHeight":434629999,
            "prioritizationFeeLamports":21000,"computeUnitLimit":190000,
            "simulationError":null}"#;
        let s = parse_swap_response(body).unwrap();
        assert_eq!(s.transaction_base64, "AQAAdGVzdA==");
        assert_eq!(s.last_valid_block_height, Some(434_629_999));
        assert_eq!(s.prioritization_fee_lamports, Some(21_000));
        assert_eq!(s.compute_unit_limit, Some(190_000));
    }

    #[test]
    fn refuses_when_jupiter_simulation_fails() {
        let body = r#"{"swapTransaction":"AQAA","simulationError":
            {"errorCode":"InsufficientFunds","error":"insufficient lamports"}}"#;
        let err = parse_swap_response(body).unwrap_err();
        assert!(err.contains("would fail"));
        assert!(err.contains("insufficient lamports"));
    }

    #[test]
    fn swap_response_without_transaction_errors() {
        assert!(parse_swap_response(r#"{"error":"no route"}"#).is_err());
        assert!(parse_swap_response("{}").is_err());
    }

    #[test]
    fn swap_url_normalizes_trailing_slash() {
        assert_eq!(
            swap_url("https://lite-api.jup.ag/"),
            "https://lite-api.jup.ag/swap/v1/swap"
        );
    }

    // Captured from a live lite-api.jup.ag quote response.
    const QUOTE_BODY: &str = r#"{"inputMint":"So11111111111111111111111111111111111111112",
        "inAmount":"100000000","outputMint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "outAmount":"7750169","otherAmountThreshold":"7711419","swapMode":"ExactIn",
        "slippageBps":50,"platformFee":null,"priceImpactPct":"0.0000261528137173428758",
        "routePlan":[{"swapInfo":{"ammKey":"8sKQ","label":"HumidiFi",
        "inputMint":"So11111111111111111111111111111111111111112",
        "outputMint":"EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "inAmount":"100000000","outAmount":"7750169"},"percent":100}],
        "contextSlot":434629560,"swapUsdValue":"7.749799375161330"}"#;

    #[test]
    fn parses_quote() {
        let q = parse_quote(QUOTE_BODY).unwrap();
        assert_eq!(q.in_amount, "100000000");
        assert_eq!(q.out_amount, "7750169");
        assert_eq!(q.min_out_amount, "7711419");
        assert_eq!(q.slippage_bps, 50);
        assert_eq!(q.route_labels, vec!["HumidiFi"]);
        assert!(q.price_impact_pct.unwrap() < 0.001);
        assert!((q.usd_value.unwrap() - 7.7498).abs() < 0.001);
    }

    #[test]
    fn quote_error_becomes_readable_message() {
        let body = r#"{"error":"Could not find any route"}"#;
        let err = parse_quote(body).unwrap_err();
        assert!(err.contains("Could not find any route"));
    }

    #[test]
    fn quote_missing_fields_errors() {
        assert!(parse_quote(r#"{"inputMint":"a"}"#).is_err());
    }
}
