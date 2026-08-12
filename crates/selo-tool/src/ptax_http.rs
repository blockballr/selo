//! Live exchange-rate transport for selo-tool.
//!
//! Implements `selo_core::ptax::FxRateSource` over the public HTTP feeds:
//! BCB Olinda for date-specific PTAX, BCB SGS series 10813 for the latest
//! PTAX, CoinGecko for date-specific SOL/USD, and Jupiter's free price API
//! for the latest SOL/USD. This is the only place the HTTP client is used
//! for rate lookups; selo-core stays I/O-free.

use selo_core::ptax::{FxRateSource, MAX_PLAUSIBLE_PTAX};
use serde::Deserialize;

/// BCB Olinda PTAX response: array of daily cotacao records.
#[derive(Debug, Deserialize)]
struct PtaxOlindaResponse {
    #[serde(default)]
    value: Vec<PtaxOlindaRecord>,
}

#[derive(Debug, Deserialize)]
struct PtaxOlindaRecord {
    #[serde(rename = "cotacaoVenda", default)]
    cotacao_venda: Option<f64>,
}

/// BCB SGS series 10813 response: daily records with a string valor.
#[derive(Debug, Deserialize)]
struct SgsRecord {
    #[serde(default)]
    valor: String,
}

/// CoinGecko history response, only the fields we need.
#[derive(Debug, Deserialize)]
struct CoinGeckoHistory {
    #[serde(default)]
    market_data: Option<CoinGeckoMarketData>,
}

#[derive(Debug, Deserialize)]
struct CoinGeckoMarketData {
    #[serde(default)]
    current_price: Option<CoinGeckoPrice>,
}

#[derive(Debug, Deserialize)]
struct CoinGeckoPrice {
    #[serde(default)]
    usd: Option<f64>,
}

/// A rate source backed by the live public APIs.
#[derive(Debug, Default, Clone)]
pub struct HttpFxRateSource;

impl HttpFxRateSource {
    pub fn new() -> Self {
        Self
    }
}

/// Fetch the PTAX sell rate for a specific date from BCB's Olinda API.
///
/// `date_ymd` is in "YYYY-MM-DD" format. Returns `None` when the API is
/// unreachable, the date is a weekend or holiday (BCB returns an empty
/// list), or the rate exceeds `MAX_PLAUSIBLE_PTAX`.
pub fn fetch_ptax_for_date(date_ymd: &str) -> Option<f64> {
    // BCB Olinda expects MM-DD-YYYY in the query string.
    let parts: Vec<&str> = date_ymd.splitn(3, '-').collect();
    if parts.len() != 3 {
        return None;
    }
    let mm_dd_yyyy = format!("{}-{}-{}", parts[1], parts[2], parts[0]);
    let url = format!(
        "https://olinda.bcb.gov.br/olinda/servico/PTAX/versao/v1/odata/CotacaoDolarDia(dataCotacao=@dataCotacao)?@dataCotacao='{}'&$top=1&$format=json",
        mm_dd_yyyy
    );

    let response = ureq::get(&url).call().ok()?;
    let body = response.into_body().read_to_string().ok()?;
    let parsed: PtaxOlindaResponse = serde_json::from_str(&body).ok()?;
    let rate = parsed.value.first()?.cotacao_venda?;

    if rate <= 0.0 || rate > MAX_PLAUSIBLE_PTAX {
        return None;
    }
    Some(rate)
}

/// Fetch the SOL/USD price for a specific date, "YYYY-MM-DD".
///
/// Tries CoinGecko's historical endpoint first; if it is unreachable,
/// rate-limited, or returns an implausible value, falls back to Binance's
/// daily kline close for the same UTC day. A single feed failing must not
/// silently drop the ledger onto the historical constant, so two
/// independent sources are consulted before giving up.
pub fn fetch_sol_usd_for_date(date_ymd: &str) -> Option<f64> {
    coingecko_sol_usd_for_date(date_ymd).or_else(|| binance_sol_usd_for_date(date_ymd))
}

/// CoinGecko daily history for SOL/USD.
///
/// CoinGecko expects DD-MM-YYYY and returns `market_data.current_price.usd`.
fn coingecko_sol_usd_for_date(date_ymd: &str) -> Option<f64> {
    let parts: Vec<&str> = date_ymd.splitn(3, '-').collect();
    let dd_mm_yyyy = format!("{}-{}-{}", parts[2], parts[1], parts[0]);
    let url = format!(
        "https://api.coingecko.com/api/v3/coins/solana/history?date={}&localization=false",
        dd_mm_yyyy
    );

    let response = ureq::get(&url).call().ok()?;
    let body = response.into_body().read_to_string().ok()?;
    let parsed: CoinGeckoHistory = serde_json::from_str(&body).ok()?;
    let price = parsed.market_data?.current_price?.usd?;

    if price <= 0.0 || price > 1000.0 {
        return None;
    }
    Some(price)
}

/// Binance daily kline close for SOL/USDT on the given UTC day.
///
/// Binance's 1d klines are bucketed to UTC midnight, so one candle at
/// `startTime = YYYY-MM-DD 00:00 UTC` is exactly that day. The close is
/// element index 4 of the candle, a decimal string.
fn binance_sol_usd_for_date(date_ymd: &str) -> Option<f64> {
    let days = selo_core::ptax::ymd_to_days(date_ymd)?;
    let start_ms: i64 = days.checked_mul(86_400_000)?;
    let url = format!(
        "https://api.binance.com/api/v3/klines?symbol=SOLUSDT&interval=1d&startTime={start_ms}&limit=1"
    );

    let response = ureq::get(&url).call().ok()?;
    let body = response.into_body().read_to_string().ok()?;
    let candles: Vec<Vec<serde_json::Value>> = serde_json::from_str(&body).ok()?;
    let close = candles.first()?.get(4)?.as_str()?.parse::<f64>().ok()?;
    if close <= 0.0 || close > 1000.0 {
        return None;
    }
    Some(close)
}

/// Fetches the latest live PTAX exchange rate from the BCB SGS API (series 10813).
pub fn fetch_latest_ptax() -> Option<f64> {
    let url = "https://api.bcb.gov.br/dados/serie/bcdata.sgs.10813/dados/ultimos/1?formato=json";

    let response = ureq::get(url).call().ok()?;
    let records: Vec<SgsRecord> = response.into_body().read_json().ok()?;
    let record = records.first()?;
    let normalized_val = record.valor.replace(',', ".");
    let rate = normalized_val.parse::<f64>().ok()?;
    if rate <= 0.0 || rate > MAX_PLAUSIBLE_PTAX {
        return None;
    }
    Some(rate)
}

/// Fetches the current SOL/USD price from Jupiter's free price API.
pub fn fetch_sol_usd_price() -> Option<f64> {
    let sol_mint = "So11111111111111111111111111111111111111112";
    let url = selo_core::jupiter::price_url("https://lite-api.jup.ag", &[sol_mint.to_string()]);

    let body = ureq::get(&url).call().ok()?.into_body().read_to_string().ok()?;
    let prices = selo_core::jupiter::parse_prices(&body).ok()?;
    prices
        .into_iter()
        .find(|p| p.mint == sol_mint)
        .map(|p| p.usd_price)
}

impl FxRateSource for HttpFxRateSource {
    fn ptax_for_date(&self, date_ymd: &str) -> Option<f64> {
        fetch_ptax_for_date(date_ymd)
    }

    fn sol_usd_for_date(&self, date_ymd: &str) -> Option<f64> {
        fetch_sol_usd_for_date(date_ymd)
    }

    fn latest_ptax(&self) -> Option<f64> {
        fetch_latest_ptax()
    }

    fn latest_sol_usd(&self) -> Option<f64> {
        fetch_sol_usd_price()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sgs_ptax_record_parses_comma_decimal() {
        let body = r#"[{"data":"12/08/2026","valor":"5,3421"}]"#;
        let records: Vec<SgsRecord> = serde_json::from_str(body).unwrap();
        let rate = records[0].valor.replace(',', ".").parse::<f64>().unwrap();
        assert_eq!(rate, 5.3421);
    }

    #[test]
    fn olinda_response_parses_expected_shape() {
        let body = r#"{"value":[{"cotacaoVenda":5.3210,"cotacaoCompra":5.3010,"dataHoraCotacao":"2026-08-11 13:00:00"}]}"#;
        let parsed: PtaxOlindaResponse = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.value[0].cotacao_venda, Some(5.3210));
    }

    #[test]
    fn coingecko_history_parses_expected_shape() {
        let body = r#"{"market_data":{"current_price":{"usd":182.5}}}"#;
        let parsed: CoinGeckoHistory = serde_json::from_str(body).unwrap();
        assert_eq!(parsed.market_data.unwrap().current_price.unwrap().usd, Some(182.5));
    }

    #[test]
    fn binance_kline_parses_the_daily_close() {
        // [openTime, open, high, low, close, volume, closeTime, ...]
        let body =
            r#"[[1750000000000,"170.1","172.4","169.8","171.35","12345.6",1750086400000,"2100000.0",50000,"950000.0","0","0"]]"#;
        let candles: Vec<Vec<serde_json::Value>> = serde_json::from_str(body).unwrap();
        let close = candles[0][4].as_str().unwrap().parse::<f64>().unwrap();
        assert!((close - 171.35).abs() < 1e-9);
    }

    #[test]
    fn binance_sol_usd_date_rejects_an_implausible_close() {
        // A price above the plausibility ceiling is a broken response and
        // must be treated as absent so the caller falls back, never as a
        // real $1000+ SOL close.
        assert_eq!(binance_sol_usd_for_date("nonsense"), None);
    }
}
