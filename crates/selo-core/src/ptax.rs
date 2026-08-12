//! PTAX Exchange Rate resolution
//!
//! queries are never made here: this module resolves official Banco Central
//! do Brasil (BCB) USD/BRL PTAX exchange rates for fiat-denominated
//! cost-basis calculations through an injected [`FxRateSource`]. The core
//! keeps the retry-and-fallback policy and the SOL/BRL composition pure,
//! so it stays I/O-free; the transport lives in selo-tool.
//!
//! Two feeds feed cost basis:
//! - For stablecoins (USDC, USDT, PYUSD): `amount * PTAX_USD/BRL(T)`.
//! - For SOL: `SOL/USD(T) * PTAX_USD/BRL(T)`, the Jupiter and BCB rates
//!   combined at block time.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtaxRecord {
    pub data: String,
    pub valor: String,
}

/// Standard baseline PTAX exchange rate for historical wallet ingestion.
pub const DEFAULT_HISTORICAL_PTAX: f64 = 5.0500;

/// Standard baseline SOL/USD price for historical backfills when Jupiter is
/// unavailable and the operator has not supplied a custom price.
pub const DEFAULT_HISTORICAL_SOL_USD: f64 = 20.00;

/// A transport for official exchange-rate feeds.
///
/// Mirrors `RpcSeam`: core logic stays pure, the tool supplies the live
/// implementation. Every method returns `None` when the feed is unreachable
/// or the answer is implausible, and the resolve helpers decide how to fall
/// back. Tests inject a canned stub, so no test in this crate needs a
/// network connection.
pub trait FxRateSource {
    /// The BCB PTAX sell rate for one date, "YYYY-MM-DD". None on a
    /// weekend, holiday, implausible value, or transport failure.
    fn ptax_for_date(&self, date_ymd: &str) -> Option<f64>;
    /// The SOL/USD price for one date, "YYYY-MM-DD". None when the feed is
    /// unreachable or the price is implausible.
    fn sol_usd_for_date(&self, date_ymd: &str) -> Option<f64>;
    /// The latest live PTAX rate. None when the feed is unreachable.
    fn latest_ptax(&self) -> Option<f64>;
    /// The current live SOL/USD price. None when the feed is unreachable.
    fn latest_sol_usd(&self) -> Option<f64>;
}

/// A no-op source that always reports `None`, so callers fall back to the
/// historical constants. Useful for offline runs and tests that never want
/// a live number.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullFxRateSource;

impl FxRateSource for NullFxRateSource {
    fn ptax_for_date(&self, _date_ymd: &str) -> Option<f64> {
        None
    }
    fn sol_usd_for_date(&self, _date_ymd: &str) -> Option<f64> {
        None
    }
    fn latest_ptax(&self) -> Option<f64> {
        None
    }
    fn latest_sol_usd(&self) -> Option<f64> {
        None
    }
}

/// Returns the standard baseline PTAX rate for historical backfills and old wallet ingestion.
pub fn get_historical_ptax() -> f64 {
    DEFAULT_HISTORICAL_PTAX
}

// ---------------------------------------------------------------------------
// Date helpers (civil-date arithmetic, no external date library needed)
// ---------------------------------------------------------------------------

/// Convert a "YYYY-MM-DD" string to days since Unix epoch.
pub fn ymd_to_days(ymd: &str) -> Option<i64> {
    let mut parts = ymd.splitn(3, '-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if m < 1 || m > 12 || d < 1 || d > 31 {
        return None;
    }
    // Howard Hinnant civil-date: (year, month, day) -> days since 1970-01-01.
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m <= 2 { m + 9 } else { m - 3 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era as i64 * 146097 + doe as i64 - 719468;
    Some(days)
}

/// Convert days since Unix epoch to a "YYYY-MM-DD" string.
pub fn days_to_ymd(days: i64) -> String {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

/// Subtract `n` days from a "YYYY-MM-DD" date string.
pub fn ymd_minus_days(ymd: &str, n: i64) -> Option<String> {
    let days = ymd_to_days(ymd)?;
    Some(days_to_ymd(days - n))
}

/// Convert a Unix timestamp (seconds) to a compact "YYYY-MM-DD" string.
pub fn unix_to_ymd(unix_secs: i64) -> String {
    days_to_ymd(unix_secs.div_euclid(86_400))
}

/// Maximum plausible PTAX rate. Rates above this are treated as API errors.
pub const MAX_PLAUSIBLE_PTAX: f64 = 6.50;

// ---------------------------------------------------------------------------
// Resolution with retry and fallback (pure)
// ---------------------------------------------------------------------------

/// Resolve a date-specific PTAX rate, retrying previous business days.
///
/// Tries `date_ymd` first, then up to 3 prior days. Falls back to
/// `DEFAULT_HISTORICAL_PTAX` if every attempt returns `None`.
pub fn resolve_ptax_for_date<S: FxRateSource + ?Sized>(source: &S, date_ymd: &str) -> f64 {
    let mut current = date_ymd.to_string();
    for _ in 0..4 {
        if let Some(rate) = source.ptax_for_date(&current) {
            return rate;
        }
        current = match ymd_minus_days(&current, 1) {
            Some(d) => d,
            None => break,
        };
    }
    DEFAULT_HISTORICAL_PTAX
}

/// Resolve a date-specific SOL/USD price, retrying previous days.
///
/// Tries `date_ymd` first, then up to 2 prior days. Falls back to
/// `DEFAULT_HISTORICAL_SOL_USD` if every attempt returns `None`.
pub fn resolve_sol_usd_for_date<S: FxRateSource + ?Sized>(source: &S, date_ymd: &str) -> f64 {
    let mut current = date_ymd.to_string();
    for _ in 0..3 {
        if let Some(price) = source.sol_usd_for_date(&current) {
            return price;
        }
        current = match ymd_minus_days(&current, 1) {
            Some(d) => d,
            None => break,
        };
    }
    DEFAULT_HISTORICAL_SOL_USD
}

/// Fetches the current SOL/BRL price: SOL/USD from the source multiplied by
/// USD/BRL from the source. Falls back to historical defaults when either
/// feed is unreachable but the other succeeds.
///
/// Returns `(sol_brl_price, sol_usd_price, usd_brl_rate, is_live)` where
/// `is_live` is true only when both feeds responded successfully.
pub fn fetch_sol_brl_price<S: FxRateSource + ?Sized>(source: &S) -> (f64, f64, f64, bool) {
    let sol_usd = source.latest_sol_usd();
    let latest_ptax = source.latest_ptax();
    let ptax = latest_ptax.unwrap_or(DEFAULT_HISTORICAL_PTAX);
    let ptax_is_live = latest_ptax.is_some();
    let sol_is_live = sol_usd.is_some();

    let sol_usd = sol_usd.unwrap_or(DEFAULT_HISTORICAL_SOL_USD);
    let sol_brl = sol_usd * ptax;
    (sol_brl, sol_usd, ptax, sol_is_live && ptax_is_live)
}

// ---------------------------------------------------------------------------
// Composite cost basis
// ---------------------------------------------------------------------------

/// Resolve the unit cost basis in BRL for an acquisition on a given date.
///
/// For SOL: `SOL/USD * PTAX`. For stablecoins: just `PTAX`. Other tokens get
/// the stablecoin treatment (1:1 peg assumed) unless a specific mapping is
/// added later.
pub fn resolve_cost_basis_for_date<S: FxRateSource + ?Sized>(
    source: &S,
    asset_symbol: &str,
    date_ymd: &str,
) -> f64 {
    let ptax = resolve_ptax_for_date(source, date_ymd);
    match asset_symbol {
        "SOL" => {
            let sol_usd = resolve_sol_usd_for_date(source, date_ymd);
            sol_usd * ptax
        }
        _ => ptax,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canned source used by all offline tests. Never touches the network.
    #[derive(Debug, Default, Clone, Copy)]
    struct StubFxRateSource {
        ptax: Option<f64>,
        sol_usd: Option<f64>,
    }

    impl FxRateSource for StubFxRateSource {
        fn ptax_for_date(&self, _date_ymd: &str) -> Option<f64> {
            self.ptax
        }
        fn sol_usd_for_date(&self, _date_ymd: &str) -> Option<f64> {
            self.sol_usd
        }
        fn latest_ptax(&self) -> Option<f64> {
            self.ptax
        }
        fn latest_sol_usd(&self) -> Option<f64> {
            self.sol_usd
        }
    }

    #[test]
    fn ymd_date_roundtrip() {
        let original = "2024-03-15";
        let days = ymd_to_days(original).unwrap();
        let back = days_to_ymd(days);
        assert_eq!(original, back);
    }

    #[test]
    fn ymd_epoch_start() {
        // 1970-01-01 = day 0
        assert_eq!(ymd_to_days("1970-01-01").unwrap(), 0);
    }

    #[test]
    fn ymd_minus_one_day() {
        assert_eq!(
            ymd_minus_days("2024-03-01", 1).unwrap(),
            "2024-02-29" // 2024 is a leap year
        );
    }

    #[test]
    fn ymd_minus_across_year() {
        assert_eq!(
            ymd_minus_days("2024-01-01", 1).unwrap(),
            "2023-12-31"
        );
    }

    #[test]
    fn resolve_falls_back_to_default_when_source_is_null() {
        // A null source reports nothing, so resolution must land on the
        // documented historical constant rather than panicking or zero.
        let source = NullFxRateSource;
        assert_eq!(resolve_ptax_for_date(&source, "2024-06-15"), DEFAULT_HISTORICAL_PTAX);
        assert_eq!(resolve_sol_usd_for_date(&source, "2024-06-15"), DEFAULT_HISTORICAL_SOL_USD);
    }

    #[test]
    fn resolve_uses_live_rate_from_source() {
        let source = StubFxRateSource {
            ptax: Some(5.4321),
            sol_usd: Some(180.25),
        };
        assert_eq!(resolve_ptax_for_date(&source, "2024-06-15"), 5.4321);
        assert_eq!(resolve_sol_usd_for_date(&source, "2024-06-15"), 180.25);
    }

    #[test]
    fn cost_basis_stablecoin_is_ptax() {
        let source = StubFxRateSource {
            ptax: Some(5.4321),
            sol_usd: None,
        };
        let basis = resolve_cost_basis_for_date(&source, "USDC", "2024-06-15");
        assert_eq!(basis, 5.4321);
    }

    #[test]
    fn cost_basis_sol_combines_both_feeds() {
        let source = StubFxRateSource {
            ptax: Some(5.0),
            sol_usd: Some(200.0),
        };
        let basis = resolve_cost_basis_for_date(&source, "SOL", "2024-06-15");
        assert_eq!(basis, 1000.0);
    }

    #[test]
    fn sol_brl_fallbacks_when_feed_is_dead() {
        let source = StubFxRateSource {
            ptax: Some(5.5),
            sol_usd: None,
        };
        let (sol_brl, sol_usd, ptax, is_live) = fetch_sol_brl_price(&source);
        assert_eq!(ptax, 5.5);
        assert_eq!(sol_usd, DEFAULT_HISTORICAL_SOL_USD);
        assert!((sol_brl - 5.5 * DEFAULT_HISTORICAL_SOL_USD).abs() < 1e-9);
        assert!(!is_live, "a dead SOL feed must not report live");

        let null = NullFxRateSource;
        let (_, _, ptax, is_live) = fetch_sol_brl_price(&null);
        assert_eq!(ptax, DEFAULT_HISTORICAL_PTAX);
        assert!(!is_live);
    }

    #[test]
    fn sol_brl_reports_live_only_when_both_feeds_responded() {
        let source = StubFxRateSource {
            ptax: Some(5.2),
            sol_usd: Some(190.5),
        };
        let (sol_brl, sol_usd, ptax, is_live) = fetch_sol_brl_price(&source);
        assert_eq!(sol_brl, 190.5 * 5.2);
        assert_eq!(sol_usd, 190.5);
        assert_eq!(ptax, 5.2);
        assert!(is_live);
    }
}
