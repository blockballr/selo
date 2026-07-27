//! Priority fees and compute budget instructions.
//!
//! Recent fee samples are mostly zero even on a busy network, because most
//! accounts are uncontended, so a median is useless as a recommendation.
//! This works from percentiles and reports the cost in SOL rather than in
//! micro-lamports per compute unit.

use serde_json::{json, Value};

use crate::address::validate_pubkey;
use crate::rpc::parse_result_value;

/// The ComputeBudget program, which is where both instructions below go.
pub const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";

/// `SetComputeUnitLimit` discriminant.
const IX_SET_UNIT_LIMIT: u8 = 2;
/// `SetComputeUnitPrice` discriminant.
const IX_SET_UNIT_PRICE: u8 = 3;

/// A plain SOL transfer measures about 150 compute units, but the
/// default limit assumed by the runtime is far higher. Requesting a
/// realistic limit is what makes the fee small, since cost scales with
/// the limit requested, not the units actually used.
pub const DEFAULT_TRANSFER_COMPUTE_UNITS: u32 = 1_000;

/// How badly the caller wants the transaction to land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    /// Willing to wait. 50th percentile.
    Low,
    /// Ordinary. 75th percentile.
    Normal,
    /// Wants it in the next block or two. 95th percentile.
    High,
}

impl Urgency {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Urgency::Low),
            "normal" | "" => Ok(Urgency::Normal),
            "high" => Ok(Urgency::High),
            other => Err(format!(
                "unknown urgency '{other}'; use low, normal, or high"
            )),
        }
    }

    fn percentile(self) -> f64 {
        match self {
            Urgency::Low => 50.0,
            Urgency::Normal => 75.0,
            Urgency::High => 95.0,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Urgency::Low => "low",
            Urgency::Normal => "normal",
            Urgency::High => "high",
        }
    }
}

/// A summary of the recent fee market for the accounts asked about.
#[derive(Debug, Clone)]
pub struct FeeEstimate {
    pub sample_count: usize,
    pub nonzero_count: usize,
    pub p50: u64,
    pub p75: u64,
    pub p95: u64,
    pub max: u64,
    /// Chosen price in micro-lamports per compute unit.
    pub recommended_micro_lamports: u64,
    pub urgency: Urgency,
    pub compute_units: u32,
}

impl FeeEstimate {
    /// What the priority fee actually costs, in lamports.
    ///
    /// The price is per compute unit in micro-lamports, so the total is
    /// price times units divided by a million, rounded up so the fee is
    /// never understated.
    pub fn total_lamports(&self) -> u64 {
        let total = (self.recommended_micro_lamports as u128)
            .saturating_mul(self.compute_units as u128);
        ((total + 999_999) / 1_000_000) as u64
    }
}

/// Build a `getRecentPrioritizationFees` request for the writable
/// accounts a transaction will touch. Fees are per account, so asking
/// about the accounts actually involved gives a far better estimate
/// than a global sample.
pub fn fees_request(accounts: &[String]) -> Result<String, String> {
    let mut validated = Vec::with_capacity(accounts.len());
    for a in accounts {
        validated.push(validate_pubkey(a)?);
    }
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getRecentPrioritizationFees",
        "params": [validated]
    })
    .to_string())
}

/// Percentile over a sorted slice, using nearest-rank.
fn percentile_of(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[index]
}

/// Parse the fee samples and produce a recommendation.
///
/// Percentiles over the non-zero samples when any exist. With most samples
/// at zero, a percentile over everything collapses to zero and recommends
/// not bidding during exactly the congestion it handles. All zero means the
/// network is genuinely idle and zero is honest.
pub fn parse_fees(
    body: &str,
    urgency: Urgency,
    compute_units: u32,
) -> Result<FeeEstimate, String> {
    let result = parse_result_value(body)?;
    let samples = result
        .as_array()
        .ok_or_else(|| "getRecentPrioritizationFees result is not an array".to_string())?;

    let mut all: Vec<u64> = samples
        .iter()
        .filter_map(|s| s.get("prioritizationFee").and_then(Value::as_u64))
        .collect();
    if all.is_empty() {
        return Err("no prioritization fee samples returned".to_string());
    }
    all.sort_unstable();
    let sample_count = all.len();
    let max = *all.last().unwrap_or(&0);

    let nonzero: Vec<u64> = all.iter().copied().filter(|&f| f > 0).collect();
    let nonzero_count = nonzero.len();
    let basis: &[u64] = if nonzero.is_empty() { &all } else { &nonzero };

    let p50 = percentile_of(basis, 50.0);
    let p75 = percentile_of(basis, 75.0);
    let p95 = percentile_of(basis, 95.0);
    let recommended_micro_lamports = percentile_of(basis, urgency.percentile());

    Ok(FeeEstimate {
        sample_count,
        nonzero_count,
        p50,
        p75,
        p95,
        max,
        recommended_micro_lamports,
        urgency,
        compute_units,
    })
}

/// Serialize a `SetComputeUnitLimit` instruction's data.
pub fn set_compute_unit_limit_data(units: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(5);
    data.push(IX_SET_UNIT_LIMIT);
    data.extend_from_slice(&units.to_le_bytes());
    data
}

/// Serialize a `SetComputeUnitPrice` instruction's data.
pub fn set_compute_unit_price_data(micro_lamports: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(9);
    data.push(IX_SET_UNIT_PRICE);
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn body_from(fees: &[u64]) -> String {
        let samples: Vec<Value> = fees
            .iter()
            .enumerate()
            .map(|(i, f)| json!({ "slot": 1000 + i, "prioritizationFee": f }))
            .collect();
        json!({ "jsonrpc": "2.0", "id": 1, "result": samples }).to_string()
    }

    #[test]
    fn request_validates_accounts() {
        let req = fees_request(&[MINT.to_string()]).unwrap();
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "getRecentPrioritizationFees");
        assert_eq!(v["params"][0][0], MINT);
        assert!(fees_request(&["nope!".to_string()]).is_err());
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let data = [1u64, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(percentile_of(&data, 50.0), 5);
        assert_eq!(percentile_of(&data, 75.0), 8);
        assert_eq!(percentile_of(&data, 95.0), 10);
        assert_eq!(percentile_of(&[], 50.0), 0);
    }

    #[test]
    fn zero_heavy_distribution_ignores_zeros() {
        // The shape actually seen on mainnet: mostly zero with a few
        // large outliers. A percentile over everything would be zero.
        let mut fees = vec![0u64; 135];
        fees.extend_from_slice(&[10_000, 20_000, 30_000, 40_000, 50_000,
                                 60_000, 70_000, 80_000, 90_000, 100_000,
                                 110_000, 120_000, 130_000, 140_000, 6_145_297]);
        let est = parse_fees(&body_from(&fees), Urgency::Normal, 1_000).unwrap();
        assert_eq!(est.sample_count, 150);
        assert_eq!(est.nonzero_count, 15);
        assert!(est.p50 > 0, "median of nonzero samples must not be zero");
        assert!(est.p95 >= est.p75);
        assert!(est.p75 >= est.p50);
        assert_eq!(est.max, 6_145_297);
    }

    #[test]
    fn all_zero_samples_recommend_zero() {
        let est = parse_fees(&body_from(&[0, 0, 0, 0]), Urgency::High, 1_000).unwrap();
        assert_eq!(est.nonzero_count, 0);
        assert_eq!(est.recommended_micro_lamports, 0);
        assert_eq!(est.total_lamports(), 0);
    }

    #[test]
    fn urgency_orders_recommendations() {
        let fees: Vec<u64> = (1..=100).collect();
        let body = body_from(&fees);
        let low = parse_fees(&body, Urgency::Low, 1_000).unwrap();
        let normal = parse_fees(&body, Urgency::Normal, 1_000).unwrap();
        let high = parse_fees(&body, Urgency::High, 1_000).unwrap();
        assert!(low.recommended_micro_lamports < normal.recommended_micro_lamports);
        assert!(normal.recommended_micro_lamports < high.recommended_micro_lamports);
    }

    #[test]
    fn cost_conversion_rounds_up() {
        let est = FeeEstimate {
            sample_count: 1,
            nonzero_count: 1,
            p50: 0,
            p75: 0,
            p95: 0,
            max: 0,
            recommended_micro_lamports: 1_000_000,
            urgency: Urgency::Normal,
            compute_units: 1_000,
        };
        // 1e6 micro-lamports per CU over 1000 CU is exactly 1000 lamports.
        assert_eq!(est.total_lamports(), 1_000);

        let tiny = FeeEstimate {
            recommended_micro_lamports: 1,
            compute_units: 1,
            ..est
        };
        // Never round a real fee down to nothing.
        assert_eq!(tiny.total_lamports(), 1);
    }

    #[test]
    fn urgency_parsing() {
        assert_eq!(Urgency::parse("high").unwrap(), Urgency::High);
        assert_eq!(Urgency::parse(" LOW ").unwrap(), Urgency::Low);
        assert_eq!(Urgency::parse("").unwrap(), Urgency::Normal);
        assert!(Urgency::parse("urgent").is_err());
    }

    #[test]
    fn compute_budget_instruction_data() {
        assert_eq!(set_compute_unit_limit_data(200_000), vec![2, 0x40, 0x0D, 0x03, 0x00]);
        let price = set_compute_unit_price_data(1_000);
        assert_eq!(price[0], 3);
        assert_eq!(&price[1..], &1_000u64.to_le_bytes());
    }

    #[test]
    fn empty_sample_set_is_an_error() {
        assert!(parse_fees(&body_from(&[]), Urgency::Normal, 1_000).is_err());
    }
}
