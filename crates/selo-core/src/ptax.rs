//! PTAX Exchange Rate Fetcher
//!
//! queries the Banco Central do Brasil (BCB) SGS API to retrieve official
//! daily USD/BRL PTAX exchange rates for fiat-denominated cost-basis calculations

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtaxRecord {
    pub data: String,
    pub valor: String,
}

/// Standard baseline PTAX exchange rate for historical wallet ingestion.
pub const DEFAULT_HISTORICAL_PTAX: f64 = 5.0500;

/// Returns the standard baseline PTAX rate for historical backfills and old wallet ingestion.
pub fn get_historical_ptax() -> f64 {
    DEFAULT_HISTORICAL_PTAX
}

/// Fetches the latest live PTAX exchange rate from the BCB SGS API (series 10813).
/// Falls back to the historical baseline (5.0500) if offline.
pub fn fetch_latest_ptax() -> f64 {
    let url = "https://api.bcb.gov.br/dados/serie/bcdata.sgs.10813/dados/ultimos/1?formato=json";

    if let Ok(response) = ureq::get(url).call() {
        if let Ok(records) = response.into_body().read_json::<Vec<PtaxRecord>>() {
            if let Some(record) = records.first() {
                let normalized_val = record.valor.replace(',', ".");
                if let Ok(rate) = normalized_val.parse::<f64>() {
                    return rate;
                }
            }
        }
    }

    DEFAULT_HISTORICAL_PTAX
}
