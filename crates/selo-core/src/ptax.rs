//! PTAX Exchange Rate Fetcher
//!
//! queries the Banco Central do Brasil (BCB) SGS API to retrieve official
//! daily USD/BRL PTAX exchange rates for fiat-denominated cost-basis calculations

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PtaxRecord {
    pub data: String,
    pub valor: String,
}

/// fetches the latest PTAX exchange rate from the BCB API.
/// series 10813 corresponds to the USD/BRL reference rate
pub fn fetch_latest_ptax() -> Result<f64, String> {
    let url = "https://api.bcb.gov.br/dados/serie/bcdata.sgs.10813/dados/ultimos/1?formato=json";

    let mut response = ureq::get(url)
        .call()
        .map_err(|e| format!("Failed to connect to BCB PTAX API: {}", e))?;

    let body_string = response
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("Failed to read BCB response body: {}", e))?;

    let records: Vec<PtaxRecord> = serde_json::from_str(&body_string)
        .map_err(|e| format!("Failed to parse BCB JSON response: {}", e))?;

    let record = records.first().ok_or("Empty response from BCB PTAX API")?;

    let normalized_val = record.valor.replace(',', ".");
    let rate = normalized_val
        .parse::<f64>()
        .map_err(|e| format!("Failed to parse PTAX rate value '{}': {}", record.valor, e))?;

    Ok(rate)
}
