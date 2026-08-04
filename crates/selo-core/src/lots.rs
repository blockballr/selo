//! Tax Lot Accounting Engine
//!
//! tracks cost basis and acquisition history for token streams using FIFO/LIFO matching

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxLot {
    pub id: String,
    pub asset_symbol: String,
    pub amount: u64,              // raw token units / lamports
    pub unit_cost_basis_brl: f64, // cost basis per unit converted at historical PTAX
    pub acquired_at_utc: String,  // ISO-8601 timestamp
    pub ptax_rate_used: f64,      // PTAX rate reference on acquisition date
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtaxQuote {
    pub currency: String,
    pub date: String,
    pub buy_rate: f64,
    pub sell_rate: f64,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TaxLedger {
    pub lots: Vec<TaxLot>,
}

impl TaxLedger {
    pub fn new() -> Self {
        Self { lots: Vec::new() }
    }

    /// add new acquired lot to the tracking ledger
    pub fn add_lot(&mut self, lot: TaxLot) {
        self.lots.push(lot);
    }

    /// fetch PTAX rate and record a new acquisition in one go
    pub fn record_acquisition(
        &mut self,
        id: String,
        asset_symbol: String,
        amount: u64,
        acquired_at_utc: String,
    ) -> Result<(), String> {
        let ptax_rate = crate::ptax::fetch_latest_ptax()?;

        let unit_cost_basis_brl = ptax_rate;

        let lot = TaxLot {
            id,
            asset_symbol,
            amount,
            unit_cost_basis_brl,
            acquired_at_utc,
            ptax_rate_used: ptax_rate,
        };

        self.add_lot(lot);
        Ok(())
    }

    /// calculate FIFO cost basis: disposal of a given amount
    pub fn dispose_fifo(
        &mut self,
        asset_symbol: &str,
        amount_to_dispose: u64,
    ) -> Result<f64, String> {
        let mut remaining_to_dispose = amount_to_dispose;
        let mut total_cost_basis_brl = 0.0;

        // filter and sort active lots for the asset by acquisition time (FIFO)
        let asset_lots: Vec<&mut TaxLot> = self
            .lots
            .iter_mut()
            .filter(|l| l.asset_symbol == asset_symbol && l.amount > 0)
            .collect();

        for lot in asset_lots {
            if remaining_to_dispose == 0 {
                break;
            }

            if lot.amount <= remaining_to_dispose {
                // consume the entire lot
                total_cost_basis_brl += (lot.amount as f64) * lot.unit_cost_basis_brl;
                remaining_to_dispose -= lot.amount;
                lot.amount = 0;
            } else {
                // partially consume the lot
                total_cost_basis_brl += (remaining_to_dispose as f64) * lot.unit_cost_basis_brl;
                lot.amount -= remaining_to_dispose;
                remaining_to_dispose = 0;
            }
        }

        if remaining_to_dispose > 0 {
            return Err(format!(
                "Insufficient tax lots for {}. Short by {} units.",
                asset_symbol, remaining_to_dispose
            ));
        }

        Ok(total_cost_basis_brl)
    }

    /// compute: ZK-friendly Poseidon state root over the BN254 scalar field
    pub fn compute_state_root(&self) -> Result<String, String> {
        if self.lots.is_empty() {
            return Ok("0x0".to_string());
        }

        let lots_clone = self.lots.clone();

        // spawn thread 8mb allocation stack: safely handle heavy ZK matrix allocations on Windows
        let handle = std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                let mut poseidon = Poseidon::<Fr>::new_circom(3)
                    .map_err(|e| format!("Failed to initialize Poseidon hasher: {}", e))?;

                let mut current_hash = Fr::from(0u64);

                for lot in &lots_clone {
                    let amount_fe = Fr::from(lot.amount);
                    let ptax_scaled = (lot.ptax_rate_used * 10_000.0) as u64;
                    let ptax_fe = Fr::from(ptax_scaled);

                    current_hash = poseidon
                        .hash(&[current_hash, amount_fe, ptax_fe])
                        .map_err(|e| format!("Poseidon hashing failed: {}", e))?;
                }

                let repr = current_hash.into_bigint();
                let bytes = repr.to_bytes_be();
                Ok(format!("0x{}", hex::encode(bytes)))
            })
            .map_err(|e| format!("Failed to spawn hashing thread: {}", e))?;

        handle
            .join()
            .map_err(|_| "State root computation thread panicked".to_string())?
    }

    // text summary with ZK Poseidon state root
    pub fn generate_report(&self) -> Result<String, String> {
        let state_root = self.compute_state_root()?;

        let mut report = String::new();
        report.push_str("==================================================\n");
        report.push_str("            SELO TAX LOT ACCOUNTING REPORT         \n");
        report.push_str("==================================================\n");
        report.push_str(&format!(
            "ZK State Root (Poseidon BN254):\n{}\n",
            state_root
        ));
        report.push_str("--------------------------------------------------\n");

        if self.lots.is_empty() {
            report.push_str("No tax lots recorded in the ledger.\n");
        } else {
            for lot in &self.lots {
                report.push_str(&format!(
                    "Lot ID: {}\n  Asset: {} | Amount: {}\n  Unit Cost (BRL): R$ {:.2} | PTAX: {:.4}\n  Acquired: {}\n--------------------------------------------------\n",
                    lot.id,
                    lot.asset_symbol,
                    lot.amount,
                    lot.unit_cost_basis_brl,
                    lot.ptax_rate_used,
                    lot.acquired_at_utc
                ));
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_state_root_determinism() {
        let ledger1 = TaxLedger { lots: vec![] };
        assert_eq!(ledger1.compute_state_root().unwrap(), "0x0");

        let sample_lot = TaxLot {
            id: "lot-SOL-001".to_string(),
            asset_symbol: "SOL".to_string(),
            amount: 100_000_000,
            unit_cost_basis_brl: 5.07,
            ptax_rate_used: 5.0717,
            acquired_at_utc: "2026-08-04T12:00:00Z".to_string(),
        };

        let ledger_a = TaxLedger {
            lots: vec![sample_lot.clone()],
        };
        let root_a = ledger_a.compute_state_root().unwrap();
        assert_ne!(root_a, "0x0");

        let ledger_b = TaxLedger {
            lots: vec![sample_lot],
        };
        let root_b = ledger_b.compute_state_root().unwrap();

        // Verify that identical ledgers produce identical Poseidon commitments
        assert_eq!(
            root_a, root_b,
            "Identical tax lot sets must yield matching Poseidon BN254 roots"
        );
    }
}
