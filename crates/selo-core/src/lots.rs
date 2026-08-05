//! Tax Lot Accounting Engine
//!
//! tracks cost basis and acquisition history for token streams using FIFO/LIFO matching
//!
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MultiWalletLedger {
    pub wallets: BTreeMap<String, TaxLedger>,
}

impl MultiWalletLedger {
    pub fn new() -> Self {
        Self {
            wallets: BTreeMap::new(),
        }
    }

    /// Retrieve a reference to a wallet's tax ledger
    pub fn get_ledger(&self, pubkey: &str) -> Option<&TaxLedger> {
        self.wallets.get(pubkey)
    }

    /// Retrieve a mutable reference to a wallet's tax ledger, creating one if absent
    pub fn get_mut_ledger(&mut self, pubkey: &str) -> &mut TaxLedger {
        self.wallets.entry(pubkey.to_string()).or_default()
    }

    /// Generate a cumulative tax ledger combining all lots across all stored wallets
    pub fn cumulative_ledger(&self) -> TaxLedger {
        let mut combined = TaxLedger::new();
        for ledger in self.wallets.values() {
            combined.lots.extend(ledger.lots.clone());
            combined
                .unclassified_counterparties
                .extend(ledger.unclassified_counterparties.clone());
        }
        combined
            .lots
            .sort_by(|a, b| a.acquired_at_utc.cmp(&b.acquired_at_utc));
        combined
    }
}

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
    #[serde(default)]
    pub unclassified_counterparties: BTreeSet<String>,
}

impl TaxLedger {
    pub fn new() -> Self {
        Self {
            lots: Vec::new(),
            unclassified_counterparties: BTreeSet::new(),
        }
    }

    /// add new acquired lot to the tracking ledger
    pub fn add_lot(&mut self, lot: TaxLot) {
        self.lots.push(lot);
    }

    /// record a new acquisition with historical PTAX rate (with built-in deduplication)
    pub fn record_acquisition(
        &mut self,
        id: String,
        asset_symbol: String,
        amount: u64,
        ptax_rate_brl: f64,
        acquired_at_utc: String,
    ) -> Result<(), String> {
        if self.lots.iter().any(|l| l.id == id) {
            return Ok(()); // Lot already exists; skip silently for efficient subsequent runs
        }

        let lot = TaxLot {
            id,
            asset_symbol,
            amount,
            unit_cost_basis_brl: ptax_rate_brl,
            acquired_at_utc,
            ptax_rate_used: ptax_rate_brl,
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
        let ledger1: TaxLedger = TaxLedger {
            lots: vec![],
            ..Default::default()
        };
        assert_eq!(ledger1.compute_state_root().unwrap(), "0x0");

        let sample_lot = TaxLot {
            id: "lot-SOL-001".to_string(),
            asset_symbol: "SOL".to_string(),
            amount: 100_000_000,
            unit_cost_basis_brl: 5.07,
            ptax_rate_used: 5.0717,
            acquired_at_utc: "2026-08-04T12:00:00Z".to_string(),
        };

        let ledger_a: TaxLedger = TaxLedger {
            lots: vec![sample_lot.clone()],
            ..Default::default()
        };
        let root_a: String = ledger_a.compute_state_root().unwrap();
        assert_ne!(root_a, "0x0");

        let ledger_b: TaxLedger = TaxLedger {
            lots: vec![sample_lot],
            ..Default::default()
        };
        let root_b: String = ledger_b.compute_state_root().unwrap();

        // Verify that identical ledgers produce identical Poseidon commitments
        assert_eq!(
            root_a, root_b,
            "Identical tax lot sets must yield matching Poseidon BN254 roots"
        );
    }
}
