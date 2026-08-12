//! Tax Lot Accounting Engine
//!
//! tracks cost basis and acquisition history for token streams using FIFO/LIFO matching
//!
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::basis::{BookSnapshot, Disposal, LotMethod};
use crate::ledger::LedgerEvent;

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
            combined.gain_records.extend(ledger.gain_records.clone());
        }
        combined
            .lots
            .sort_by(|a, b| a.acquired_at_utc.cmp(&b.acquired_at_utc));
        combined
    }
}

/// A recorded capital gain or loss from disposing of a tax lot.
///
/// Generated during ingest when an Expense event consumes cost basis.
/// For swap transactions (Expense + Income in the same tx), the
/// proceeds are the BRL value of what was received on the Income side.
/// For standalone expenses (payments with no matching income), proceeds
/// are zero, making the full cost basis a capital loss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GainRecord {
    pub disposal_ref: String,   // transaction signature
    pub asset_symbol: String,   // "SOL", "USDC", etc.
    pub amount_base_units: u64, // quantity disposed in base units
    pub cost_basis_brl: f64,    // cost basis consumed (BRL)
    #[serde(default)]
    pub cost_basis_usd: f64,    // cost basis consumed (USD)
    pub proceeds_brl: f64,      // BRL value received (0 for pure payments)
    #[serde(default)]
    pub proceeds_usd: f64,      // USD value received
    pub gain_brl: f64,          // proceeds - cost_basis (negative = loss)
    #[serde(default)]
    pub gain_usd: f64,           // gain in USD
    pub date_ymd: String,       // disposal date YYYY-MM-DD
    pub is_swap: bool,          // matched against an Income event in the same tx
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
    /// Signatures already processed for this wallet, so an interrupted
    /// ingestion can resume rather than restart from zero.
    #[serde(default)]
    pub processed_signatures: BTreeSet<String>,
    /// Capital gain/loss records from disposals during ingest.
    #[serde(default)]
    pub gain_records: Vec<GainRecord>,
    /// The integer-exact FIFO/HIFO book. This is the source of truth for
    /// which acquisitions remain open and how disposals were matched; the
    /// f64 `lots` and `gain_records` above are deterministic projections
    /// of it for reporting. Older ledger files predate the book and load
    /// as an empty one.
    #[serde(default)]
    pub book: BookSnapshot,
    /// Disposal records produced by the book, kept so a re-derivation can
    /// walk every reported gain back to the lots that supplied it.
    #[serde(default)]
    pub disposals: Vec<Disposal>,
    /// The raw ledger events this wallet was built from. The integer book
    /// is rebuilt from this list on every ingest, so an interrupted run
    /// resumes by re-deriving the full book rather than mutating a partial
    /// one. Old ledger files predate event persistence and load empty.
    #[serde(default)]
    pub events: Vec<LedgerEvent>,
    /// Resolved exchange rates, keyed by `"symbol|YYYY-MM-DD"` (cost basis)
    /// and `"ptax|YYYY-MM-DD"` (USD conversion). The book is rebuilt from
    /// the same events every run, so the rates it used must be replayed
    /// too: a live feed that succeeds today and is rate-limited tomorrow
    /// would otherwise quietly change the ledger. Persisting the rates
    /// makes reconcile deterministic and offline after the first ingest.
    #[serde(default)]
    pub rates: BTreeMap<String, f64>,
}

impl TaxLedger {
    pub fn new() -> Self {
        Self {
            lots: Vec::new(),
            unclassified_counterparties: BTreeSet::new(),
            processed_signatures: BTreeSet::new(),
            gain_records: Vec::new(),
            book: BookSnapshot {
                method: LotMethod::Fifo,
                ..Default::default()
            },
            disposals: Vec::new(),
            events: Vec::new(),
            rates: BTreeMap::new(),
        }
    }

    /// Append an event unless one with the same signature and mint already
    /// exists. Events are the rebuild input, so duplicates would double
    /// book acquisitions on the next re-derivation.
    pub fn record_event(&mut self, event: LedgerEvent) {
        let dup = self
            .events
            .iter()
            .any(|e| e.signature == event.signature && e.mint == event.mint && e.kind == event.kind);
        if !dup {
            self.events.push(event);
        }
    }

    /// True when the ledger holds no lots and no disposal records, so a
    /// report export has nothing to say. A report of all zeros would
    /// mislead, so callers refuse instead of rendering one.
    pub fn is_empty(&self) -> bool {
        self.lots.is_empty() && self.gain_records.is_empty() && self.disposals.is_empty()
    }

    /// Sum of all recorded capital gains and losses.
    pub fn total_gains(&self) -> f64 {
        self.gain_records.iter().map(|g| g.gain_brl).sum()
    }

    /// Rebuild the integer book and the f64 projections from the persisted
    /// event history.
    ///
    /// The book is the source of truth: it sorts acquisitions by time and
    /// disposes strictly FIFO, atomically, and refuses anything that would
    /// over-consume a position. Rebuilding it from the full event list on
    /// every call means an interrupted or resumed ingest re-derives the
    /// same book instead of mutating a partial one, so positions can never
    /// be silently destroyed by a re-run.
    ///
    /// `rate(symbol, ymd)` is the price of one whole token in BRL for the
    /// given day (PTAX for stablecoins, SOL/USD * PTAX for SOL), and
    /// `ptax(ymd)` is the USD/BRL rate for that day, used only to render
    /// the USD columns. Both come from the tool's rate cache; the book
    /// itself never touches a feed.
    ///
    /// Every f64 figure below is a deterministic projection of integer
    /// book records, computed once here and stored, so the report and the
    /// Poseidon state root never recompute with floats.
    pub fn reconcile(
        &mut self,
        rate: &dyn Fn(&str, &str) -> f64,
        ptax: &dyn Fn(&str) -> f64,
    ) -> Result<(), String> {
        use crate::basis::{
            sort_disposals, BasisEvidence, DisposalEvent, Lot as BasisLot, LotBook,
            oracle_cost,
        };
        use crate::ledger::{decimals_for_symbol, mint_to_symbol, EventKind};
        use crate::ptax::unix_to_ymd;
        use std::collections::HashMap;

        const MICRO_PER_BRL: f64 = 1_000_000.0;

        // Rates are memoized on the ledger, keyed by purpose so a cost
        // basis and a PTAX conversion never collide. First ingest resolves
        // from the live feed and stores; every later rebuild replays the
        // stored value, which is what makes the whole book deterministic
        // and offline after the first pass.
        let cost_of = |rates: &mut BTreeMap<String, f64>,
                           symbol: &str,
                           ymd: &str,
                           live: &dyn Fn() -> f64|
         -> f64 {
            let key = format!("{symbol}|{ymd}");
            if let Some(v) = rates.get(&key) {
                return *v;
            }
            let v = live();
            rates.insert(key, v);
            v
        };
        let ptax_of = |rates: &mut BTreeMap<String, f64>,
                           ymd: &str,
                           live: &dyn Fn() -> f64|
         -> f64 {
            let key = format!("ptax|{ymd}");
            if let Some(v) = rates.get(&key) {
                return *v;
            }
            let v = live();
            rates.insert(key, v);
            v
        };

        self.lots.clear();
        self.gain_records.clear();
        self.disposals.clear();

        if self.events.is_empty() {
            self.book = BookSnapshot {
                method: self.book.method,
                ..Default::default()
            };
            return Ok(());
        }

        // 1. Order every event by block time. The book insists on time
        // order because lot selection depends on what was open at the
        // moment of each disposal, so an event without a reported time
        // cannot be placed and is dropped rather than guessed.
        let mut events: Vec<LedgerEvent> = self
            .events
            .iter()
            .filter(|e| e.block_time_unix.is_some())
            .cloned()
            .collect();
        events.sort_by_key(|e| e.block_time_unix.unwrap_or(0));

        let earliest_unix = events
            .first()
            .and_then(|e| e.block_time_unix)
            .unwrap_or(0);
        let earliest_ymd = unix_to_ymd(earliest_unix);

        // 2. Opening-balance sizing. Assets whose position would go
        // negative partway through the history were funded externally or
        // before tracking began (for a DEX wallet the funding often arrives
        // as unclassified transfers, which are deliberately not booked as
        // income). The synthetic opening lot must cover the worst drawdown
        // across the whole timeline, not merely the final net, so a later
        // disposal can never be refused against money the tool never saw
        // arrive. Walking the timeline gives that peak exactly.
        let mut opening_shortfall: HashMap<String, i128> = HashMap::new();
        {
            let mut running: HashMap<String, i128> = HashMap::new();
            for ev in &events {
                let symbol = mint_to_symbol(&ev.mint).to_string();
                let delta = match ev.kind {
                    EventKind::Income => ev.amount_base_units as i128,
                    EventKind::Expense => -(ev.amount_base_units as i128),
                    _ => 0,
                };
                let bal = running.entry(symbol.clone()).or_insert(0);
                *bal += delta;
                // The most negative balance reached is how much external
                // funding the position leaned on at its weakest point.
                if *bal < 0 {
                    let need = opening_shortfall.entry(symbol).or_insert(0);
                    if -*bal > *need {
                        *need = -*bal;
                    }
                }
            }
        }

        let mut mint_of: HashMap<String, String> = HashMap::new();
        for ev in &events {
            mint_of
                .entry(mint_to_symbol(&ev.mint).to_string())
                .or_insert_with(|| ev.mint.clone());
        }

        let mut book = LotBook::new(self.book.method);
        // HashMap iteration order is randomized per process, which would
        // give the opening lots a different acceptance sequence on every
        // run and make the persisted book not byte-identical. Iterate the
        // symbols in sorted order so the rebuilt book is deterministic.
        let mut shortfall_symbols: Vec<&String> = opening_shortfall.keys().collect();
        shortfall_symbols.sort();
        for symbol in shortfall_symbols {
            let shortfall = *opening_shortfall.get(symbol).unwrap() as u128;
            if shortfall == 0 {
                continue;
            }
            let mint = mint_of
                .get(symbol)
                .cloned()
                .unwrap_or_else(|| crate::ledger::NATIVE_SOL_MINT.to_string());
            let cost_micro_per_token =
                (cost_of(&mut self.rates, symbol, &earliest_ymd, &|| rate(symbol, &earliest_ymd))
                    * MICRO_PER_BRL) as u128;
            let cost = oracle_cost(shortfall, cost_micro_per_token, decimals_for_symbol(symbol))?;
            book.acquire(BasisLot {
                mint,
                acquisition_ref: format!("opening-balance-{}-{}", symbol, earliest_ymd),
                acquired_at_unix: earliest_unix,
                quantity_base_units: shortfall,
                cost_base_units: cost,
                evidence: BasisEvidence::OracleDerived {
                    source: "ptax:USD/BRL".to_string(),
                    priced_at_unix: earliest_unix,
                },
            })?;
        }

        // 3. Feed events in time order. Income opens a lot valued at the
        // day's rate; Expense closes lots with proceeds from any income in
        // the same signature (a swap) or nothing (a pure payment).
        for ev in &events {
            let symbol = mint_to_symbol(&ev.mint).to_string();
            let date_ymd = unix_to_ymd(ev.block_time_unix.unwrap_or(0));
            match ev.kind {
                EventKind::Income if ev.amount_base_units > 0 => {
                    let cost_micro_per_token =
                        (cost_of(&mut self.rates, &symbol, &date_ymd, &|| rate(&symbol, &date_ymd))
                            * MICRO_PER_BRL) as u128;
                    let cost = oracle_cost(
                        ev.amount_base_units as u128,
                        cost_micro_per_token,
                        decimals_for_symbol(&symbol),
                    )?;
                    book.acquire(BasisLot {
                        mint: ev.mint.clone(),
                        acquisition_ref: format!("{}-{}", ev.signature, ev.mint),
                        acquired_at_unix: ev.block_time_unix.unwrap_or(0),
                        quantity_base_units: ev.amount_base_units as u128,
                        cost_base_units: cost,
                        evidence: BasisEvidence::OracleDerived {
                            source: "ptax:USD/BRL".to_string(),
                            priced_at_unix: ev.block_time_unix.unwrap_or(0),
                        },
                    })?;
                }
                EventKind::Expense if ev.amount_base_units > 0 => {
                    // Proceeds from same-signature income siblings.
                    let mut proceeds_micro: u128 = 0;
                    for sibling in &events {
                        if sibling.signature == ev.signature
                            && sibling.kind == EventKind::Income
                            && sibling.amount_base_units > 0
                        {
                            let s_symbol = mint_to_symbol(&sibling.mint).to_string();
                            let s_date = unix_to_ymd(sibling.block_time_unix.unwrap_or(0));
                            let s_micro_per_token = (cost_of(
                                &mut self.rates,
                                &s_symbol,
                                &s_date,
                                &|| rate(&s_symbol, &s_date),
                            ) * MICRO_PER_BRL) as u128;
                            proceeds_micro += oracle_cost(
                                sibling.amount_base_units as u128,
                                s_micro_per_token,
                                decimals_for_symbol(&s_symbol),
                            )?;
                        }
                    }
                    let records = book.dispose(DisposalEvent {
                        mint: ev.mint.clone(),
                        disposal_ref: ev.signature.clone(),
                        disposed_at_unix: ev.block_time_unix.unwrap_or(0),
                        quantity_base_units: ev.amount_base_units as u128,
                        proceeds_base_units: proceeds_micro,
                    })?;
                    self.disposals.extend(records);
                }
                _ => {}
            }
        }

        sort_disposals(&mut self.disposals);
        self.book = book.snapshot();

        // 4. Project the book onto the f64 records the report consumes.
        for lot in book.remaining_lots() {
            let symbol = mint_to_symbol(&lot.mint).to_string();
            let decimals = decimals_for_symbol(&symbol);
            let unit_cost_per_token = if lot.quantity_base_units > 0 {
                lot.cost_base_units as f64
                    * 10f64.powi(decimals as i32)
                    / lot.quantity_base_units as f64
                    / MICRO_PER_BRL
            } else {
                0.0
            };
            self.lots.push(TaxLot {
                id: lot.acquisition_ref.clone(),
                asset_symbol: symbol.clone(),
                amount: u64::try_from(lot.quantity_base_units).unwrap_or(u64::MAX),
                unit_cost_basis_brl: unit_cost_per_token,
                acquired_at_utc: format!("{} UTC", unix_to_ymd(lot.acquired_at_unix)),
                ptax_rate_used: unit_cost_per_token,
            });
        }

        for d in &self.disposals {
            let symbol = mint_to_symbol(&d.mint).to_string();
            let ymd = unix_to_ymd(d.disposed_at_unix);
            let ptax_rate = ptax_of(&mut self.rates, &ymd, &|| ptax(&ymd)).max(f64::EPSILON);
            // The cost was fixed at the consumed lot's acquisition date,
            // so its USD equivalent uses that day's PTAX, not the disposal
            // day's. Proceeds and gain are dated to the disposal.
            let cost_ymd = unix_to_ymd(d.acquired_at_unix);
            let cost_ptax_rate =
                ptax_of(&mut self.rates, &cost_ymd, &|| ptax(&cost_ymd)).max(f64::EPSILON);
            let cost_brl = d.cost_basis_base_units as f64 / MICRO_PER_BRL;
            let proceeds_brl = d.proceeds_base_units as f64 / MICRO_PER_BRL;
            let gain_brl = d.gain_base_units as f64 / MICRO_PER_BRL;
            self.gain_records.push(GainRecord {
                disposal_ref: d.disposal_ref.clone(),
                asset_symbol: symbol,
                amount_base_units: u64::try_from(d.quantity_base_units).unwrap_or(u64::MAX),
                cost_basis_brl: cost_brl,
                cost_basis_usd: cost_brl / cost_ptax_rate,
                proceeds_brl,
                proceeds_usd: proceeds_brl / ptax_rate,
                gain_brl,
                gain_usd: gain_brl / ptax_rate,
                date_ymd: ymd,
                is_swap: d.proceeds_base_units > 0,
            });
        }

        Ok(())
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

    #[test]
    fn browser_poseidon_self_test_vectors_match_the_rust_fold() {
        // The HTML report's Verify in Browser button runs a hand-written
        // width-4 Poseidon in JavaScript. Its self-test pins two vectors
        // claimed to come from the Rust fold; this test recomputes them
        // with the same hasher the state root uses, so a drift between
        // the two implementations fails the suite rather than the auditor.
        let fold = |a: u64, b: u64, c: u64| -> String {
            let mut poseidon = Poseidon::<Fr>::new_circom(3).unwrap();
            let out = poseidon
                .hash(&[Fr::from(a), Fr::from(b), Fr::from(c)])
                .unwrap();
            hex::encode(out.into_bigint().to_bytes_be())
        };

        assert_eq!(
            fold(0, 5_000_000, 50_500),
            "2f965d1a1ad15eb3351f8e772d681e6287754eb759d579193896e93e219c8bf8"
        );
        assert_eq!(
            fold(1, 2, 3),
            "0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732"
        );
    }

    #[test]
    fn reconcile_books_fifo_not_the_order_events_arrived() {
        use crate::ledger::{EventKind, LedgerEvent};

        // Three SOL acquisitions on three different days, then one disposal
        // larger than the first acquisition. The book must consume the
        // OLDEST lot first regardless of the order the events were pushed.
        let mut ledger = TaxLedger::new();
        let ev = |day: i64, kind: EventKind, amount: i128| LedgerEvent {
            block_time_unix: Some(1_700_000_000 + day * 86_400),
            kind,
            amount_base_units: amount,
            mint: crate::ledger::NATIVE_SOL_MINT.to_string(),
            counterparty: None,
            counterparty_address: None,
            signature: format!("sig-{day}"),
            is_classified: true,
        };
        // Pushed out of order on purpose: day 30, then day 10, then day 20.
        for e in [ev(30, EventKind::Income, 2_000_000_000), ev(10, EventKind::Income, 1_000_000_000), ev(20, EventKind::Income, 3_000_000_000)] {
            ledger.record_event(e);
        }
        // A fixed rate: 100 BRL per whole SOL (10^9 base units). So one
        // base unit costs 100/10^9 micro-BRL, and 1 SOL costs 100 BRL.
        let rate = |_sym: &str, _ymd: &str| 100.0f64;
        let ptax = |_ymd: &str| 5.0f64;
        ledger.reconcile(&rate, &ptax).unwrap();

        // All three lots are still open (nothing disposed yet).
        assert_eq!(ledger.lots.len(), 3);

        // Now dispose 1.5 SOL. FIFO must take the day-10 lot (1 SOL) fully
        // and half of the day-20 lot (0.5 SOL), NOT the day-30 lot.
        ledger.record_event(ev(40, EventKind::Expense, 1_500_000_000));
        ledger.reconcile(&rate, &ptax).unwrap();

        assert_eq!(ledger.disposals.len(), 2, "one record per lot consumed");
        // Cost basis consumed: 1 SOL at 100 BRL + 0.5 SOL at 100 BRL = 150.
        let total_cost: f64 = ledger.gain_records.iter().map(|g| g.cost_basis_brl).sum();
        assert!((total_cost - 150.0).abs() < 1e-6, "cost basis {}", total_cost);
        // The day-10 lot (acquired first) was fully consumed first.
        assert_eq!(ledger.gain_records[0].amount_base_units, 1_000_000_000);
        // Remaining: 2.5 SOL of the day-20 lot + all 2 SOL of the day-30 lot.
        let remaining: u64 = ledger.lots.iter().map(|l| l.amount).sum();
        assert_eq!(remaining, 4_500_000_000);
    }

    #[test]
    fn reconcile_creates_an_opening_balance_lot_for_a_shortfall() {
        use crate::ledger::{EventKind, LedgerEvent};

        // A wallet that only ever spent USDC (funded externally) has no
        // income events; a pure expense of 1 USDC must still dispose
        // against an opening-balance lot instead of erroring.
        let mut ledger = TaxLedger::new();
        ledger.record_event(LedgerEvent {
            block_time_unix: Some(1_700_000_000),
            kind: EventKind::Expense,
            amount_base_units: 1_000_000, // 1 USDC, sign lives in the kind
            mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            counterparty: None,
            counterparty_address: None,
            signature: "sig-spend".to_string(),
            is_classified: true,
        });
        let rate = |_sym: &str, _ymd: &str| 5.5f64; // 5.5 BRL per USDC
        let ptax = |_ymd: &str| 5.5f64;
        ledger.reconcile(&rate, &ptax).unwrap();

        assert_eq!(ledger.disposals.len(), 1);
        let gain = &ledger.gain_records[0];
        assert!((gain.cost_basis_brl - 5.5).abs() < 1e-6, "cost basis {}", gain.cost_basis_brl);
        // No lots remain: the opening-balance lot was fully consumed. The
        // snapshot keeps the spent lot with a zero remaining quantity,
        // which is the book's true state and re-derives to nothing held.
        assert!(ledger.lots.is_empty());
        assert_eq!(
            ledger
                .book
                .open_lots
                .iter()
                .map(|o| o.remaining_quantity)
                .sum::<u128>(),
            0,
            "the opening lot must be fully consumed"
        );
    }

    #[test]
    fn reconcile_is_deterministic_across_runs() {
        use crate::ledger::{EventKind, LedgerEvent};

        let mut ledger = TaxLedger::new();
        let ev = |day: i64, kind: EventKind, amount: i128| LedgerEvent {
            block_time_unix: Some(1_700_000_000 + day * 86_400),
            kind,
            amount_base_units: amount,
            mint: crate::ledger::NATIVE_SOL_MINT.to_string(),
            counterparty: None,
            counterparty_address: None,
            signature: format!("sig-{day}"),
            is_classified: true,
        };
        for e in [ev(1, EventKind::Income, 1_000_000_000), ev(2, EventKind::Income, 2_000_000_000), ev(3, EventKind::Expense, -1_000_000_000)] {
            ledger.record_event(e);
        }
        let rate = |_sym: &str, _ymd: &str| 50.0f64;
        let ptax = |_ymd: &str| 5.0f64;

        ledger.reconcile(&rate, &ptax).unwrap();
        let first_root = ledger.compute_state_root().unwrap();
        let first_gains: Vec<f64> = ledger.gain_records.iter().map(|g| g.gain_brl).collect();

        // Re-running reconcile (as a resume would) must not change anything.
        ledger.reconcile(&rate, &ptax).unwrap();
        let second_root = ledger.compute_state_root().unwrap();
        let second_gains: Vec<f64> = ledger.gain_records.iter().map(|g| g.gain_brl).collect();

        assert_eq!(first_root, second_root);
        assert_eq!(first_gains, second_gains);
        assert_eq!(ledger.lots.len(), 2, "disposal consumed the day-1 lot only");
    }

    #[test]
    fn reconcile_replays_persisted_rates_when_the_live_feed_changes() {
        use crate::ledger::{EventKind, LedgerEvent};

        // The whole point of the persisted rate cache: once a rate is
        // resolved and stored on the ledger, a later rebuild must reuse it
        // even if the live feed (which can be rate-limited or offline) now
        // says something different. Otherwise an ingest today and a resume
        // tomorrow could quietly produce two different ledgers.
        let mut ledger = TaxLedger::new();
        ledger.record_event(LedgerEvent {
            block_time_unix: Some(1_700_000_000),
            kind: EventKind::Income,
            amount_base_units: 1_000_000_000,
            mint: crate::ledger::NATIVE_SOL_MINT.to_string(),
            counterparty: None,
            counterparty_address: None,
            signature: "sig-in".to_string(),
            is_classified: true,
        });
        ledger.record_event(LedgerEvent {
            block_time_unix: Some(1_700_086_400),
            kind: EventKind::Expense,
            amount_base_units: 500_000_000,
            mint: crate::ledger::NATIVE_SOL_MINT.to_string(),
            counterparty: None,
            counterparty_address: None,
            signature: "sig-out".to_string(),
            is_classified: true,
        });

        // First pass: live rate is 100 BRL/SOL.
        let rate_live = |_s: &str, _y: &str| 100.0f64;
        let ptax_live = |_y: &str| 5.0f64;
        ledger.reconcile(&rate_live, &ptax_live).unwrap();
        // cost basis for the acquisition day + ptax for the acquisition and
        // disposal days (income and expense are a day apart).
        assert_eq!(ledger.rates.len(), 3, "cost basis + two ptax days");
        let first_gain: f64 = ledger.gain_records.iter().map(|g| g.gain_brl).sum();

        // Second pass: the feed now returns 50 BRL/SOL (a fallback or a
        // different snapshot). The persisted rates must win.
        let rate_changed = |_s: &str, _y: &str| 50.0f64;
        let ptax_changed = |_y: &str| 4.0f64;
        ledger.reconcile(&rate_changed, &ptax_changed).unwrap();
        let second_gain: f64 = ledger.gain_records.iter().map(|g| g.gain_brl).sum();

        assert_eq!(first_gain, second_gain, "rate change must not move the ledger");
        // All three rates were resolved on the first pass and reused after.
        assert_eq!(ledger.rates.len(), 3, "no new rates resolved on the replay");
    }
}
