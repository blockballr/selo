//! Cost basis: acquisitions opened as lots, disposals closed against them.
//!
//! `LotBook` takes its lot method at construction and there is no setter.
//! A caller choosing FIFO for one sale and HIFO for the next is shopping
//! for a number, so the type makes it unrepresentable.
//!
//! Every lot carries a `BasisEvidence` class with no default, so an
//! oracle-derived cost cannot be spelled without naming its source and
//! timestamp. The class travels onto every disposal derived from it.
//!
//! Deterministic like `ledger`, since this gets hashed and anchored: no
//! map iteration order, no clock, no floating point, ties broken by data.
//! Money is integers, gains are `i128`, every multiplication checked.

use std::cmp::Ordering;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::ledger::{EventKind, LedgerEvent};

/// Which open lot a disposal consumes.
///
/// The declaration order is part of the sort key on disposal records,
/// so reordering these variants changes the hash of any day that mixes
/// books. Add new methods at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum LotMethod {
    /// Oldest acquisition first. The default assumption of most tax
    /// authorities and the only method that needs no election in many
    /// jurisdictions, which is why it is listed first here.
    #[default]
    Fifo,
    /// Highest cost per unit first, which realizes the smallest gain
    /// available from the lots on hand. Legitimate where specific
    /// identification is permitted and the identification is recorded
    /// at the time of the disposal, which is what this module does.
    Hifo,
}

impl LotMethod {
    /// Stable text form. It goes into the canonical line that gets
    /// hashed, so these strings are fixed.
    pub fn as_str(&self) -> &'static str {
        match self {
            LotMethod::Fifo => "fifo",
            LotMethod::Hifo => "hifo",
        }
    }

    /// Parse a configured method name, ignoring case and surrounding
    /// space. Anything else is refused rather than mapped to a
    /// neighbouring method, since silently booking a year under a method
    /// nobody chose is the failure this whole module exists to prevent.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "fifo" => Ok(LotMethod::Fifo),
            "hifo" => Ok(LotMethod::Hifo),
            other => Err(format!(
                "lot_method {other:?} is not a method this book knows; set it to fifo or hifo"
            )),
        }
    }

    /// Read the method from the jailed config section, key `lot_method`.
    ///
    /// Fails closed, like the catalog. An absent endpoint can fall back to a
    /// public node; an absent lot method cannot, because picking one silently
    /// would decide the operator's tax figure and claim an election never
    /// made.
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let raw = section
            .get("lot_method")
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                "no lot_method configured; the operator must declare fifo or hifo once, \
                 because a cost basis method chosen after the fact is not an accounting \
                 policy, it is a preference"
                    .to_string()
            })?;
        Self::parse(raw)
    }
}

/// Where a lot's cost figure came from.
///
/// No `Default` and no "unknown" variant. A basis with no provenance is
/// exactly what this type exists to make impossible. The oracle variant
/// cannot be built without naming its source and timestamp: a price with
/// no source is a guess, and one with no timestamp cannot be checked.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BasisEvidence {
    /// The cost is a difference between two integers the chain reported.
    /// A swap is the usual case: what was paid is on the other side of
    /// the same transaction, so the figure re-derives from chain data
    /// alone and needs nobody's word for it.
    ExactFromChain,
    /// The cost came from an external price feed, because the
    /// acquisition had no on-chain counter-payment to read. Staking
    /// rewards, airdrops and mining income are all this case.
    OracleDerived {
        /// Which feed said so. Recorded verbatim so a reviewer can go
        /// and ask that feed the same question.
        source: String,
        /// The time the price was read, which is not always the moment
        /// of acquisition, and the gap is exactly what a reviewer wants
        /// to see rather than have smoothed away.
        priced_at_unix: i64,
    },
}

impl BasisEvidence {
    /// True only for a figure that re-derives from chain data.
    pub fn is_exact(&self) -> bool {
        matches!(self, BasisEvidence::ExactFromChain)
    }

    /// Stable class name for the canonical line.
    pub fn class(&self) -> &'static str {
        match self {
            BasisEvidence::ExactFromChain => "exact_from_chain",
            BasisEvidence::OracleDerived { .. } => "oracle_derived",
        }
    }
}

/// One acquisition, held until something consumes it.
///
/// `cost_base_units` is in the smallest unit of whatever currency the
/// book reports in, typically micro-USD, and never in the acquired
/// asset's own units. Keeping the reporting currency implicit and
/// integral means no line of this module ever divides by a rate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lot {
    /// Mint of the asset acquired, or `ledger::NATIVE_SOL_MINT` for
    /// lamports. Lots never pool across mints.
    pub mint: String,
    /// What this acquisition can be traced back to, normally the
    /// transaction signature. It appears on every disposal record the
    /// lot produces, so a reviewer can walk from an 8949 line back to
    /// the chain without asking anyone.
    pub acquisition_ref: String,
    /// Acquisition time as the chain reported it. Never a local clock:
    /// the holding period is computed from this, and a locally invented
    /// timestamp could move a disposal across the long term boundary.
    pub acquired_at_unix: i64,
    /// Quantity acquired, in the mint's smallest unit.
    pub quantity_base_units: u128,
    /// Total cost of the whole lot in the reporting currency's smallest
    /// unit. Zero is allowed and means exactly what it says: a free
    /// airdrop has a zero basis and its entire proceeds are gain.
    pub cost_base_units: u128,
    /// How that cost figure was arrived at. Required, always.
    pub evidence: BasisEvidence,
}

/// A serializable snapshot of one open lot as the book holds it.
///
/// `quantity_base_units` and `cost_base_units` on the inner `Lot` are the
/// REMAINING amounts (what the next disposal can reach), not the original
/// acquisition. `seq` is the book's acceptance order, used only as a last
/// resort tie-break and carried so a restored book sorts identically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenLotSnapshot {
    pub lot: Lot,
    pub remaining_quantity: u128,
    pub remaining_cost: u128,
    pub seq: u64,
}

/// A disposal as it arrives, before it has been matched against lots.
///
/// This is the input side. The output is [`Disposal`], which is the
/// reportable record and carries the basis this book supplied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisposalEvent {
    /// Mint of the asset that left.
    pub mint: String,
    /// What the disposal can be traced back to, normally the signature.
    pub disposal_ref: String,
    /// Disposal time as the chain reported it.
    pub disposed_at_unix: i64,
    /// Quantity that left, in the mint's smallest unit, unsigned. The
    /// direction is in the name of the operation, not in the sign of the
    /// number, so there is no way to spell a disposal that adds to the
    /// position.
    pub quantity_base_units: u128,
    /// What came in for it, in the reporting currency's smallest unit.
    pub proceeds_base_units: u128,
}

/// One reportable disposal against one lot. A Form 8949 line.
///
/// Every field a reviewer needs is on the record itself rather than
/// reachable through the book that produced it, because these records
/// outlive the process that made them and get hashed on their own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disposal {
    pub mint: String,
    pub disposal_ref: String,
    pub disposed_at_unix: i64,
    /// Acquisition date of the lot consumed. Present per record rather
    /// than as an aggregate "various", which is what makes the holding
    /// period computable line by line.
    pub acquired_at_unix: i64,
    pub acquisition_ref: String,
    /// How much of the lot this record consumed.
    pub quantity_base_units: u128,
    /// The share of the disposal's proceeds allocated to this lot.
    pub proceeds_base_units: u128,
    /// The share of the lot's cost that left with it.
    pub cost_basis_base_units: u128,
    /// Proceeds minus basis. Signed, because a loss is the point.
    pub gain_base_units: i128,
    /// The consumed lot's evidence class, carried through unchanged. A
    /// gain computed against an oracle derived basis is still an oracle
    /// derived figure, and rolling it up with exact ones would launder
    /// the weakest number in the book into the strongest column.
    pub basis_evidence: BasisEvidence,
    /// The method that selected this lot. On the record so that the
    /// output states its own policy rather than relying on a note
    /// somewhere else that the book was run under FIFO.
    pub method: LotMethod,
}

impl Disposal {
    /// The total order disposal records are sorted by.
    ///
    /// Every field participates, so two records that compare equal are
    /// equal and no tie can be broken by the order the caller happened
    /// to assemble them in.
    fn sort_key(
        &self,
    ) -> (
        &str,
        i64,
        &str,
        i64,
        &str,
        u128,
        u128,
        u128,
        i128,
        &BasisEvidence,
        LotMethod,
    ) {
        (
            &self.disposal_ref,
            self.disposed_at_unix,
            &self.mint,
            self.acquired_at_unix,
            &self.acquisition_ref,
            self.quantity_base_units,
            self.proceeds_base_units,
            self.cost_basis_base_units,
            self.gain_base_units,
            &self.basis_evidence,
            self.method,
        )
    }

    /// True when the basis on this line re-derives from chain data.
    pub fn basis_is_exact(&self) -> bool {
        self.basis_evidence.is_exact()
    }

    /// The record as one canonical line of text.
    ///
    /// Fixed shape, because it is what gets hashed. Tab separated, this field
    /// order, absent values a single hyphen, integers base ten. Evidence takes
    /// three columns rather than one packed string, so a source containing a
    /// separator cannot shift the fields after it.
    pub fn canonical_line(&self) -> String {
        let (source, priced_at) = match &self.basis_evidence {
            BasisEvidence::ExactFromChain => ("-".to_string(), "-".to_string()),
            BasisEvidence::OracleDerived {
                source,
                priced_at_unix,
            } => (source.clone(), priced_at_unix.to_string()),
        };
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.disposal_ref,
            self.disposed_at_unix,
            self.mint,
            self.method.as_str(),
            self.quantity_base_units,
            self.proceeds_base_units,
            self.acquisition_ref,
            self.acquired_at_unix,
            self.cost_basis_base_units,
            self.gain_base_units,
            self.basis_evidence.class(),
            source,
            priced_at,
        )
    }
}

/// Put disposal records into canonical order, in place.
///
/// Callers that assemble records from several books must run this last,
/// so the order the books were visited in cannot reach the output.
pub fn sort_disposals(records: &mut [Disposal]) {
    records.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
}

/// Sum the gains on a set of records.
///
/// Checked, and an error rather than a saturating total: a year whose
/// gain does not fit in `i128` is a year with a bad number in it, and
/// reporting a clamped figure would be worse than reporting nothing.
pub fn total_gain(records: &[Disposal]) -> Result<i128, String> {
    let mut total: i128 = 0;
    for record in records {
        total = total.checked_add(record.gain_base_units).ok_or_else(|| {
            "total gain overflows i128, which means one of these records is wrong".to_string()
        })?;
    }
    Ok(total)
}

/// Value a quantity at a unit price, for lots that need one.
///
/// This is the arithmetic behind an oracle derived basis: `quantity` is
/// in the asset's base units, `unit_price_base_units` is the price of
/// one whole token in the reporting currency's smallest unit, and
/// `asset_decimals` is what converts between them.
///
/// Checked multiplication: this is where a nine decimal mint meets a real
/// balance and a wrapped product becomes a plausible basis. Division
/// truncates on purpose, so the result is reproducible and a rounding
/// artifact never lands in the filer's favour.
pub fn oracle_cost(
    quantity_base_units: u128,
    unit_price_base_units: u128,
    asset_decimals: u32,
) -> Result<u128, String> {
    let scale = 10u128
        .checked_pow(asset_decimals)
        .ok_or_else(|| format!("a mint with {asset_decimals} decimals is not representable"))?;
    let product = quantity_base_units
        .checked_mul(unit_price_base_units)
        .ok_or_else(|| {
            format!(
                "valuing {quantity_base_units} base units at {unit_price_base_units} per whole \
                 token overflows; this figure cannot be represented, so it is refused rather \
                 than wrapped"
            )
        })?;
    Ok(product / scale)
}

/// An acquisition the book still holds part of.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenLot {
    lot: Lot,
    remaining_quantity: u128,
    remaining_cost: u128,
    /// Order this lot was accepted in. Only ever a last resort tie
    /// break, after every field of the data itself has tied.
    seq: u64,
}

/// The open lots for one merchant, and the one method they are all
/// closed under.
#[derive(Debug, Clone)]
pub struct LotBook {
    method: LotMethod,
    lots: Vec<OpenLot>,
    last_event_unix: Option<i64>,
    next_seq: u64,
}

impl LotBook {
    /// Open a book under one method. There is no other constructor and
    /// no way to change the method later, which is the whole point.
    pub fn new(method: LotMethod) -> Self {
        Self {
            method,
            lots: Vec::new(),
            last_event_unix: None,
            next_seq: 0,
        }
    }

    /// The method every disposal in this book is closed under.
    pub fn method(&self) -> LotMethod {
        self.method
    }

    /// Record an acquisition.
    ///
    /// A zero quantity acquisition is refused, not stored. It would be a lot
    /// nothing can consume, and any cost on it would sit in the book without
    /// ever reaching a disposal record. Saying so now is cheaper than finding
    /// a hole in April.
    pub fn acquire(&mut self, lot: Lot) -> Result<(), String> {
        let mint = clean_field(&lot.mint, "mint")?;
        let acquisition_ref = clean_field(&lot.acquisition_ref, "acquisition_ref")?;
        if lot.quantity_base_units == 0 {
            return Err(format!(
                "acquisition {acquisition_ref} has a quantity of zero; a lot that can never be \
                 consumed would strand its cost outside every disposal record"
            ));
        }
        let evidence = match &lot.evidence {
            BasisEvidence::ExactFromChain => BasisEvidence::ExactFromChain,
            BasisEvidence::OracleDerived {
                source,
                priced_at_unix,
            } => BasisEvidence::OracleDerived {
                source: clean_field(source, "oracle source")?,
                priced_at_unix: *priced_at_unix,
            },
        };
        self.check_time_order(lot.acquired_at_unix, "acquisition", &acquisition_ref)?;

        let seq = self.next_seq;
        self.next_seq += 1;
        self.lots.push(OpenLot {
            remaining_quantity: lot.quantity_base_units,
            remaining_cost: lot.cost_base_units,
            lot: Lot {
                mint,
                acquisition_ref,
                evidence,
                ..lot
            },
            seq,
        });
        self.last_event_unix = Some(lot.acquired_at_unix);
        Ok(())
    }

    /// Close a disposal against the open lots and produce its records.
    ///
    /// One record per lot consumed, not one aggregated row, so each row has a
    /// single acquisition date and a single evidence class. Callers can sum
    /// these; they cannot recover them from a summary.
    ///
    /// Disposing more than the book holds is an error and leaves the book
    /// untouched. Clamping or opening a negative position would paper over the
    /// real defect, an acquisition that never got recorded.
    ///
    /// A zero quantity produces no records, and is only accepted when the
    /// proceeds are also zero.
    pub fn dispose(&mut self, event: DisposalEvent) -> Result<Vec<Disposal>, String> {
        let mint = clean_field(&event.mint, "mint")?;
        let disposal_ref = clean_field(&event.disposal_ref, "disposal_ref")?;
        self.check_time_order(event.disposed_at_unix, "disposal", &disposal_ref)?;

        if event.quantity_base_units == 0 {
            if event.proceeds_base_units != 0 {
                return Err(format!(
                    "disposal {disposal_ref} brought in {} but disposed of nothing; proceeds \
                     with no quantity have no basis to be set against",
                    event.proceeds_base_units
                ));
            }
            self.last_event_unix = Some(event.disposed_at_unix);
            return Ok(Vec::new());
        }

        // Work on a copy and commit only on success, so a disposal that
        // fails halfway through leaves no half consumed lots behind. A
        // book that is wrong is recoverable; a book that is wrong in a
        // way that depends on which error fired is not.
        let mut scratch = self.lots.clone();
        let order = selection_order(self.method, &mint, &scratch);

        let mut available: u128 = 0;
        for &i in &order {
            available = available
                .checked_add(scratch[i].remaining_quantity)
                .ok_or_else(|| "quantity on hand overflows u128".to_string())?;
        }
        if available < event.quantity_base_units {
            return Err(format!(
                "disposal {disposal_ref} disposes of {} base units of {mint} but the book holds \
                 only {available}; this is a missing acquisition, not a short position, so it is \
                 refused rather than booked negative",
                event.quantity_base_units
            ));
        }

        // Decide what each lot gives up before touching anything, so the
        // proceeds can be split across a known set of takes.
        let mut takes: Vec<(usize, u128)> = Vec::new();
        let mut outstanding = event.quantity_base_units;
        for &i in &order {
            if outstanding == 0 {
                break;
            }
            let take = scratch[i].remaining_quantity.min(outstanding);
            outstanding -= take;
            takes.push((i, take));
        }

        let mut records = Vec::with_capacity(takes.len());
        let mut proceeds_allocated: u128 = 0;
        for (position, (index, take)) in takes.iter().copied().enumerate() {
            let last = position + 1 == takes.len();
            // Split the proceeds by quantity. Every share but the last
            // truncates, and the last takes whatever is left, so the
            // shares sum to the proceeds exactly. Handing the remainder
            // to a fixed position rather than spreading it keeps the
            // result reproducible without anyone having to know the
            // rounding rule.
            let proceeds = if last {
                event.proceeds_base_units - proceeds_allocated
            } else {
                let share = event.proceeds_base_units.checked_mul(take).ok_or_else(|| {
                    format!(
                        "allocating proceeds of {} across lots overflows",
                        event.proceeds_base_units
                    )
                })? / event.quantity_base_units;
                proceeds_allocated += share;
                share
            };

            let open = &mut scratch[index];
            // Same conservation rule on the basis side: a lot consumed
            // to the end gives up every remaining unit of its cost, so
            // the shares of a lot's basis sum to what the lot cost, to
            // the base unit, however many disposals it took to empty it.
            let basis = if take == open.remaining_quantity {
                open.remaining_cost
            } else {
                open.remaining_cost.checked_mul(take).ok_or_else(|| {
                    format!(
                        "allocating basis of {} across a partial disposal overflows",
                        open.remaining_cost
                    )
                })? / open.remaining_quantity
            };
            open.remaining_cost -= basis;
            open.remaining_quantity -= take;

            let gain = signed(proceeds, "proceeds")?
                .checked_sub(signed(basis, "cost basis")?)
                .ok_or_else(|| "gain overflows i128".to_string())?;

            records.push(Disposal {
                mint: mint.clone(),
                disposal_ref: disposal_ref.clone(),
                disposed_at_unix: event.disposed_at_unix,
                acquired_at_unix: open.lot.acquired_at_unix,
                acquisition_ref: open.lot.acquisition_ref.clone(),
                quantity_base_units: take,
                proceeds_base_units: proceeds,
                cost_basis_base_units: basis,
                gain_base_units: gain,
                basis_evidence: open.lot.evidence.clone(),
                method: self.method,
            });
        }

        self.lots = scratch;
        self.last_event_unix = Some(event.disposed_at_unix);
        Ok(records)
    }

    /// What is still held of one mint, in base units.
    pub fn quantity_on_hand(&self, mint: &str) -> u128 {
        self.lots
            .iter()
            .filter(|l| l.lot.mint == mint.trim())
            .map(|l| l.remaining_quantity)
            .sum()
    }

    /// The unconsumed basis of one mint, in the reporting currency.
    pub fn cost_on_hand(&self, mint: &str) -> u128 {
        self.lots
            .iter()
            .filter(|l| l.lot.mint == mint.trim())
            .map(|l| l.remaining_cost)
            .sum()
    }

    /// The lots still open, in the order this book's method would
    /// consume them, mint by mint in byte order of the mint.
    ///
    /// The quantity and cost on each returned `Lot` are what remains,
    /// not what was originally acquired, since what remains is what the
    /// next disposal can reach.
    pub fn remaining_lots(&self) -> Vec<Lot> {
        let mut mints: Vec<&str> = self
            .lots
            .iter()
            .filter(|l| l.remaining_quantity > 0)
            .map(|l| l.lot.mint.as_str())
            .collect();
        mints.sort_unstable();
        mints.dedup();

        let mut out = Vec::new();
        for mint in mints {
            for i in selection_order(self.method, mint, &self.lots) {
                let open = &self.lots[i];
                out.push(Lot {
                    quantity_base_units: open.remaining_quantity,
                    cost_base_units: open.remaining_cost,
                    ..open.lot.clone()
                });
            }
        }
        out
    }

    /// Refuse an event that predates the last one accepted.
    ///
    /// Lot selection depends on what was open at the disposal, so an
    /// acquisition slipped in behind an already-reported disposal would change
    /// a record this book has handed out and hashed. Out of order events are
    /// refused; the caller replays from the start.
    fn check_time_order(&self, at: i64, what: &str, reference: &str) -> Result<(), String> {
        if let Some(last) = self.last_event_unix {
            if at < last {
                return Err(format!(
                    "{what} {reference} is timestamped {at}, before the last event this book \
                     accepted at {last}; lot selection depends on what was open at the time, so \
                     events must arrive in time order and a back dated one is refused"
                ));
            }
        }
        Ok(())
    }

    /// Serialize the book's open lots and method for persistence.
    ///
    /// A ledger persists between runs, so a book whose acquisitions span
    /// several ingest sessions must be restorable without re-reading the
    /// chain. The snapshot is the entire state: the method (immutable),
    /// the open lots with their remaining quantities and costs, the
    /// acceptance sequence, and the last accepted event time.
    pub fn snapshot(&self) -> BookSnapshot {
        BookSnapshot {
            method: self.method,
            open_lots: self
                .lots
                .iter()
                .map(|open| OpenLotSnapshot {
                    lot: open.lot.clone(),
                    remaining_quantity: open.remaining_quantity,
                    remaining_cost: open.remaining_cost,
                    seq: open.seq,
                })
                .collect(),
            last_event_unix: self.last_event_unix,
            next_seq: self.next_seq,
        }
    }

    /// Restore a book from a snapshot, refusing anything a fresh book
    /// would also refuse. A snapshot carries the method, so the caller
    /// cannot quietly switch books mid-life.
    pub fn from_snapshot(snapshot: BookSnapshot) -> Result<Self, String> {
        let mut book = Self::new(snapshot.method);
        for open in &snapshot.open_lots {
            if open.remaining_quantity > open.lot.quantity_base_units {
                return Err(format!(
                    "snapshot lot {} has more remaining ({}) than it acquired ({})",
                    open.lot.acquisition_ref, open.remaining_quantity, open.lot.quantity_base_units
                ));
            }
            book.lots.push(OpenLot {
                lot: open.lot.clone(),
                remaining_quantity: open.remaining_quantity,
                remaining_cost: open.remaining_cost,
                seq: open.seq,
            });
        }
        book.next_seq = snapshot.next_seq;
        book.last_event_unix = snapshot.last_event_unix;
        Ok(book)
    }
}

/// A serializable snapshot of a [`LotBook`]'s full state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BookSnapshot {
    pub method: LotMethod,
    pub open_lots: Vec<OpenLotSnapshot>,
    pub last_event_unix: Option<i64>,
    pub next_seq: u64,
}

/// The indices of the open lots of one mint, in the order the method
/// consumes them.
///
/// Both orders are total. FIFO breaks ties on acquisition reference then
/// acceptance sequence; HIFO falls back to the whole FIFO key, so equal
/// cost lots still leave oldest first. Nothing depends on vector order
/// beyond that last resort.
fn selection_order(method: LotMethod, mint: &str, lots: &[OpenLot]) -> Vec<usize> {
    let mut indices: Vec<usize> = lots
        .iter()
        .enumerate()
        .filter(|(_, l)| l.lot.mint == mint && l.remaining_quantity > 0)
        .map(|(i, _)| i)
        .collect();
    match method {
        LotMethod::Fifo => indices.sort_by(|&a, &b| fifo_key(&lots[a]).cmp(&fifo_key(&lots[b]))),
        LotMethod::Hifo => indices.sort_by(|&a, &b| {
            // Reversed arguments: highest unit cost first.
            cmp_unit_cost(&lots[b], &lots[a])
                .then_with(|| fifo_key(&lots[a]).cmp(&fifo_key(&lots[b])))
        }),
    }
    indices
}

fn fifo_key(lot: &OpenLot) -> (i64, &str, u64) {
    (
        lot.lot.acquired_at_unix,
        lot.lot.acquisition_ref.as_str(),
        lot.seq,
    )
}

/// Compare two lots by cost per base unit.
///
/// Per unit, not per lot: HIFO means the most expensive units, and
/// ranking by total cost would put a large cheap lot ahead of a small
/// expensive one and quietly stop being HIFO.
fn cmp_unit_cost(a: &OpenLot, b: &OpenLot) -> Ordering {
    cmp_ratio(
        a.remaining_cost,
        a.remaining_quantity,
        b.remaining_cost,
        b.remaining_quantity,
    )
}

/// Compare `a/b` with `c/d` exactly, for positive denominators.
///
/// Cross multiplying overflows on large `u128` values, and an overflow
/// inside a comparator is not a wrong answer once, it is a sort order that
/// is not an order. This compares integer parts and recurses on inverted
/// remainders, which terminates for Euclid's reason.
fn cmp_ratio(mut a: u128, mut b: u128, mut c: u128, mut d: u128) -> Ordering {
    // A lot with no quantity left is never offered to this comparator,
    // but defining the degenerate case keeps the function total.
    if b == 0 || d == 0 {
        return b.cmp(&d);
    }
    let mut flipped = false;
    loop {
        let (whole_ab, rem_ab) = (a / b, a % b);
        let (whole_cd, rem_cd) = (c / d, c % d);
        if whole_ab != whole_cd {
            let order = whole_ab.cmp(&whole_cd);
            return if flipped { order.reverse() } else { order };
        }
        match (rem_ab == 0, rem_cd == 0) {
            (true, true) => return Ordering::Equal,
            // A zero fractional part is the smaller of the two, and the
            // sense of that inverts with each level of recursion.
            (true, false) => {
                return if flipped {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            (false, true) => {
                return if flipped {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            (false, false) => {}
        }
        // rem_ab/b against rem_cd/d is b/rem_ab against d/rem_cd with
        // the comparison reversed.
        a = b;
        b = rem_ab;
        c = d;
        d = rem_cd;
        flipped = !flipped;
    }
}

/// Turn a ledger revenue event into a lot, given what it cost.
///
/// The cost and its evidence are the caller's to supply, because they
/// are not in the event: the ledger records what moved, and what was
/// paid for it either sits on the other side of the same transaction or
/// comes from a price feed. This function will not invent either.
///
/// An event with no block time is refused. A lot with no acquisition
/// date cannot produce a reportable line, and dating it from a local
/// clock would put a number in the book that no re-derivation could
/// reproduce.
pub fn lot_from_event(
    event: &LedgerEvent,
    cost_base_units: u128,
    evidence: BasisEvidence,
) -> Result<Lot, String> {
    if event.kind != EventKind::Revenue {
        return Err(format!(
            "ledger event {} is {}, not revenue; only value arriving opens a lot",
            event.signature,
            event.kind.as_str()
        ));
    }
    if event.amount_base_units <= 0 {
        return Err(format!(
            "revenue event {} has a non-positive amount of {}",
            event.signature, event.amount_base_units
        ));
    }
    let acquired_at_unix = event.block_time_unix.ok_or_else(|| {
        format!(
            "ledger event {} has no block time, so the lot would have no acquisition date and \
             no computable holding period",
            event.signature
        )
    })?;
    Ok(Lot {
        mint: event.mint.clone(),
        acquisition_ref: event.signature.clone(),
        acquired_at_unix,
        quantity_base_units: event.amount_base_units as u128,
        cost_base_units,
        evidence,
    })
}

/// Turn a ledger payout event into a disposal, given its proceeds.
///
/// `FeePaid` is refused even though a fee is strictly a disposal of SOL.
/// Whether it is a capital disposal or a deductible expense is a policy
/// question with two defensible answers, and this will not pick one and
/// bury it in a helper. Build the `DisposalEvent` directly.
pub fn disposal_from_event(
    event: &LedgerEvent,
    proceeds_base_units: u128,
) -> Result<DisposalEvent, String> {
    if event.kind != EventKind::Payout {
        return Err(format!(
            "ledger event {} is {}, not a payout; only value leaving closes a lot, and whether \
             a fee is a disposal or an expense is the operator's call to make explicitly",
            event.signature,
            event.kind.as_str()
        ));
    }
    if event.amount_base_units >= 0 {
        return Err(format!(
            "payout event {} has a non-negative amount of {}",
            event.signature, event.amount_base_units
        ));
    }
    let disposed_at_unix = event.block_time_unix.ok_or_else(|| {
        format!(
            "ledger event {} has no block time, so the disposal would have no date",
            event.signature
        )
    })?;
    Ok(DisposalEvent {
        mint: event.mint.clone(),
        disposal_ref: event.signature.clone(),
        disposed_at_unix,
        // Negated before the cast, so the unsigned quantity is the
        // magnitude that left rather than a reinterpreted bit pattern.
        quantity_base_units: event.amount_base_units.unsigned_abs(),
        proceeds_base_units,
    })
}

/// Widen a money figure into the signed space gains live in.
fn signed(value: u128, what: &str) -> Result<i128, String> {
    i128::try_from(value)
        .map_err(|_| format!("{what} of {value} is too large to take a signed difference of"))
}

/// Reject a field that is empty or carries a separator.
///
/// A tab inside a reference would shift every column after it in the
/// canonical line, which means two different records could hash the same
/// way. Trimming is done here so that one caller's trailing space cannot
/// split a mint into two lots that never see each other.
fn clean_field(value: &str, what: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{what} is empty"));
    }
    if trimmed.contains('\t') || trimmed.contains('\n') {
        return Err(format!(
            "{what} {trimmed:?} contains a separator, which would corrupt the canonical line it \
             is written into"
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::NATIVE_SOL_MINT;

    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    /// One second past midnight on 1 January 2024, and a day in seconds.
    const T0: i64 = 1_704_067_201;
    const DAY: i64 = 86_400;

    fn lot(reference: &str, day: i64, quantity: u128, cost: u128) -> Lot {
        Lot {
            mint: NATIVE_SOL_MINT.to_string(),
            acquisition_ref: reference.to_string(),
            acquired_at_unix: T0 + day * DAY,
            quantity_base_units: quantity,
            cost_base_units: cost,
            evidence: BasisEvidence::ExactFromChain,
        }
    }

    fn sale(reference: &str, day: i64, quantity: u128, proceeds: u128) -> DisposalEvent {
        DisposalEvent {
            mint: NATIVE_SOL_MINT.to_string(),
            disposal_ref: reference.to_string(),
            disposed_at_unix: T0 + day * DAY,
            quantity_base_units: quantity,
            proceeds_base_units: proceeds,
        }
    }

    /// Three lots of one SOL each, bought cheap, dear, then middling, so
    /// FIFO and HIFO cannot agree on which to consume first.
    fn three_lots(method: LotMethod) -> LotBook {
        let mut book = LotBook::new(method);
        book.acquire(lot("buy-a", 0, 1_000_000_000, 20_000_000))
            .unwrap();
        book.acquire(lot("buy-b", 1, 1_000_000_000, 90_000_000))
            .unwrap();
        book.acquire(lot("buy-c", 2, 1_000_000_000, 50_000_000))
            .unwrap();
        book
    }

    fn lines(records: &[Disposal]) -> Vec<String> {
        records.iter().map(Disposal::canonical_line).collect()
    }

    #[test]
    fn fifo_consumes_the_oldest_lot_first() {
        let mut book = three_lots(LotMethod::Fifo);
        let records = book
            .dispose(sale("sell-1", 3, 1_000_000_000, 60_000_000))
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].acquisition_ref, "buy-a");
        assert_eq!(records[0].cost_basis_base_units, 20_000_000);
        assert_eq!(records[0].proceeds_base_units, 60_000_000);
        assert_eq!(records[0].gain_base_units, 40_000_000);
        assert_eq!(records[0].acquired_at_unix, T0);
        // The other two lots are untouched and still in age order.
        assert_eq!(book.quantity_on_hand(NATIVE_SOL_MINT), 2_000_000_000);
        let open = book.remaining_lots();
        assert_eq!(open[0].acquisition_ref, "buy-b");
        assert_eq!(open[1].acquisition_ref, "buy-c");
    }

    #[test]
    fn hifo_consumes_the_highest_cost_lot_first() {
        let mut book = three_lots(LotMethod::Hifo);
        let records = book
            .dispose(sale("sell-1", 3, 1_000_000_000, 60_000_000))
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].acquisition_ref, "buy-b");
        assert_eq!(records[0].cost_basis_base_units, 90_000_000);
        assert_eq!(records[0].gain_base_units, -30_000_000);
        let open = book.remaining_lots();
        // Next in line is the middling lot, then the cheapest.
        assert_eq!(open[0].acquisition_ref, "buy-c");
        assert_eq!(open[1].acquisition_ref, "buy-a");
    }

    #[test]
    fn the_two_methods_give_genuinely_different_answers() {
        let mut fifo = three_lots(LotMethod::Fifo);
        let mut hifo = three_lots(LotMethod::Hifo);
        let event = sale("sell-1", 3, 1_500_000_000, 90_000_000);
        let fifo_records = fifo.dispose(event.clone()).unwrap();
        let hifo_records = hifo.dispose(event).unwrap();

        // Same proceeds, different basis, so a different reported gain.
        // This is exactly why the method has to be declared once: a
        // caller free to pick per disposal is choosing the answer.
        // FIFO takes the cheap lot whole and half the dear one; HIFO
        // takes the dear lot whole and half the middling one.
        assert_eq!(
            total_gain(&fifo_records).unwrap(),
            90_000_000 - 20_000_000 - 45_000_000
        );
        assert_eq!(
            total_gain(&hifo_records).unwrap(),
            90_000_000 - 90_000_000 - 25_000_000
        );
        assert_ne!(
            total_gain(&fifo_records).unwrap(),
            total_gain(&hifo_records).unwrap()
        );
        assert_ne!(lines(&fifo_records), lines(&hifo_records));

        // And the surviving position differs too, so the divergence
        // compounds into every later disposal rather than netting out.
        assert_ne!(
            fifo.cost_on_hand(NATIVE_SOL_MINT),
            hifo.cost_on_hand(NATIVE_SOL_MINT)
        );
    }

    #[test]
    fn hifo_ranks_by_unit_cost_not_by_lot_size() {
        // A big cheap lot must not outrank a small expensive one.
        let mut book = LotBook::new(LotMethod::Hifo);
        book.acquire(lot("small-dear", 0, 3, 300)).unwrap();
        book.acquire(lot("big-cheap", 1, 10, 500)).unwrap();
        let records = book.dispose(sale("sell-1", 2, 1, 100)).unwrap();
        assert_eq!(records[0].acquisition_ref, "small-dear");
    }

    #[test]
    fn a_disposal_spanning_several_lots_yields_one_record_per_lot() {
        let mut book = three_lots(LotMethod::Fifo);
        let records = book
            .dispose(sale("sell-1", 3, 2_500_000_000, 250_000_000))
            .unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records
                .iter()
                .map(|r| r.acquisition_ref.as_str())
                .collect::<Vec<_>>(),
            vec!["buy-a", "buy-b", "buy-c"]
        );
        // Each row carries its own acquisition date, which is the reason
        // for one row per lot rather than one aggregate saying "various".
        assert_eq!(records[0].acquired_at_unix, T0);
        assert_eq!(records[1].acquired_at_unix, T0 + DAY);
        assert_eq!(records[2].acquired_at_unix, T0 + 2 * DAY);
        // The third lot was only half eaten.
        assert_eq!(records[2].quantity_base_units, 500_000_000);
        assert_eq!(records[2].cost_basis_base_units, 25_000_000);
        assert_eq!(book.quantity_on_hand(NATIVE_SOL_MINT), 500_000_000);
        assert_eq!(book.cost_on_hand(NATIVE_SOL_MINT), 25_000_000);

        // Nothing was created or lost on either side of the split.
        let quantity: u128 = records.iter().map(|r| r.quantity_base_units).sum();
        let proceeds: u128 = records.iter().map(|r| r.proceeds_base_units).sum();
        assert_eq!(quantity, 2_500_000_000);
        assert_eq!(proceeds, 250_000_000);
    }

    #[test]
    fn proceeds_that_do_not_divide_evenly_still_sum_to_the_proceeds() {
        // Three lots, a proceeds figure with a remainder in every share.
        let mut book = LotBook::new(LotMethod::Fifo);
        book.acquire(lot("buy-a", 0, 3, 1)).unwrap();
        book.acquire(lot("buy-b", 1, 3, 1)).unwrap();
        book.acquire(lot("buy-c", 2, 3, 1)).unwrap();
        let records = book.dispose(sale("sell-1", 3, 9, 100)).unwrap();
        let allocated: u128 = records.iter().map(|r| r.proceeds_base_units).sum();
        assert_eq!(allocated, 100);
        // Truncated shares, remainder on the last record, and no
        // fractional cent invented anywhere.
        assert_eq!(
            records
                .iter()
                .map(|r| r.proceeds_base_units)
                .collect::<Vec<_>>(),
            vec![33, 33, 34]
        );
    }

    #[test]
    fn a_lot_emptied_over_several_disposals_gives_up_exactly_its_cost() {
        // Seven base units costing 100 does not divide, so each partial
        // basis truncates. The invariant is that the shares still sum to
        // the original cost once the lot is gone.
        let mut book = LotBook::new(LotMethod::Fifo);
        book.acquire(lot("buy-a", 0, 7, 100)).unwrap();
        let mut basis_total = 0u128;
        for (i, quantity) in [3u128, 3, 1].into_iter().enumerate() {
            let records = book
                .dispose(sale(&format!("sell-{i}"), 1 + i as i64, quantity, 10))
                .unwrap();
            basis_total += records[0].cost_basis_base_units;
        }
        assert_eq!(basis_total, 100);
        assert_eq!(book.quantity_on_hand(NATIVE_SOL_MINT), 0);
        assert_eq!(book.cost_on_hand(NATIVE_SOL_MINT), 0);
        assert!(book.remaining_lots().is_empty());
    }

    #[test]
    fn disposing_more_than_is_held_is_an_error_and_changes_nothing() {
        let mut book = three_lots(LotMethod::Fifo);
        let before = book.remaining_lots();
        let err = book
            .dispose(sale("sell-1", 3, 3_000_000_001, 999))
            .unwrap_err();
        assert!(err.contains("holds only 3000000000"), "{err}");
        assert!(err.contains("missing acquisition"), "{err}");
        // The book is exactly as it was, so a caller that fixes the
        // missing acquisition and replays gets the same answer as one
        // that never made the mistake.
        assert_eq!(book.remaining_lots(), before);
        assert_eq!(book.quantity_on_hand(NATIVE_SOL_MINT), 3_000_000_000);
    }

    #[test]
    fn disposing_from_an_empty_book_is_an_error_not_a_short_position() {
        let mut book = LotBook::new(LotMethod::Fifo);
        let err = book.dispose(sale("sell-1", 0, 1, 1)).unwrap_err();
        assert!(err.contains("holds only 0"), "{err}");
    }

    #[test]
    fn a_disposal_of_another_mint_does_not_reach_these_lots() {
        let mut book = three_lots(LotMethod::Fifo);
        let mut event = sale("sell-1", 3, 1, 1);
        event.mint = USDC.to_string();
        assert!(book.dispose(event).is_err());
        assert_eq!(book.quantity_on_hand(NATIVE_SOL_MINT), 3_000_000_000);
    }

    #[test]
    fn a_sale_below_cost_is_a_negative_gain() {
        let mut book = LotBook::new(LotMethod::Fifo);
        book.acquire(lot("buy-a", 0, 1_000_000_000, 90_000_000))
            .unwrap();
        let records = book
            .dispose(sale("sell-1", 1, 1_000_000_000, 20_000_000))
            .unwrap();
        assert_eq!(records[0].gain_base_units, -70_000_000);
        assert!(records[0].gain_base_units < 0);
        assert_eq!(total_gain(&records).unwrap(), -70_000_000);
        assert!(records[0].canonical_line().contains("\t-70000000\t"));
    }

    #[test]
    fn the_evidence_class_survives_from_the_lot_onto_every_record() {
        let mut book = LotBook::new(LotMethod::Fifo);
        // An airdrop priced by a feed, then a swap priced by the chain.
        book.acquire(Lot {
            evidence: BasisEvidence::OracleDerived {
                source: "pyth:SOL/USD".to_string(),
                priced_at_unix: T0 - 60,
            },
            ..lot("airdrop", 0, 1_000_000_000, 20_000_000)
        })
        .unwrap();
        book.acquire(lot("swap", 1, 1_000_000_000, 30_000_000))
            .unwrap();

        let records = book
            .dispose(sale("sell-1", 2, 2_000_000_000, 100_000_000))
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].basis_evidence,
            BasisEvidence::OracleDerived {
                source: "pyth:SOL/USD".to_string(),
                priced_at_unix: T0 - 60,
            }
        );
        assert!(!records[0].basis_is_exact());
        assert_eq!(records[1].basis_evidence, BasisEvidence::ExactFromChain);
        assert!(records[1].basis_is_exact());

        // The two are distinguishable in the hashed output, not only in
        // memory, so a reviewer reading the anchored file can tell which
        // number rests on somebody else's price.
        assert!(records[0]
            .canonical_line()
            .contains("oracle_derived\tpyth:SOL/USD\t"));
        assert!(records[1]
            .canonical_line()
            .contains("exact_from_chain\t-\t-"));
        assert_ne!(records[0].basis_evidence, records[1].basis_evidence);
    }

    #[test]
    fn an_oracle_basis_cannot_be_recorded_without_naming_its_source() {
        let mut book = LotBook::new(LotMethod::Fifo);
        let err = book
            .acquire(Lot {
                evidence: BasisEvidence::OracleDerived {
                    source: "   ".to_string(),
                    priced_at_unix: T0,
                },
                ..lot("airdrop", 0, 1, 1)
            })
            .unwrap_err();
        assert!(err.contains("oracle source is empty"), "{err}");

        // A source carrying a separator would shift the columns after it
        // in the canonical line, so it is refused too.
        let err = book
            .acquire(Lot {
                evidence: BasisEvidence::OracleDerived {
                    source: "feed\tname".to_string(),
                    priced_at_unix: T0,
                },
                ..lot("airdrop", 0, 1, 1)
            })
            .unwrap_err();
        assert!(err.contains("separator"), "{err}");
    }

    #[test]
    fn a_zero_quantity_acquisition_is_refused() {
        let mut book = LotBook::new(LotMethod::Fifo);
        let err = book.acquire(lot("buy-a", 0, 0, 500)).unwrap_err();
        assert!(err.contains("quantity of zero"), "{err}");
        assert!(book.remaining_lots().is_empty());
    }

    #[test]
    fn a_zero_quantity_disposal_produces_no_record_but_zero_for_money_does_not() {
        let mut book = three_lots(LotMethod::Fifo);
        let records = book.dispose(sale("sell-1", 3, 0, 0)).unwrap();
        assert!(records.is_empty());
        assert_eq!(book.quantity_on_hand(NATIVE_SOL_MINT), 3_000_000_000);

        let err = book.dispose(sale("sell-2", 4, 0, 5_000)).unwrap_err();
        assert!(err.contains("disposed of nothing"), "{err}");
    }

    #[test]
    fn a_lot_with_no_cost_reports_its_whole_proceeds_as_gain() {
        // A free airdrop is a zero basis position, not a missing one.
        let mut book = LotBook::new(LotMethod::Fifo);
        book.acquire(lot("airdrop", 0, 1_000, 0)).unwrap();
        let records = book.dispose(sale("sell-1", 1, 1_000, 7_500)).unwrap();
        assert_eq!(records[0].cost_basis_base_units, 0);
        assert_eq!(records[0].gain_base_units, 7_500);
    }

    #[test]
    fn events_arriving_out_of_time_order_are_refused() {
        let mut book = three_lots(LotMethod::Fifo);
        book.dispose(sale("sell-1", 5, 1_000_000_000, 60_000_000))
            .unwrap();
        // An acquisition back dated behind a disposal that has already
        // been reported would change a record already handed out.
        let err = book.acquire(lot("buy-late", 4, 1_000, 1_000)).unwrap_err();
        assert!(err.contains("time order"), "{err}");
        let err = book
            .dispose(sale("sell-early", 4, 1_000_000_000, 60_000_000))
            .unwrap_err();
        assert!(err.contains("time order"), "{err}");
        // Same second is fine: two events can share a block time.
        assert!(book.acquire(lot("buy-same", 5, 1_000, 1_000)).is_ok());
    }

    #[test]
    fn the_same_script_run_twice_is_byte_identical() {
        // The whole point of anchoring a hash of this output is that an
        // auditor re-derives it. If two runs could differ, the anchor
        // would prove nothing at all.
        let run = |method: LotMethod| {
            let mut book = LotBook::new(method);
            book.acquire(Lot {
                evidence: BasisEvidence::OracleDerived {
                    source: "pyth:SOL/USD".to_string(),
                    priced_at_unix: T0,
                },
                ..lot("buy-a", 0, 1_000_000_000, 20_000_000)
            })
            .unwrap();
            book.acquire(lot("buy-b", 1, 1_000_000_000, 90_000_000))
                .unwrap();
            book.acquire(lot("buy-c", 1, 1_000_000_000, 90_000_000))
                .unwrap();
            book.acquire(lot("buy-d", 2, 1_000_000_000, 50_000_000))
                .unwrap();
            let mut records = book.dispose(sale("sell-1", 3, 2_500_000_000, 137)).unwrap();
            records.extend(book.dispose(sale("sell-2", 4, 1_000_000_000, 71)).unwrap());
            sort_disposals(&mut records);
            (lines(&records).join("\n"), book.remaining_lots())
        };
        for method in [LotMethod::Fifo, LotMethod::Hifo] {
            let first = run(method);
            let second = run(method);
            assert_eq!(first.0, second.0);
            assert_eq!(first.1, second.1);
            // Two lots that tie on time and on unit cost still come out
            // in one fixed order rather than whichever the sort felt
            // like, which is what makes the repeat meaningful.
            assert!(first.0.contains("buy-b"), "{}", first.0);
            assert!(first.0.contains("buy-c"), "{}", first.0);
        }
    }

    #[test]
    fn sorting_records_does_not_depend_on_the_order_they_were_collected() {
        let mut book = three_lots(LotMethod::Fifo);
        let mut records = book
            .dispose(sale("sell-1", 3, 2_500_000_000, 250_000_000))
            .unwrap();
        let mut reversed: Vec<Disposal> = records.iter().rev().cloned().collect();
        sort_disposals(&mut records);
        sort_disposals(&mut reversed);
        assert_eq!(lines(&records), lines(&reversed));
    }

    #[test]
    fn valuing_a_lot_at_an_oracle_price_uses_checked_multiplication() {
        // One SOL at 20.500000 USD, nine decimals in, six decimals out.
        assert_eq!(
            oracle_cost(1_000_000_000, 20_500_000, 9).unwrap(),
            20_500_000
        );
        // A third of a SOL truncates rather than rounding, and the
        // truncation is downward on the basis, never on the gain.
        assert_eq!(oracle_cost(333_333_333, 20_500_000, 9).unwrap(), 6_833_333);
        assert_eq!(oracle_cost(0, 20_500_000, 9).unwrap(), 0);

        // Right at the edge of u128 and one step past it.
        let half = u128::MAX / 2;
        assert!(oracle_cost(half, 2, 0).is_ok());
        let err = oracle_cost(half + 1, 3, 0).unwrap_err();
        assert!(err.contains("overflows"), "{err}");
        assert!(oracle_cost(1, 1, u32::MAX).is_err());
    }

    #[test]
    fn a_basis_allocation_that_cannot_be_represented_is_refused_not_wrapped() {
        let mut book = LotBook::new(LotMethod::Fifo);
        book.acquire(lot("buy-a", 0, 4, u128::MAX)).unwrap();
        // A partial consumption multiplies the remaining cost by the
        // quantity taken, which is exactly where a wrapped product would
        // become a plausible looking basis.
        let err = book.dispose(sale("sell-1", 1, 3, 10)).unwrap_err();
        assert!(err.contains("overflows"), "{err}");
        // Refused, and the lot is untouched.
        assert_eq!(book.cost_on_hand(NATIVE_SOL_MINT), u128::MAX);

        // Consuming the whole lot needs no multiplication, so it gets as
        // far as the signed conversion and is refused there instead.
        let err = book.dispose(sale("sell-1", 1, 4, 10)).unwrap_err();
        assert!(
            err.contains("too large to take a signed difference"),
            "{err}"
        );
    }

    #[test]
    fn allocating_proceeds_that_cannot_be_represented_is_refused() {
        let mut book = LotBook::new(LotMethod::Fifo);
        book.acquire(lot("buy-a", 0, 2, 1)).unwrap();
        book.acquire(lot("buy-b", 1, 2, 1)).unwrap();
        let err = book.dispose(sale("sell-1", 2, 4, u128::MAX)).unwrap_err();
        assert!(err.contains("overflows"), "{err}");
        assert_eq!(book.quantity_on_hand(NATIVE_SOL_MINT), 4);
    }

    #[test]
    fn unit_costs_compare_exactly_where_cross_multiplication_would_overflow() {
        // Cross multiplying any of these pairs wraps u128. The
        // comparison still has to be exact, because a comparator that
        // wraps produces a sort order that is not an order.
        let big = u128::MAX;
        assert_eq!(cmp_ratio(big, big - 1, big, big - 1), Ordering::Equal);
        assert_eq!(cmp_ratio(big, big - 1, big - 1, big), Ordering::Greater);
        assert_eq!(cmp_ratio(big - 1, big, big, big - 1), Ordering::Less);
        assert_eq!(cmp_ratio(big, 3, big, 4), Ordering::Greater);

        // And the ordinary cases it is really used for.
        assert_eq!(cmp_ratio(1, 3, 2, 6), Ordering::Equal);
        assert_eq!(cmp_ratio(1, 2, 2, 3), Ordering::Less);
        assert_eq!(cmp_ratio(300, 3, 500, 10), Ordering::Greater);
        assert_eq!(cmp_ratio(0, 5, 0, 7), Ordering::Equal);
        assert_eq!(cmp_ratio(0, 5, 1, 7), Ordering::Less);
    }

    #[test]
    fn hifo_over_a_huge_book_still_picks_the_dearest_unit() {
        // The same near-overflow numbers, this time through the real
        // selection path rather than the comparator on its own.
        let mut book = LotBook::new(LotMethod::Hifo);
        book.acquire(lot("cheap", 0, u128::MAX / 2, u128::MAX / 4))
            .unwrap();
        book.acquire(lot("dear", 1, 4, 4)).unwrap();
        let records = book.dispose(sale("sell-1", 2, 4, 4)).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].acquisition_ref, "dear");
    }

    #[test]
    fn a_position_too_large_to_add_up_is_refused_rather_than_wrapped() {
        // Two lots whose quantities do not fit in one integer cannot be
        // summed into an amount on hand, so the disposal is refused
        // instead of being checked against a wrapped total.
        let mut book = LotBook::new(LotMethod::Fifo);
        book.acquire(lot("buy-a", 0, u128::MAX, 1)).unwrap();
        book.acquire(lot("buy-b", 1, 4, 1)).unwrap();
        let err = book.dispose(sale("sell-1", 2, 1, 1)).unwrap_err();
        assert!(err.contains("overflows"), "{err}");
    }

    #[test]
    fn a_book_survives_a_snapshot_round_trip_byte_identically() {
        let mut book = three_lots(LotMethod::Fifo);
        book.dispose(sale("sell-1", 3, 1_000_000_000, 60_000_000))
            .unwrap();

        let snap = book.snapshot();
        let restored = LotBook::from_snapshot(snap.clone()).unwrap();
        assert_eq!(restored.snapshot(), snap);
        assert_eq!(restored.method(), LotMethod::Fifo);
        assert_eq!(restored.quantity_on_hand(NATIVE_SOL_MINT), 2_000_000_000);
        assert_eq!(restored.cost_on_hand(NATIVE_SOL_MINT), 140_000_000);

        // A restored book continues to book disposals identically.
        let mut original = book;
        let mut resumed = restored;
        for _ in 0..4 {
            let event = sale("sell-next", 4, 500_000_000, 40_000_000);
            let a = original.dispose(event.clone()).unwrap();
            let b = resumed.dispose(event).unwrap();
            assert_eq!(lines(&a), lines(&b));
        }
        assert_eq!(original.snapshot(), resumed.snapshot());
    }

    #[test]
    fn a_snapshot_with_a_lying_remaining_quantity_is_refused() {
        let book = three_lots(LotMethod::Fifo);
        let mut snap = book.snapshot();
        snap.open_lots[0].remaining_quantity = snap.open_lots[0].lot.quantity_base_units + 1;
        let err = LotBook::from_snapshot(snap).unwrap_err();
        assert!(err.contains("more remaining"), "{err}");
    }

    #[test]
    fn the_method_is_read_from_config_and_a_missing_one_fails_closed() {
        let section = HashMap::from([("lot_method".to_string(), " HIFO ".to_string())]);
        assert_eq!(LotMethod::from_section(&section).unwrap(), LotMethod::Hifo);
        let section = HashMap::from([("lot_method".to_string(), "fifo".to_string())]);
        assert_eq!(LotMethod::from_section(&section).unwrap(), LotMethod::Fifo);

        let err = LotMethod::from_section(&HashMap::new()).unwrap_err();
        assert!(err.contains("no lot_method configured"), "{err}");
        let section = HashMap::from([("lot_method".to_string(), "lifo".to_string())]);
        let err = LotMethod::from_section(&section).unwrap_err();
        assert!(err.contains("fifo or hifo"), "{err}");
    }

    #[test]
    fn a_book_reports_the_method_it_was_opened_with_on_every_record() {
        for method in [LotMethod::Fifo, LotMethod::Hifo] {
            let mut book = three_lots(method);
            assert_eq!(book.method(), method);
            let records = book.dispose(sale("sell-1", 3, 1_000_000_000, 1)).unwrap();
            assert!(records.iter().all(|r| r.method == method));
            assert!(records[0].canonical_line().contains(method.as_str()));
        }
    }

    #[test]
    fn ledger_events_convert_into_lots_and_disposals() {
        let revenue = LedgerEvent {
            block_time_unix: Some(T0),
            kind: EventKind::Revenue,
            amount_base_units: 500,
            mint: USDC.to_string(),
            decimals: 6,
            counterparty: Some("Customer".to_string()),
            counterparty_address: None,
            signature: "sig1".to_string(),
            is_classified: false,
        };

        let opened = lot_from_event(&revenue, 10_000_000, BasisEvidence::ExactFromChain).unwrap();
        assert_eq!(opened.mint, USDC);
        assert_eq!(opened.quantity_base_units, 500);
        assert_eq!(opened.acquired_at_unix, T0);
        assert_eq!(opened.acquisition_ref, "sig1");

        let payout = LedgerEvent {
            block_time_unix: Some(T0 + DAY),
            kind: EventKind::Payout,
            amount_base_units: -200, // must be negative
            mint: USDC.to_string(),
            decimals: 6,
            counterparty: Some("Vendor".to_string()),
            counterparty_address: None,
            signature: "sig2".to_string(),
            is_classified: false,
        };

        let closing = disposal_from_event(&payout, 4_200_000).unwrap();

        let mut book = LotBook::new(LotMethod::Fifo);
        book.acquire(opened).unwrap();
        let records = book.dispose(closing).unwrap();

        assert_eq!(records[0].gain_base_units, 200_000);
    }

    #[test]
    fn conversions_refuse_what_they_cannot_book_honestly() {
        let mut event = LedgerEvent {
            block_time_unix: Some(3000),
            kind: EventKind::Income, // trigger refusal
            amount_base_units: 1000,
            mint: "USDC".to_string(),
            decimals: 6,
            counterparty: Some("Client".to_string()),
            counterparty_address: None,
            signature: "sig3".to_string(),
            is_classified: false,
        };

        // return correct error
        let err = lot_from_event(&event, 1, BasisEvidence::ExactFromChain).unwrap_err();
        assert!(err.contains("not revenue"), "{err}");

        // A fee is arguably a disposal of SOL and arguably an expense.
        // The module refuses to make that election quietly.
        event.block_time_unix = Some(T0);
        event.kind = EventKind::FeePaid;
        event.amount_base_units = -5_000;
        let err = disposal_from_event(&event, 0).unwrap_err();
        assert!(err.contains("operator's call"), "{err}");
        let err = lot_from_event(&event, 1, BasisEvidence::ExactFromChain).unwrap_err();
        assert!(err.contains("not revenue"), "{err}");
    }

    #[test]
    fn canonical_lines_are_fixed_in_shape() {
        let mut book = LotBook::new(LotMethod::Fifo);
        book.acquire(Lot {
            mint: USDC.to_string(),
            acquisition_ref: "sig-in".to_string(),
            acquired_at_unix: T0,
            quantity_base_units: 1_000_000,
            cost_base_units: 900_000,
            evidence: BasisEvidence::ExactFromChain,
        })
        .unwrap();
        let records = book
            .dispose(DisposalEvent {
                mint: USDC.to_string(),
                disposal_ref: "sig-out".to_string(),
                disposed_at_unix: T0 + DAY,
                quantity_base_units: 1_000_000,
                proceeds_base_units: 1_100_000,
            })
            .unwrap();
        assert_eq!(
            records[0].canonical_line(),
            format!(
                "sig-out\t{}\t{USDC}\tfifo\t1000000\t1100000\tsig-in\t{T0}\t900000\t200000\t\
                 exact_from_chain\t-\t-",
                T0 + DAY
            )
        );
        assert_eq!(records[0].canonical_line().split('\t').count(), 13);
    }
}
