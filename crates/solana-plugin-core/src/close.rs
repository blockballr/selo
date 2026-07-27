//! The daily close: a day of trading turned into one hashable record.
//!
//! Settlement decides that a payment happened. The ledger normalizes what
//! moved. Neither of them says what was sold, because chain data does not
//! carry a sku. This module joins the two halves: it takes the sales the
//! chain proves were paid and the quote log's record of what each of those
//! orders contained, and produces a single canonical, itemized record of
//! the day plus a commitment to it that can be anchored on chain.
//!
//! Why determinism is the point, and not a nicety. The whole value of an
//! anchor is that an auditor who trusts nothing the shop says can go to
//! the chain, re-derive the day from the same transactions, and check that
//! it hashes to the value the shop published. That check means something
//! only if the derivation is a pure function of chain state and the quote
//! log. So byte-identical output for identical input is the audit
//! property, restated.
//!
//! It is simultaneously the anti-tampering property, which is the reason
//! it is enforced this hard. The shop agent reads customer messages all
//! day, which means it reads text an attacker wrote. If any number in the
//! close were model authored, or if the output depended on the order in
//! which the agent happened to fetch things, then a persuasive message at
//! closing time would be a path to a falsified book. Nothing here is
//! model authored. Every amount is copied from a `ConfirmedSale` that came
//! out of a balance delta, every price is copied from a `QuoteEntry` that
//! was written at issuance from operator config, and the output is put
//! through a total order over every field so the input order cannot reach
//! it. A prompt-injected agent can choose which day to close. It has no
//! surface on which to change what that day contains.
//!
//! The same reasoning explains the refusals. Where two records disagree,
//! or where a sale has no quote behind it, this module stops rather than
//! picking one. A close that silently resolved a disagreement would be
//! publishing a number no auditor could re-derive, which is worse than
//! publishing nothing.
//!
//! # Which hash, and why
//!
//! Poseidon over BN254, through `zk::hash_pair`, rather than a bare
//! SHA-256 of the record text. The commitment is meant to live in a ZK
//! compression context, where state is a Poseidon merkle tree and a proof
//! about that state is checked inside a circuit. A SHA-256 digest is
//! enormously expensive to prove in a BN254 circuit, so committing with
//! SHA-256 would produce a number that is anchorable but not usefully
//! provable, which defeats the reason for anchoring it there.
//!
//! Poseidon does not take arbitrary bytes, though. It operates on BN254
//! field elements, and a canonical line is variable length UTF-8. The
//! bridge between the two is the standard one, and the one Light Protocol
//! itself uses in `hash_to_bn254_field_size_be`: hash the bytes with
//! SHA-256, then force the digest below the field modulus by zeroing its
//! leading byte. That leaves a 248 bit value, and 2^248 is comfortably
//! below the BN254 scalar modulus of roughly 2^253.5, so every possible
//! input maps to a valid field element on the first try. No rejection
//! loop, no input-dependent branch, no way for one input to have two
//! images. SHA-256 appears here only as that embedding; the commitment
//! itself is Poseidon throughout.
//!
//! The lines are then folded into a Poseidon merkle tree rather than
//! hashed as one blob, which buys something a flat hash does not: an
//! auditor can be shown that one specific sale is in the anchored day,
//! with a proof `zk::verify_proof` already checks, without being handed
//! the rest of the day. The tree root is finally bound to a header
//! element carrying the merchant, the day bounds, and the line count, so
//! one day's root cannot be replayed as another day's and the padding
//! used to square the tree cannot be reinterpreted as extra sales.
//!
//! # Privacy is enforced here, not assumed
//!
//! Under ZK compression the committed data is public through the indexer.
//! Anything that reaches the anchored record is world readable and cannot
//! be withdrawn. Customer identity therefore must never enter it: no
//! phone numbers, no names, no message content.
//!
//! A property that holds only while nobody makes a mistake is not a
//! property, so it is enforced structurally and then checked. Structurally,
//! the record has exactly one free text field. The signature is validated
//! as a 64 byte base58 signature, the mint as a 32 byte base58 pubkey, and
//! everything else is an integer, so none of those can carry a sentence at
//! all. That leaves the sku, which comes from operator config rather than
//! from customer text, and the sku is scanned by `reject_identity_shaped`
//! before any line is built.
//!
//! The scan is deliberately biased towards false positives. A run of seven
//! or more digits, counted across the separators a written phone number
//! uses, is refused, as is an `@` and any control character. A catalog
//! entry named "SKU-1234567" will therefore fail to close, and that is the
//! intended trade: a refused close is a human looking at a config file for
//! five minutes, while a leaked phone number is permanent and public.
//!
//! What the scan does not claim to do is detect a name. There is no
//! mechanical test for one. The defence against a name is the structural
//! half above: there is no field for it to go in, and the one free text
//! field is not reachable from customer input.
//!
//! Wallet addresses are not treated as identity. The payer already signed
//! a public transaction, so its address is on chain by nature of the
//! payment and republishing it reveals nothing new. It is left out of the
//! record all the same, for a different reason: the signature already
//! points at the transaction that names it, so carrying the payer would
//! add data without adding a fact.

use sha2::{Digest, Sha256};

use crate::address::{decode_pubkey, validate_pubkey};
use crate::message::{compile_message, Instruction};
use crate::quote::AmountTag;
use crate::quotelog::QuoteEntry;
use crate::settle::ConfirmedSale;
use crate::tx::validate_signature;
use crate::zk::hash_pair;

/// Version tag for the canonical form.
///
/// It is the first thing in the header line and the first thing in the
/// anchor memo, and it is part of the commitment. Anything that changes
/// the field order, the separators, or the hashing has to change this
/// too, because otherwise two incompatible schemes would produce numbers
/// that look interchangeable and are not.
pub const CLOSE_DOMAIN: &str = "daybook-close-v1";

/// The SPL Memo program, version three.
///
/// A memo is the right instrument for an anchor: it writes to no account,
/// so there is no state to rent, migrate, or get wrong, and the payload
/// lands in the transaction where any indexer already reads it.
pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// A digit run this long or longer is treated as a phone number.
///
/// Seven is the shortest subscriber number that is dialable on its own,
/// so it is the floor below which a run cannot be a phone number and
/// above which it might be.
pub const MIN_PHONE_DIGITS: usize = 7;

/// The longest sku that may appear in a record.
///
/// A sku is an identifier. Anything longer is prose, and prose in an
/// itemized record is a place for a sentence about a customer to hide.
pub const MAX_SKU_BYTES: usize = 64;

/// The most lines one close will carry.
///
/// The tag encoding allows ninety nine sales points times a hundred
/// counter values, so a day cannot honestly exceed 9,900 orders. The cap
/// is set above that and enforced anyway, because an unbounded line count
/// is an unbounded tree.
pub const MAX_CLOSE_LINES: usize = 16_384;

/// The most bytes an anchor memo may carry.
///
/// Comfortably inside what fits in a single transaction alongside the
/// signature and header, so a close never fails at submission time for a
/// reason that could have been caught here.
pub const MAX_MEMO_BYTES: usize = 566;

/// One itemized sale, as it will be hashed.
///
/// The order reference, what was sold, what it cost, and the signature
/// that proves it was paid. Nothing else, and in particular nothing about
/// who paid: see the privacy note in the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseLine {
    /// Which terminal issued the order.
    pub sales_point: u8,
    /// Which order at that terminal.
    pub order_counter: u8,
    /// Catalog identifier of what was sold.
    pub sku: String,
    pub quantity: u32,
    /// Catalog price for one unit, in the mint's smallest unit.
    pub unit_price_base_units: u64,
    /// What the chain shows arriving, tag included. Read, never chosen.
    pub amount_base_units: u64,
    pub mint: String,
    /// The payment that proves this line. An auditor opens it and sees
    /// the same amount arrive at the same merchant.
    pub signature: String,
}

impl CloseLine {
    /// The total order lines are sorted by.
    ///
    /// Every field participates, so two lines that compare equal here are
    /// equal in full and no tie can be broken by input order. The
    /// signature leads because it is the one component unique for all
    /// time, which puts the common case in one comparison.
    fn sort_key(&self) -> (&str, u8, u8, &str, u32, u64, u64, &str) {
        (
            &self.signature,
            self.sales_point,
            self.order_counter,
            &self.sku,
            self.quantity,
            self.unit_price_base_units,
            self.amount_base_units,
            &self.mint,
        )
    }

    /// The line as one canonical line of text.
    ///
    /// Tab separated, fields in this order, integers in base ten with no
    /// separators. This is the form that gets hashed, so it is fixed:
    /// anything that changes it changes every historical anchor. The tab
    /// is safe as a separator only because `reject_identity_shaped`
    /// refuses a sku containing one.
    pub fn canonical_line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.sales_point,
            self.order_counter,
            self.sku,
            self.quantity,
            self.unit_price_base_units,
            self.amount_base_units,
            self.mint,
        ) + "\t"
            + &self.signature
    }

    /// The Poseidon leaf for this line.
    pub fn leaf(&self) -> [u8; 32] {
        field_element(format!("{CLOSE_DOMAIN}/line\n{}", self.canonical_line()).as_bytes())
    }
}

/// A day of trading, itemized, ordered, and committed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyClose {
    /// The wallet the day's money arrived at.
    pub merchant: String,
    /// Start of the day, inclusive, as a unix time.
    pub day_start_unix: i64,
    /// End of the day, exclusive.
    pub day_end_unix: i64,
    /// Every sale, in canonical order.
    pub lines: Vec<CloseLine>,
    /// Poseidon merkle root over the lines.
    pub merkle_root: [u8; 32],
    /// The anchored value: the root bound to the day's header.
    pub commitment: [u8; 32],
}

impl DailyClose {
    /// The whole day as canonical text, header first, one line per sale.
    ///
    /// Every line is terminated rather than separated, so an empty day is
    /// the header and nothing else and there is no question of whether a
    /// trailing newline belongs. This is what an auditor re-derives.
    pub fn canonical_record(&self) -> String {
        let mut out = self.header_line();
        out.push('\n');
        for line in &self.lines {
            out.push_str(&line.canonical_line());
            out.push('\n');
        }
        out
    }

    /// The header, which binds the commitment to this day and no other.
    pub fn header_line(&self) -> String {
        format!(
            "{CLOSE_DOMAIN}\t{}\t{}\t{}\t{}",
            self.merchant,
            self.day_start_unix,
            self.day_end_unix,
            self.lines.len()
        )
    }

    /// The Poseidon leaves, in canonical order.
    pub fn leaves(&self) -> Vec<[u8; 32]> {
        self.lines.iter().map(CloseLine::leaf).collect()
    }

    /// The commitment as base58, which is how it appears in the memo.
    pub fn commitment_base58(&self) -> String {
        bs58::encode(self.commitment).into_string()
    }

    /// Total received across the day, in the smallest unit.
    ///
    /// `u128` because a day of a high supply mint can exceed `u64` once
    /// summed, and a total that silently wrapped would be the one number
    /// in this module nobody checks.
    pub fn total_base_units(&self) -> u128 {
        self.lines
            .iter()
            .map(|l| l.amount_base_units as u128)
            .sum()
    }

    /// The memo payload that carries the commitment on chain.
    ///
    /// Self describing on purpose. Someone reading the transaction years
    /// later gets the scheme version, the merchant, the day, how many
    /// sales it covers, and the commitment, without needing this code.
    pub fn anchor_memo(&self) -> String {
        format!(
            "{CLOSE_DOMAIN} {} {} {} {} {}",
            self.merchant,
            self.day_start_unix,
            self.day_end_unix,
            self.lines.len(),
            self.commitment_base58()
        )
    }

    /// The merkle proof for one line, in the form `zk::verify_proof` takes.
    ///
    /// This is what lets a single sale be shown to be part of the anchored
    /// day without disclosing the others, which is the reason the lines
    /// are a tree rather than one digest.
    pub fn merkle_proof(&self, index: usize) -> Result<Vec<[u8; 32]>, String> {
        let mut level = self.leaves();
        if index >= level.len() {
            return Err(format!(
                "line {index} is outside this close, which has {} lines",
                level.len()
            ));
        }
        let empty = empty_leaf();
        let mut idx = index;
        let mut proof = Vec::new();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(empty);
            }
            proof.push(level[idx ^ 1]);
            level = fold_level(&level)?;
            idx /= 2;
        }
        Ok(proof)
    }
}

/// An unsigned transaction that writes the commitment to the chain.
///
/// Unsigned because this module holds no key. The merchant signs, which
/// is also what makes the anchor mean anything: an anchor anyone could
/// write is an anchor anyone could forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAnchor {
    /// Serialized legacy message, exactly what gets signed.
    pub message: Vec<u8>,
    /// The memo the message carries, so a human can read what they sign
    /// without decoding the bytes.
    pub memo: String,
    pub commitment: [u8; 32],
    pub merchant: String,
    pub blockhash: String,
}

/// Turn a day's confirmed sales and quote entries into a closed day.
///
/// The inputs are the merchant, the day's bounds, the sales the chain
/// proved, and the quote log. There is no amount argument, no total, and
/// no override, which is the same stance `settle` and `refund` take: the
/// caller chooses which day to close and the code decides what is in it.
///
/// The window is checked rather than applied. A sale outside it is an
/// error, not a line quietly dropped, because a close that filtered by
/// its own bounds would let a caller shrink a day by moving them and hide
/// money in the gap. The mismatch is made visible instead.
///
/// The refusals, in the order they are checked:
///
/// - The merchant is not a valid address.
/// - The day's bounds are not a forward interval.
/// - There are more sales than `MAX_CLOSE_LINES`.
/// - A sale carries no block time, so it cannot be placed in any day.
/// - A sale falls outside the stated window.
/// - Two sales share a signature, which would count one payment twice.
/// - No quote entry matches a sale's order reference and amount, so there
///   is no record of what was sold.
/// - The matching quote entries disagree with each other about the item.
/// - The quote entry and the chain disagree about the sku or the quantity.
///   The sale's sku was copied from the quote at match time, so a
///   disagreement means one of the two records was altered afterwards.
/// - The itemization does not reconcile: quantity times unit price plus
///   the order's tag must equal the amount the chain shows, exactly.
/// - A sku is identity shaped, empty, over length, or carries a character
///   that would break the canonical form.
pub fn build_close(
    merchant: &str,
    day_start_unix: i64,
    day_end_unix: i64,
    sales: &[ConfirmedSale],
    quotes: &[QuoteEntry],
) -> Result<DailyClose, String> {
    let merchant = validate_pubkey(merchant)
        .map_err(|e| format!("merchant address is not a valid Solana address: {e}"))?;
    if day_end_unix <= day_start_unix {
        return Err(format!(
            "the day runs from {day_start_unix} to {day_end_unix}, which is not a forward \
             interval; a close needs a day it can name"
        ));
    }
    if sales.len() > MAX_CLOSE_LINES {
        return Err(format!(
            "{} sales exceeds the {MAX_CLOSE_LINES} lines one close will carry",
            sales.len()
        ));
    }

    let mut lines = Vec::with_capacity(sales.len());
    for sale in sales {
        lines.push(line_for(sale, quotes, day_start_unix, day_end_unix)?);
    }

    // The total order, applied last and over every field, so the order in
    // which the caller fetched transactions cannot reach the commitment.
    // The caller fetches over a network, and network order is not
    // something an auditor can reproduce.
    lines.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    // Duplicates are checked after sorting, where they are adjacent. Two
    // lines carrying one signature would book one payment twice, and the
    // day would still hash cleanly and still be wrong.
    for pair in lines.windows(2) {
        if pair[0].signature == pair[1].signature {
            return Err(format!(
                "payment {} appears twice in this day's sales, which would count it twice",
                pair[0].signature
            ));
        }
    }

    let leaves: Vec<[u8; 32]> = lines.iter().map(CloseLine::leaf).collect();
    let merkle_root = merkle_root(&leaves)?;
    let header = field_element(
        format!(
            "{CLOSE_DOMAIN}/day\n{merchant}\n{day_start_unix}\n{day_end_unix}\n{}",
            lines.len()
        )
        .as_bytes(),
    );
    // Binding the root to the header is what stops a root being replayed
    // under a different day or a different line count. The padding that
    // squares an odd tree is indistinguishable from a real leaf inside
    // the root alone; it is not indistinguishable once the count is in.
    let commitment = hash_pair(&merkle_root, &header)?;

    Ok(DailyClose {
        merchant,
        day_start_unix,
        day_end_unix,
        lines,
        merkle_root,
        commitment,
    })
}

/// Build the unsigned transaction that anchors a close.
///
/// One memo instruction, paid and signed by the merchant. Accounts are
/// described by meaning and laid out by `message::compile_message` rather
/// than indexed by hand, so there is no index to transpose.
pub fn prepare_anchor(close: &DailyClose, recent_blockhash: &str) -> Result<PreparedAnchor, String> {
    let merchant = decode_pubkey(&close.merchant)
        .map_err(|e| format!("merchant address is not a valid Solana address: {e}"))?;
    let memo_program = decode_pubkey(MEMO_PROGRAM_ID)
        .map_err(|e| format!("memo program id is not a valid Solana address: {e}"))?;

    let memo = close.anchor_memo();
    if memo.len() > MAX_MEMO_BYTES {
        return Err(format!(
            "anchor memo is {} bytes, more than the {MAX_MEMO_BYTES} one transaction carries",
            memo.len()
        ));
    }

    // The memo program reads the signers from the accounts it is given.
    // Naming the merchant here is what records on chain that this
    // merchant published this commitment, rather than that somebody did.
    let message = compile_message(
        &merchant,
        &[Instruction {
            program_id: memo_program,
            accounts: vec![crate::message::AccountMeta::signer_writable(merchant)],
            data: memo.as_bytes().to_vec(),
        }],
        recent_blockhash,
    )?;

    Ok(PreparedAnchor {
        message,
        memo,
        commitment: close.commitment,
        merchant: close.merchant.clone(),
        blockhash: recent_blockhash.trim().to_string(),
    })
}

/// True when `text` carries something shaped like a phone number.
///
/// The run is counted across the separators a written number uses, so
/// "0803 123 4567" and "(555) 010-1234" are caught along with the bare
/// digits, while "RICE-5KG" is not: the letter breaks the run.
pub fn looks_like_phone_number(text: &str) -> bool {
    let mut run = 0usize;
    for c in text.chars() {
        if c.is_ascii_digit() {
            run += 1;
            if run >= MIN_PHONE_DIGITS {
                return true;
            }
        } else if !matches!(c, ' ' | '-' | '.' | '(' | ')' | '+' | '/') {
            // A separator continues a run, anything else ends it.
            run = 0;
        }
    }
    false
}

/// Refuse a value that could carry customer identity into the record, or
/// that would break the canonical form.
///
/// Applied to the sku, which is the record's only free text field. The
/// control character check is not cosmetic: the canonical form is tab
/// separated and newline terminated, so a sku carrying either could make
/// two different days serialize to the same bytes.
pub fn reject_identity_shaped(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} is empty, so the line names nothing"));
    }
    if value.len() > MAX_SKU_BYTES {
        return Err(format!(
            "{field} is {} bytes, more than the {MAX_SKU_BYTES} an identifier may use; \
             anything longer is prose, and prose does not belong in an anchored record",
            value.len()
        ));
    }
    if let Some(c) = value.chars().find(|c| c.is_control()) {
        return Err(format!(
            "{field} contains the control character {:?}, which would break the canonical \
             form and could make two different days serialize identically",
            c
        ));
    }
    if value.contains('@') {
        return Err(format!(
            "refusing to close: {field} contains '@', which is shaped like contact details. \
             The anchored record is public through the indexer, so customer identity in it \
             would be world readable and could not be withdrawn"
        ));
    }
    if looks_like_phone_number(value) {
        return Err(format!(
            "refusing to close: {field} contains a run of {MIN_PHONE_DIGITS} or more digits, \
             which is shaped like a phone number. The anchored record is public through the \
             indexer, so customer identity in it would be world readable and could not be \
             withdrawn. If this is a legitimate catalog identifier, rename it"
        ));
    }
    Ok(())
}

/// Map arbitrary bytes onto a BN254 field element.
///
/// SHA-256 for the compression, then the leading byte is zeroed so the
/// result is below 2^248 and therefore below the field modulus. Every
/// input maps on the first attempt, so the mapping is total and carries
/// no input-dependent branch. See the module documentation for why this
/// is the embedding rather than the commitment.
pub fn field_element(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out[0] = 0;
    out
}

/// The padding leaf, used to square a level with an odd number of nodes.
///
/// A fixed domain separated constant rather than a repeat of the last
/// real leaf, because duplicating a leaf lets a shorter day be presented
/// as a longer one with the same root.
pub fn empty_leaf() -> [u8; 32] {
    field_element(format!("{CLOSE_DOMAIN}/empty").as_bytes())
}

/// Hash one level of the tree into the next.
fn fold_level(level: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, String> {
    let mut next = Vec::with_capacity(level.len() / 2);
    for pair in level.chunks(2) {
        next.push(hash_pair(&pair[0], &pair[1])?);
    }
    Ok(next)
}

/// Fold leaves into a Poseidon merkle root, padding odd levels.
///
/// An empty day is the padding leaf itself. That is a real value rather
/// than a special case: a day with no sales has a commitment like any
/// other, so a shop that traded nothing still publishes a checkable
/// statement that it traded nothing.
fn merkle_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], String> {
    if leaves.is_empty() {
        return Ok(empty_leaf());
    }
    let empty = empty_leaf();
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(empty);
        }
        level = fold_level(&level)?;
    }
    Ok(level[0])
}

/// Join one confirmed sale to the quote log and check the result.
fn line_for(
    sale: &ConfirmedSale,
    quotes: &[QuoteEntry],
    day_start_unix: i64,
    day_end_unix: i64,
) -> Result<CloseLine, String> {
    let signature = validate_signature(&sale.signature)
        .map_err(|e| format!("sale carries an unusable signature: {e}"))?;
    let mint = validate_pubkey(&sale.mint)
        .map_err(|e| format!("sale {signature} names a mint that is not an address: {e}"))?;

    // No clock is read here. The only time a sale has is the block time
    // the chain reported, and a sale without one cannot be placed in a
    // day at all. Filling it from a local clock would produce a close
    // that does not survive re-derivation.
    let block_time = sale.block_time_unix.ok_or_else(|| {
        format!(
            "sale {signature} carries no block time, so it cannot be placed in the day \
             running from {day_start_unix} to {day_end_unix}"
        )
    })?;
    if block_time < day_start_unix || block_time >= day_end_unix {
        return Err(format!(
            "sale {signature} settled at {block_time}, outside the day running from \
             {day_start_unix} to {day_end_unix}; the window is checked rather than applied, \
             so that moving it cannot quietly drop a sale"
        ));
    }

    // The order reference plus the exact amount. Counters cycle, so the
    // reference alone is not unique over a long enough log, and the
    // amount is what actually settled this order.
    let matches: Vec<&QuoteEntry> = quotes
        .iter()
        .filter(|q| {
            q.sales_point == sale.sales_point
                && q.order_counter == sale.order_counter
                && q.amount_due_base_units == sale.amount_base_units
        })
        .collect();

    let quote = *matches.first().ok_or_else(|| {
        format!(
            "no quote entry records order {}/{} at {} base units, so what payment {} bought \
             is not on record and the day cannot be itemized",
            sale.sales_point, sale.order_counter, sale.amount_base_units, signature
        )
    })?;

    if let Some(other) = matches.iter().find(|q| {
        q.sku != quote.sku
            || q.quantity != quote.quantity
            || q.unit_price_base_units != quote.unit_price_base_units
            || q.mint != quote.mint
    }) {
        return Err(format!(
            "order {}/{} at {} base units has two quote entries that disagree, {} times {} \
             against {} times {}; which one was sold is a decision for a human and not for \
             this code",
            sale.sales_point,
            sale.order_counter,
            sale.amount_base_units,
            quote.quantity,
            quote.sku,
            other.quantity,
            other.sku
        ));
    }

    // The sale's sku and quantity were copied from the quote when the
    // payment matched, so these must already agree. Checking rather than
    // assuming means an alteration to either record after the fact stops
    // the close instead of being averaged away.
    if quote.sku != sale.sku || quote.quantity != sale.quantity {
        return Err(format!(
            "payment {signature} settled {} of {} according to the chain record but {} of {} \
             according to the quote log; the two disagree, so the day cannot be closed",
            sale.quantity, sale.sku, quote.quantity, quote.sku
        ));
    }
    if quote.mint != mint {
        return Err(format!(
            "payment {signature} moved mint {mint} but order {}/{} was quoted in {}",
            sale.sales_point, sale.order_counter, quote.mint
        ));
    }

    // The reconciliation. Quantity times unit price is the subtotal, and
    // the subtotal plus the order's tag is what the customer was asked to
    // send, which is what the chain shows arriving. If that arithmetic
    // does not close, the itemization is not a description of the money.
    let tag = AmountTag::new(sale.sales_point, sale.order_counter)?;
    let subtotal = quote
        .unit_price_base_units
        .checked_mul(sale.quantity as u64)
        .ok_or_else(|| {
            format!(
                "{} at {} base units overflows on payment {signature}",
                sale.quantity, quote.unit_price_base_units
            )
        })?;
    let expected = subtotal
        .checked_add(tag.value())
        .ok_or_else(|| format!("the tagged amount for payment {signature} overflows"))?;
    if expected != sale.amount_base_units {
        return Err(format!(
            "order {}/{} itemizes to {} of {} at {} base units, which tags to {expected}, \
             but payment {signature} shows {} arriving; the itemization does not describe \
             the money",
            sale.sales_point,
            sale.order_counter,
            sale.quantity,
            quote.sku,
            quote.unit_price_base_units,
            sale.amount_base_units
        ));
    }

    reject_identity_shaped("sku", &quote.sku)?;

    Ok(CloseLine {
        sales_point: sale.sales_point,
        order_counter: sale.order_counter,
        sku: quote.sku.clone(),
        quantity: sale.quantity,
        unit_price_base_units: quote.unit_price_base_units,
        amount_base_units: sale.amount_base_units,
        mint,
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quote::issue_quote;
    use crate::zk::verify_proof;

    const MERCHANT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const CUSTOMER: &str = "GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const USDT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
    const BLOCKHASH: &str = "GXUnrX52iuQTFTqqCMDwoL6o8uMqfdFoodnXCsNGGoRr";

    const DAY_START: i64 = 1_750_000_000;
    const DAY_END: i64 = DAY_START + 86_400;
    const NOON: i64 = DAY_START + 43_200;

    fn sig(byte: u8) -> String {
        bs58::encode([byte; 64]).into_string()
    }

    /// One consistent sale and the quote entry behind it, built through
    /// `issue_quote` so the amounts reconcile the way a real day's do
    /// rather than because a fixture said so.
    fn sale_and_quote(
        sales_point: u8,
        order_counter: u8,
        sku: &str,
        quantity: u32,
        unit_price: u64,
        mint: &str,
        sig_byte: u8,
    ) -> (ConfirmedSale, QuoteEntry) {
        let quote = issue_quote(
            sales_point,
            order_counter,
            sku,
            quantity,
            unit_price,
            mint,
            DAY_START,
            900,
        )
        .expect("fixture quote is valid");
        let sale = ConfirmedSale {
            signature: sig(sig_byte),
            slot: 301_455_912 + sig_byte as u64,
            block_time_unix: Some(NOON),
            sales_point,
            order_counter,
            sku: sku.to_string(),
            quantity,
            amount_base_units: quote.amount_due_base_units,
            mint: mint.to_string(),
            payer: CUSTOMER.to_string(),
        };
        (sale, QuoteEntry::from(&quote))
    }

    /// A three sale day.
    fn a_day() -> (Vec<ConfirmedSale>, Vec<QuoteEntry>) {
        let items = [
            (3u8, 47u8, "RICE-5KG", 1u32, 10_000_000u64, 1u8),
            (3, 48, "OIL-1L", 2, 3_500_000, 2),
            (7, 4, "SOAP", 3, 1_250_000, 3),
        ];
        let mut sales = Vec::new();
        let mut quotes = Vec::new();
        for (sp, oc, sku, qty, price, byte) in items {
            let (s, q) = sale_and_quote(sp, oc, sku, qty, price, USDC, byte);
            sales.push(s);
            quotes.push(q);
        }
        (sales, quotes)
    }

    fn close_of(sales: &[ConfirmedSale], quotes: &[QuoteEntry]) -> DailyClose {
        build_close(MERCHANT, DAY_START, DAY_END, sales, quotes).expect("the day closes")
    }

    #[test]
    fn every_fixture_address_is_a_real_pubkey() {
        // A fixture address that could never exist on chain would make a
        // passing test prove nothing.
        for address in [MERCHANT, CUSTOMER, USDC, USDT, MEMO_PROGRAM_ID] {
            assert!(validate_pubkey(address).is_ok(), "{address} is not a pubkey");
        }
    }

    #[test]
    fn a_day_itemizes_what_was_sold_and_what_proved_it() {
        let (sales, quotes) = a_day();
        let close = close_of(&sales, &quotes);
        assert_eq!(close.lines.len(), 3);

        let rice = close
            .lines
            .iter()
            .find(|l| l.sku == "RICE-5KG")
            .expect("the rice line");
        assert_eq!(rice.sales_point, 3);
        assert_eq!(rice.order_counter, 47);
        assert_eq!(rice.quantity, 1);
        assert_eq!(rice.unit_price_base_units, 10_000_000);
        assert_eq!(rice.amount_base_units, 10_000_347);
        assert_eq!(rice.mint, USDC);
        assert_eq!(rice.signature, sig(1));

        // 10.000347 plus 7.000348 plus 3.750704.
        assert_eq!(close.total_base_units(), 10_000_347 + 7_000_348 + 3_750_704);
    }

    #[test]
    fn the_canonical_line_is_fixed_in_shape() {
        // The anchored commitment is taken over these bytes, so the shape
        // is pinned rather than left to formatting drift.
        let (sales, quotes) = a_day();
        let close = close_of(&sales, &quotes);
        let rice = close.lines.iter().find(|l| l.sku == "RICE-5KG").unwrap();
        assert_eq!(
            rice.canonical_line(),
            format!("3\t47\tRICE-5KG\t1\t10000000\t10000347\t{USDC}\t{}", sig(1))
        );
        assert_eq!(
            close.header_line(),
            format!("{CLOSE_DOMAIN}\t{MERCHANT}\t{DAY_START}\t{DAY_END}\t3")
        );
        // Terminated, not separated, so an empty day is unambiguous.
        assert!(close.canonical_record().ends_with('\n'));
        assert_eq!(close.canonical_record().lines().count(), 4);
    }

    #[test]
    fn closing_the_same_day_twice_is_byte_identical() {
        // The property the anchor rests on. If this can differ, an
        // auditor re-deriving the day gets a different number and the
        // anchor proves nothing.
        let (sales, quotes) = a_day();
        for _ in 0..8 {
            let first = close_of(&sales, &quotes);
            let second = close_of(&sales, &quotes);
            assert_eq!(first, second);
            assert_eq!(first.canonical_record(), second.canonical_record());
            assert_eq!(first.commitment, second.commitment);
            assert_eq!(first.anchor_memo(), second.anchor_memo());
        }
    }

    #[test]
    fn shuffling_the_input_does_not_move_the_commitment() {
        // The caller fetches sales over a network and holds quotes in
        // issuance order. Neither is something an auditor can reproduce,
        // so neither may reach the output. Every permutation of a three
        // sale day is checked against the reference, on both lists.
        let (sales, quotes) = a_day();
        let expected = close_of(&sales, &quotes);

        let orders = [
            [0usize, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        for sale_order in orders {
            for quote_order in orders {
                let s: Vec<ConfirmedSale> = sale_order.iter().map(|i| sales[*i].clone()).collect();
                let q: Vec<QuoteEntry> = quote_order.iter().map(|i| quotes[*i].clone()).collect();
                let shuffled = close_of(&s, &q);
                assert_eq!(shuffled.commitment, expected.commitment);
                assert_eq!(shuffled.canonical_record(), expected.canonical_record());
                assert_eq!(shuffled.lines, expected.lines);
            }
        }
    }

    #[test]
    fn changing_any_single_field_changes_the_commitment() {
        // A commitment that did not move when a number moved would let a
        // shop restate a day under an anchor that already matched it.
        let (sales, quotes) = a_day();
        let base = close_of(&sales, &quotes).commitment;
        let mut seen = vec![base];

        let mut variants: Vec<DailyClose> = Vec::new();

        // The sku, at the same price.
        let (s, q) = sale_and_quote(3, 47, "RICE-10KG", 1, 10_000_000, USDC, 1);
        variants.push(one_line_day(s, q));

        // The quantity, with the unit price adjusted so it reconciles.
        let (s, q) = sale_and_quote(3, 47, "RICE-5KG", 2, 5_000_000, USDC, 1);
        variants.push(one_line_day(s, q));

        // The unit price, and so the amount.
        let (s, q) = sale_and_quote(3, 47, "RICE-5KG", 1, 20_000_000, USDC, 1);
        variants.push(one_line_day(s, q));

        // The order reference, which moves the tag and so the amount.
        let (s, q) = sale_and_quote(3, 48, "RICE-5KG", 1, 10_000_000, USDC, 1);
        variants.push(one_line_day(s, q));
        let (s, q) = sale_and_quote(4, 47, "RICE-5KG", 1, 10_000_000, USDC, 1);
        variants.push(one_line_day(s, q));

        // The mint.
        let (s, q) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDT, 1);
        variants.push(one_line_day(s, q));

        // The signature, with everything else identical.
        let (s, q) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDC, 9);
        variants.push(one_line_day(s, q));

        for variant in &variants {
            assert!(
                !seen.contains(&variant.commitment),
                "a changed field left the commitment where it was: {:?}",
                variant.lines
            );
            seen.push(variant.commitment);
        }

        // The header is committed to as well, so the same sales under a
        // different merchant or a different day are a different close.
        let (s, q) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDC, 1);
        let reference = one_line_day(s.clone(), q.clone());
        let other_merchant =
            build_close(CUSTOMER, DAY_START, DAY_END, &[s.clone()], &[q.clone()]).unwrap();
        assert_ne!(reference.commitment, other_merchant.commitment);
        let other_day = build_close(MERCHANT, DAY_START - 1, DAY_END, &[s.clone()], &[q.clone()])
            .unwrap();
        assert_ne!(reference.commitment, other_day.commitment);
        let other_end = build_close(MERCHANT, DAY_START, DAY_END + 1, &[s], &[q]).unwrap();
        assert_ne!(reference.commitment, other_end.commitment);

        // And the number of lines is in the header, so a day cannot be
        // presented as a longer or shorter one with the same root.
        assert_ne!(close_of(&sales, &quotes).commitment, reference.commitment);
    }

    fn one_line_day(sale: ConfirmedSale, quote: QuoteEntry) -> DailyClose {
        build_close(MERCHANT, DAY_START, DAY_END, &[sale], &[quote]).expect("the day closes")
    }

    #[test]
    fn a_day_with_no_sales_still_closes() {
        // A shop that traded nothing publishes a checkable statement that
        // it traded nothing, rather than publishing nothing at all, which
        // is indistinguishable from a shop that skipped its close.
        let close = build_close(MERCHANT, DAY_START, DAY_END, &[], &[]).expect("an empty day");
        assert!(close.lines.is_empty());
        assert_eq!(close.total_base_units(), 0);
        assert_eq!(close.merkle_root, empty_leaf());
        assert_eq!(
            close.canonical_record(),
            format!("{CLOSE_DOMAIN}\t{MERCHANT}\t{DAY_START}\t{DAY_END}\t0\n")
        );
        // Still deterministic, still anchorable.
        let again = build_close(MERCHANT, DAY_START, DAY_END, &[], &[]).unwrap();
        assert_eq!(close.commitment, again.commitment);
        assert!(prepare_anchor(&close, BLOCKHASH).is_ok());

        // An empty day is not the same value as a day with one sale, even
        // though the tree pads with the same leaf.
        let (s, q) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDC, 1);
        assert_ne!(close.commitment, one_line_day(s, q).commitment);
    }

    #[test]
    fn a_phone_number_in_a_sku_refuses_the_close() {
        // The constraint that is not optional. Under ZK compression the
        // record is public through the indexer, so this must fail closed
        // rather than depend on nobody making a mistake.
        for sku in [
            "08031234567",
            "0803 123 4567",
            "RICE for 5551234",
            "call +234-803-123-4567",
            "(555) 010-1234",
        ] {
            let (s, q) = sale_and_quote(3, 47, sku, 1, 10_000_000, USDC, 1);
            let err = build_close(MERCHANT, DAY_START, DAY_END, &[s], &[q]).unwrap_err();
            assert!(
                err.contains("phone number") && err.contains("world readable"),
                "{sku:?} closed or failed for the wrong reason: {err}"
            );
        }
    }

    #[test]
    fn contact_details_and_prose_are_refused_too() {
        let (s, q) = sale_and_quote(3, 47, "rice for ada@example.com", 1, 10_000_000, USDC, 1);
        let err = build_close(MERCHANT, DAY_START, DAY_END, &[s], &[q]).unwrap_err();
        assert!(err.contains('@'), "{err}");

        // A tab would break the canonical form and could make two
        // different days serialize to the same bytes.
        let (s, q) = sale_and_quote(3, 47, "RICE\t5KG", 1, 10_000_000, USDC, 1);
        let err = build_close(MERCHANT, DAY_START, DAY_END, &[s], &[q]).unwrap_err();
        assert!(err.contains("control character"), "{err}");

        let long = "R".repeat(MAX_SKU_BYTES + 1);
        let (s, q) = sale_and_quote(3, 47, &long, 1, 10_000_000, USDC, 1);
        let err = build_close(MERCHANT, DAY_START, DAY_END, &[s], &[q]).unwrap_err();
        assert!(err.contains("prose"), "{err}");
    }

    #[test]
    fn the_phone_shape_test_catches_numbers_and_leaves_skus_alone() {
        for text in [
            "5551234",
            "555 12 34",
            "+2348031234567",
            "555.010.1234",
            "order 12345678 shipped",
        ] {
            assert!(looks_like_phone_number(text), "missed {text:?}");
        }
        for text in [
            "RICE-5KG",
            "OIL-1L",
            "SOAP",
            "TIN-400G",
            "A1B2C3D4E5F6",
            "SKU-123456",
        ] {
            assert!(!looks_like_phone_number(text), "false positive on {text:?}");
        }
        // The documented false positive, kept as a test so the trade is
        // deliberate rather than discovered in production.
        assert!(looks_like_phone_number("SKU-1234567"));
    }

    #[test]
    fn a_sale_with_no_quote_behind_it_refuses_the_close() {
        let (sale, _) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDC, 1);
        let err = build_close(MERCHANT, DAY_START, DAY_END, &[sale], &[]).unwrap_err();
        assert!(err.contains("not on record"), "{err}");
    }

    #[test]
    fn a_quote_that_disagrees_with_the_chain_refuses_the_close() {
        // The sale says one thing, the log says another. Averaging them
        // would publish a number no auditor could re-derive.
        let (sale, quote) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDC, 1);
        let mut altered = sale.clone();
        altered.sku = "OIL-1L".to_string();
        let err = build_close(MERCHANT, DAY_START, DAY_END, &[altered], &[quote.clone()])
            .unwrap_err();
        assert!(err.contains("the two disagree"), "{err}");

        let mut altered = sale;
        altered.quantity = 2;
        let err = build_close(MERCHANT, DAY_START, DAY_END, &[altered], &[quote]).unwrap_err();
        assert!(err.contains("the two disagree"), "{err}");
    }

    #[test]
    fn an_itemisation_that_does_not_reconcile_refuses_the_close() {
        // The unit price is rewritten in the log after the fact, so the
        // line no longer describes the money that arrived.
        let (sale, mut quote) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDC, 1);
        quote.unit_price_base_units = 5_000_000;
        let err = build_close(MERCHANT, DAY_START, DAY_END, &[sale], &[quote]).unwrap_err();
        assert!(err.contains("does not describe"), "{err}");
    }

    #[test]
    fn two_quote_entries_that_disagree_are_a_humans_problem() {
        // The counter cycled and both entries are still on the books at
        // the same amount. Picking one would invent a fact.
        let (sale, quote) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDC, 1);
        let (_, other) = sale_and_quote(3, 47, "OIL-1L", 1, 10_000_000, USDC, 2);
        let err = build_close(MERCHANT, DAY_START, DAY_END, &[sale], &[quote, other]).unwrap_err();
        assert!(err.contains("disagree"), "{err}");
    }

    #[test]
    fn a_sale_outside_the_day_is_refused_rather_than_dropped() {
        // Silently filtering by the window would let a caller shrink a
        // day by moving its bounds and hide money in the gap.
        let (mut sale, quote) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDC, 1);
        sale.block_time_unix = Some(DAY_END);
        let err =
            build_close(MERCHANT, DAY_START, DAY_END, &[sale.clone()], &[quote.clone()])
                .unwrap_err();
        assert!(err.contains("outside the day"), "{err}");

        sale.block_time_unix = Some(DAY_START - 1);
        let err =
            build_close(MERCHANT, DAY_START, DAY_END, &[sale.clone()], &[quote.clone()])
                .unwrap_err();
        assert!(err.contains("outside the day"), "{err}");

        // The bounds are half open, so the first instant closes and the
        // last does not.
        sale.block_time_unix = Some(DAY_START);
        assert!(build_close(MERCHANT, DAY_START, DAY_END, &[sale.clone()], &[quote.clone()]).is_ok());
        sale.block_time_unix = Some(DAY_END - 1);
        assert!(build_close(MERCHANT, DAY_START, DAY_END, &[sale.clone()], &[quote.clone()]).is_ok());

        // No block time at all cannot be placed in any day, and is not
        // filled in from a clock.
        sale.block_time_unix = None;
        let err = build_close(MERCHANT, DAY_START, DAY_END, &[sale], &[quote]).unwrap_err();
        assert!(err.contains("no block time"), "{err}");
    }

    #[test]
    fn one_payment_may_not_be_counted_twice() {
        let (sale, quote) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDC, 1);
        let err = build_close(
            MERCHANT,
            DAY_START,
            DAY_END,
            &[sale.clone(), sale],
            &[quote],
        )
        .unwrap_err();
        assert!(err.contains("appears twice"), "{err}");
    }

    #[test]
    fn nonsense_days_and_addresses_are_refused_at_the_door() {
        assert!(build_close("pay-me-here", DAY_START, DAY_END, &[], &[]).is_err());
        assert!(build_close(MERCHANT, DAY_END, DAY_START, &[], &[]).is_err());
        assert!(build_close(MERCHANT, DAY_START, DAY_START, &[], &[]).is_err());

        let (mut sale, quote) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDC, 1);
        sale.signature = "not-a-signature".to_string();
        assert!(build_close(MERCHANT, DAY_START, DAY_END, &[sale], &[quote]).is_err());
    }

    #[test]
    fn every_leaf_and_the_commitment_are_valid_field_elements() {
        // Poseidon takes BN254 field elements, so the embedding has to
        // land below the modulus every time. Zeroing the leading byte
        // bounds the value by 2^248, which the modulus exceeds.
        let (sales, quotes) = a_day();
        let close = close_of(&sales, &quotes);
        for leaf in close.leaves() {
            assert_eq!(leaf[0], 0, "leaf is not reduced into the field");
        }
        assert_eq!(empty_leaf()[0], 0);
        assert_eq!(field_element(b"")[0], 0);
        // The commitment comes back out of Poseidon, which reduces its
        // own output, so it needs no masking to be a field element.
        assert_ne!(close.commitment, [0u8; 32]);
    }

    #[test]
    fn a_single_line_verifies_against_the_anchored_root() {
        // The reason the lines are a tree and not one digest: a sale can
        // be shown to be in the anchored day without disclosing the rest
        // of the day, using the proof checker zk.rs already verified
        // against circomlib vectors.
        let (sales, quotes) = a_day();
        let close = close_of(&sales, &quotes);
        let leaves = close.leaves();
        for (index, leaf) in leaves.iter().enumerate() {
            let proof = close.merkle_proof(index).expect("a proof for every line");
            verify_proof(leaf, index as u64, &proof, &close.merkle_root)
                .unwrap_or_else(|e| panic!("line {index} did not verify: {e}"));
            // And a line does not verify at somebody else's index.
            let wrong = (index + 1) % leaves.len();
            assert!(verify_proof(leaf, wrong as u64, &proof, &close.merkle_root).is_err());
        }
        assert!(close.merkle_proof(leaves.len()).is_err());
    }

    #[test]
    fn a_five_line_day_pads_and_still_verifies() {
        // An odd tree is where a padding rule goes wrong, so the folding
        // and the proof are checked to agree at a size that pads at more
        // than one level.
        let mut sales = Vec::new();
        let mut quotes = Vec::new();
        for i in 0..5u8 {
            let (s, q) = sale_and_quote(3, 40 + i, "RICE-5KG", 1, 10_000_000, USDC, i + 1);
            sales.push(s);
            quotes.push(q);
        }
        let close = close_of(&sales, &quotes);
        assert_eq!(close.lines.len(), 5);
        for (index, leaf) in close.leaves().iter().enumerate() {
            let proof = close.merkle_proof(index).unwrap();
            verify_proof(leaf, index as u64, &proof, &close.merkle_root)
                .unwrap_or_else(|e| panic!("line {index} did not verify: {e}"));
        }
    }

    #[test]
    fn the_anchor_is_a_memo_the_merchant_signs() {
        let (sales, quotes) = a_day();
        let close = close_of(&sales, &quotes);
        let anchor = prepare_anchor(&close, BLOCKHASH).expect("an anchor");

        assert_eq!(anchor.commitment, close.commitment);
        assert_eq!(anchor.merchant, MERCHANT);
        assert_eq!(anchor.blockhash, BLOCKHASH);
        assert!(anchor.memo.starts_with(CLOSE_DOMAIN));
        assert!(anchor.memo.contains(&close.commitment_base58()));
        assert!(anchor.memo.contains(MERCHANT));

        // One required signature, the merchant, at account index zero.
        let msg = &anchor.message;
        assert_eq!(msg[0], 1, "one required signature");
        assert_eq!(msg[1], 0, "no readonly signers");
        assert_eq!(msg[3], 2, "the merchant plus the memo program");
        assert_eq!(&msg[4..36], &decode_pubkey(MERCHANT).unwrap());
        assert_eq!(&msg[36..68], &decode_pubkey(MEMO_PROGRAM_ID).unwrap());
        // The memo text is carried verbatim as the instruction payload.
        assert!(
            msg.windows(anchor.memo.len())
                .any(|w| w == anchor.memo.as_bytes()),
            "the memo payload is not in the message"
        );

        assert!(prepare_anchor(&close, "not-base58-!!!").is_err());
    }

    #[test]
    fn the_anchored_record_carries_no_customer_identity() {
        // The payer is a real wallet in the fixtures and is deliberately
        // absent from every byte that gets published, along with anything
        // else that could name a person.
        let (sales, quotes) = a_day();
        let close = close_of(&sales, &quotes);
        let anchor = prepare_anchor(&close, BLOCKHASH).unwrap();
        for text in [close.canonical_record(), anchor.memo.clone()] {
            assert!(!text.contains(CUSTOMER), "the payer reached the record");
        }
        // The phone heuristic belongs on the free text rather than on the
        // whole record. Amounts and unix timestamps are legitimately long
        // runs of digits, so a record wide check could never pass and would
        // say nothing if it did. The sku is the only field a person writes,
        // and it is the field the close actually screens.
        for line in &close.lines {
            assert!(
                !looks_like_phone_number(&line.sku),
                "the sku {:?} is phone shaped and reached the record",
                line.sku
            );
        }
        // Nor does it reach the tree, which is what the commitment covers.
        let rebuilt = build_close(MERCHANT, DAY_START, DAY_END, &sales, &quotes).unwrap();
        let mut anonymised = sales.clone();
        for sale in &mut anonymised {
            sale.payer = MERCHANT.to_string();
        }
        let without = build_close(MERCHANT, DAY_START, DAY_END, &anonymised, &quotes).unwrap();
        assert_eq!(
            rebuilt.commitment, without.commitment,
            "the payer is not committed to, so changing it must not move the commitment"
        );
    }

    #[test]
    fn too_many_lines_are_refused_rather_than_folded() {
        let (sale, quote) = sale_and_quote(3, 47, "RICE-5KG", 1, 10_000_000, USDC, 1);
        let sales = vec![sale; MAX_CLOSE_LINES + 1];
        let err = build_close(MERCHANT, DAY_START, DAY_END, &sales, &[quote]).unwrap_err();
        assert!(err.contains("exceeds"), "{err}");
    }
}
