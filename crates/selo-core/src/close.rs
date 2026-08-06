//! The daily close: a day of trading turned into one hashable record.
//!
//! Byte-identical output for identical input, so an auditor can re-derive
//! the day from chain data and the quote log and get the same hash. Nothing
//! here is model authored, and disagreements refuse rather than resolve.
//!
//! Poseidon over BN254 rather than SHA-256: the commitment is meant to be
//! provable inside a BN254 circuit, where a SHA-256 digest is ruinous.

use sha2::{Digest, Sha256};

use crate::address::{decode_pubkey, validate_pubkey};
use crate::message::{compile_message, Instruction};
use crate::quote::AmountTag;
use crate::quotelog::QuoteEntry;
use crate::tx::validate_signature;
use crate::zk::hash_pair;

/// A confirmed sale on-chain, matched to a daily close line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedSale {
    pub signature: String,
    pub slot: u64,
    pub block_time_unix: Option<i64>,
    pub sales_point: u8,
    pub order_counter: u8,
    pub sku: String,
    pub quantity: u32,
    pub amount_base_units: u64,
    pub mint: String,
    pub payer: String,
}

/// Version tag for the canonical form.
///
/// First thing in the header line and the anchor memo, and part of the
/// commitment. Anything changing field order, separators or hashing must
/// change this too, or two schemes produce interchangeable-looking numbers.
pub const CLOSE_DOMAIN: &str = "selo-close-v1";

pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
pub const MIN_PHONE_DIGITS: usize = 7;
pub const MAX_SKU_BYTES: usize = 64;
pub const MAX_CLOSE_LINES: usize = 16_384;
pub const MAX_MEMO_BYTES: usize = 566;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseLine {
    pub sales_point: u8,
    pub order_counter: u8,
    pub sku: String,
    pub quantity: u32,
    pub unit_price_base_units: u64,
    pub amount_base_units: u64,
    pub mint: String,
    pub signature: String,
}

impl CloseLine {
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

    pub fn leaf(&self) -> [u8; 32] {
        field_element(format!("{CLOSE_DOMAIN}/line\n{}", self.canonical_line()).as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyClose {
    pub merchant: String,
    pub day_start_unix: i64,
    pub day_end_unix: i64,
    pub lines: Vec<CloseLine>,
    pub merkle_root: [u8; 32],
    pub commitment: [u8; 32],
}

impl DailyClose {
    pub fn canonical_record(&self) -> String {
        let mut out = self.header_line();
        out.push('\n');
        for line in &self.lines {
            out.push_str(&line.canonical_line());
            out.push('\n');
        }
        out
    }

    pub fn header_line(&self) -> String {
        format!(
            "{CLOSE_DOMAIN}\t{}\t{}\t{}\t{}",
            self.merchant,
            self.day_start_unix,
            self.day_end_unix,
            self.lines.len()
        )
    }

    pub fn leaves(&self) -> Vec<[u8; 32]> {
        self.lines.iter().map(CloseLine::leaf).collect()
    }

    pub fn commitment_base58(&self) -> String {
        bs58::encode(self.commitment).into_string()
    }

    pub fn total_base_units(&self) -> u128 {
        self.lines.iter().map(|l| l.amount_base_units as u128).sum()
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAnchor {
    pub message: Vec<u8>,
    pub memo: String,
    pub commitment: [u8; 32],
    pub merchant: String,
    pub blockhash: String,
}

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

    lines.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

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

pub fn prepare_anchor(
    close: &DailyClose,
    recent_blockhash: &str,
) -> Result<PreparedAnchor, String> {
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

pub fn looks_like_phone_number(text: &str) -> bool {
    let mut run = 0usize;
    for c in text.chars() {
        if c.is_ascii_digit() {
            run += 1;
            if run >= MIN_PHONE_DIGITS {
                return true;
            }
        } else if !matches!(c, ' ' | '-' | '.' | '(' | ')' | '+' | '/') {
            run = 0;
        }
    }
    false
}

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

pub fn field_element(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out[0] = 0;
    out
}

pub fn empty_leaf() -> [u8; 32] {
    field_element(format!("{CLOSE_DOMAIN}/empty").as_bytes())
}

fn fold_level(level: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, String> {
    let mut next = Vec::with_capacity(level.len() / 2);
    for pair in level.chunks(2) {
        next.push(hash_pair(&pair[0], &pair[1])?);
    }
    Ok(next)
}

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
        for address in [MERCHANT, CUSTOMER, USDC, USDT, MEMO_PROGRAM_ID] {
            assert!(
                validate_pubkey(address).is_ok(),
                "{address} is not a pubkey"
            );
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

        assert_eq!(close.total_base_units(), 10_000_347 + 7_000_348 + 3_750_704);
    }

    #[test]
    fn the_canonical_line_is_fixed_in_shape() {
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
        assert!(close.canonical_record().ends_with('\n'));
        assert_eq!(close.canonical_record().lines().count(), 4);
    }

    #[test]
    fn closing_the_same_day_twice_is_byte_identical() {
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
    fn a_single_line_verifies_against_the_anchored_root() {
        let (sales, quotes) = a_day();
        let close = close_of(&sales, &quotes);
        let leaves = close.leaves();
        for (index, leaf) in leaves.iter().enumerate() {
            let proof = close.merkle_proof(index).expect("a proof for every line");
            verify_proof(leaf, index as u64, &proof, &close.merkle_root)
                .unwrap_or_else(|e| panic!("line {index} did not verify: {e}"));
        }
    }
}
