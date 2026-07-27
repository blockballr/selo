//! Refunds: the one place the shop sends money out.
//!
//! No function here takes a refund amount, a destination or a mint. All
//! three come from what the ledger says arrived, so an injected model has
//! no parameter to set.
//!
//! `render_approval` parses the signable bytes back and refuses if any
//! field disagrees, so the human reads a rendering of what they sign.
//!
//! Destination is the owner of the account the money left, not the fee
//! payer, and refuses when there is no single source. Idempotency is
//! recorded at preparation, trading a stuck retry for a double-spend
//! window.

use std::collections::HashMap;

use serde_json::json;

use crate::address::{decode_pubkey, encode_pubkey, validate_pubkey};
use crate::catalog::ShopConfig;
use crate::format::base_units_to_decimal;
use crate::message::{compile_message, AccountMeta, Instruction};
use crate::pda::{associated_token_address, ASSOCIATED_TOKEN_PROGRAM_ID};
use crate::quote::{decode_amount, AmountTag};
use crate::rpc::TOKEN_PROGRAM_ID;
use crate::settle::{ConfirmedSale, ReceivedPayment};
use crate::transfer::SYSTEM_PROGRAM_ID;

/// `TransferChecked` in the SPL token instruction enum.
///
/// Mirrored from `token` rather than imported because that constant is
/// private there. The parser below asserts the byte it finds in a
/// compiled message is this one, so a divergence between the two
/// definitions fails a test rather than shipping.
const IX_TRANSFER_CHECKED: u8 = 12;

/// `CreateIdempotent` in the associated token account program.
const IX_CREATE_IDEMPOTENT: u8 = 1;

/// How long after a payment a refund may still be prepared, by default:
/// twenty four hours.
///
/// Short on purpose: the window bounds how long an injected instruction
/// stays useful against a day's takings. The default is the shortest span
/// still covering a customer who returns next morning.
pub const DEFAULT_REFUND_WINDOW_SECS: u32 = 86_400;

/// Default ceiling on refunds in any rolling day, in the settlement
/// mint's base units: a hundred whole units on a six decimal mint.
///
/// Base units, like every other amount here; mixing the two near money is
/// how a thousand-fold error happens. The default is therefore only
/// meaningful on a six decimal mint. That is the safe direction: more
/// decimals makes it a smaller real ceiling, never larger.
pub const DEFAULT_MAX_REFUND_PER_DAY_BASE_UNITS: u64 = 100_000_000;

/// The span the daily ceiling is measured over.
///
/// Rolling twenty four hours, not a calendar day. A calendar day needs a
/// timezone this does not have, and its boundary is a hole: refund the
/// ceiling at 23:59 and again at 00:01 and the limit has doubled.
pub const REFUND_DAY_SECS: i64 = 86_400;

/// Operator policy for refunds, read from the jailed config section.
///
/// Every field fails safe. An absent or unreadable key gives the
/// restrictive setting, never the permissive one, because the config a
/// shop actually runs with on its first day is the empty one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefundPolicy {
    /// Refunds are refused for payments older than this. Zero disables
    /// refunds entirely.
    pub refund_window_secs: u32,
    /// Ceiling on the total refunded in any rolling `REFUND_DAY_SECS`,
    /// in the settlement mint's base units. Zero disables refunds.
    pub max_refund_per_day_base_units: u64,
    /// Whether a refund for less than the whole received amount is
    /// permitted. Default false, and see `prepare_refund` for why this
    /// is a tripwire rather than a feature.
    pub allow_partial_refunds: bool,
}

impl RefundPolicy {
    /// Read the policy from the jailed config section.
    ///
    /// Keys: `refund_window_secs`, `max_refund_per_day_base_units`, and
    /// `allow_partial_refunds`. All optional.
    ///
    /// An explicit zero is honored on both numeric keys, since zero is
    /// stricter than the default and is how an operator turns refunds off. An
    /// absent or unparseable value falls back instead: a typo must not
    /// silently disable refunds any more than widen them.
    ///
    /// The partial flag is true only for an explicit affirmative spelling.
    /// Anything else, including the word "maybe" and the empty string,
    /// reads as false.
    pub fn from_section(section: &HashMap<String, String>) -> Self {
        let refund_window_secs = section
            .get("refund_window_secs")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(DEFAULT_REFUND_WINDOW_SECS);
        let max_refund_per_day_base_units = section
            .get("max_refund_per_day_base_units")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_REFUND_PER_DAY_BASE_UNITS);
        let allow_partial_refunds = section
            .get("allow_partial_refunds")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "true" | "yes" | "1" | "on"
                )
            })
            .unwrap_or(false);
        Self {
            refund_window_secs,
            max_refund_per_day_base_units,
            allow_partial_refunds,
        }
    }
}

/// Which order a refund is for.
///
/// This is the entire selection surface exposed to a model: two small
/// integers that name an order and carry no money. Every field of the
/// refund itself is derived from the payment those integers select.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderRef {
    pub sales_point: u8,
    pub order_counter: u8,
}

impl OrderRef {
    /// Build a reference, rejecting values the payment tag cannot hold.
    pub fn new(sales_point: u8, order_counter: u8) -> Result<Self, String> {
        AmountTag::new(sales_point, order_counter)?;
        Ok(Self {
            sales_point,
            order_counter,
        })
    }

    /// The reference of a sale the ledger confirmed.
    ///
    /// Takes only the two identifying fields. A `ConfirmedSale` also
    /// carries an amount and a payer, and both are deliberately ignored
    /// here: the refund reads them back off the payment instead, so that
    /// a hand-built sale struct cannot become a hand-built refund.
    pub fn from_sale(sale: &ConfirmedSale) -> Result<Self, String> {
        Self::new(sale.sales_point, sale.order_counter)
    }

    /// The reference a received payment carries in its low digits.
    ///
    /// `Ok(None)` for an untagged transfer, which is somebody sending a
    /// round number to the shop address rather than an order.
    pub fn from_payment(payment: &ReceivedPayment) -> Result<Option<Self>, String> {
        match decode_amount(payment.amount_base_units)? {
            Some((_, tag)) => Ok(Some(Self {
                sales_point: tag.sales_point,
                order_counter: tag.order_counter,
            })),
            None => Ok(None),
        }
    }

    /// The amount tag this reference corresponds to.
    pub fn tag(&self) -> Result<AmountTag, String> {
        AmountTag::new(self.sales_point, self.order_counter)
    }
}

/// A refund that was prepared, kept so the next one can be refused.
///
/// Appended by the caller at preparation time, from
/// `PreparedRefund::record`. It exists for two checks that both need
/// history: idempotency, and the rolling daily ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefundRecord {
    pub sales_point: u8,
    pub order_counter: u8,
    /// Signature of the payment that was refunded. The idempotency key,
    /// because it is the one identifier that is unique for all time; the
    /// order counter cycles.
    pub original_signature: String,
    pub amount_base_units: u64,
    pub mint: String,
    pub destination_owner: String,
    /// When the refund was prepared, which is what the rolling day is
    /// measured against.
    pub prepared_at_unix: i64,
}

/// An unsigned refund, plus every fact it was derived from.
///
/// `message` is exactly what a human signs. The rest is what
/// `render_approval` checks that message against, and what a caller
/// records so the same refund cannot be prepared twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRefund {
    /// Serialized legacy message. Unsigned: this module holds no key and
    /// never will.
    pub message: Vec<u8>,
    pub sales_point: u8,
    pub order_counter: u8,
    /// The payment being refunded, so a human can open it in an explorer
    /// and see the money that arrived.
    pub original_signature: String,
    /// Exactly what arrived, tag included. Not chosen, read.
    pub amount_base_units: u64,
    pub mint: String,
    pub decimals: u8,
    /// The wallet that owns the token account the money left.
    pub destination_owner: String,
    pub destination_ata: String,
    pub source_ata: String,
    pub merchant: String,
    /// True whenever the transaction carries a `CreateIdempotent`, which
    /// it always does. See `prepare_refund` for the rent implication.
    pub creates_destination_account: bool,
    pub blockhash: String,
    pub prepared_at_unix: i64,
}

impl PreparedRefund {
    /// The record to append before this refund is handed to a human.
    pub fn record(&self) -> RefundRecord {
        RefundRecord {
            sales_point: self.sales_point,
            order_counter: self.order_counter,
            original_signature: self.original_signature.clone(),
            amount_base_units: self.amount_base_units,
            mint: self.mint.clone(),
            destination_owner: self.destination_owner.clone(),
            prepared_at_unix: self.prepared_at_unix,
        }
    }
}

/// Prepare a refund for one order.
///
/// No argument here is an amount or a destination, so no injected
/// instruction can request a different sum or recipient. `receipts` must
/// come from `settle::parse_settlement_payment`, which derives each amount
/// from a balance delta.
///
/// Refuses on: wrong merchant, order never paid, an ambiguous tag from a
/// cycled counter, wrong recipient or mint, an order already refunded,
/// an unknown payer from a swap or router, a payment outside the refund
/// window, and the daily ceiling.
///
/// Always carries `CreateIdempotent` for the destination account, which
/// removes a round trip and a race. When the account really is missing the
/// merchant pays its rent, about 0.00204 SOL, and `render_approval` says
/// so in the text the human approves.
#[allow(clippy::too_many_arguments)]
pub fn prepare_refund(
    order: OrderRef,
    receipts: &[ReceivedPayment],
    shop: &ShopConfig,
    policy: &RefundPolicy,
    already_refunded: &[RefundRecord],
    merchant_pubkey: &str,
    recent_blockhash: &str,
    now_unix: i64,
) -> Result<PreparedRefund, String> {
    let merchant = validate_pubkey(merchant_pubkey)
        .map_err(|e| format!("merchant pubkey is not a valid Solana address: {e}"))?;
    // The signing wallet must be the wallet the shop is configured to
    // receive at. Refusing the mismatch keeps the refund path anchored to
    // the same operator-set address as the payment path, so there is one
    // merchant identity in the system rather than two that can drift.
    if merchant != shop.merchant_address {
        return Err(format!(
            "refusing to prepare a refund signed by {merchant}: the configured merchant is {}, \
             and a refund must come out of the wallet the sale was paid into",
            shop.merchant_address
        ));
    }

    let tag = order.tag()?;

    // Selection, and the only thing the caller influences. The payment is
    // found by matching the tag the ledger recorded in the amount, so the
    // caller names an order and the code finds the money.
    let mut matching = receipts.iter().filter(|p| {
        matches!(decode_amount(p.amount_base_units), Ok(Some((_, t))) if t == tag)
    });
    let payment = matching.next().ok_or_else(|| {
        format!(
            "no payment for order {}/{} appears in chain data, so there is nothing to refund; \
             an order that was never paid cannot be refunded",
            order.sales_point, order.order_counter
        )
    })?;
    if let Some(other) = matching.next() {
        return Err(format!(
            "two payments carry the tag for order {}/{}, {} and {}; the order counter has \
             cycled while both were still refundable, so which one to refund is a decision \
             for a human and not for this code",
            order.sales_point, order.order_counter, payment.signature, other.signature
        ));
    }

    if payment.merchant != shop.merchant_address {
        return Err(format!(
            "payment {} arrived at {} rather than the configured merchant {}, so it is not \
             this shop's money to refund",
            payment.signature, payment.merchant, shop.merchant_address
        ));
    }
    if payment.mint != shop.mint {
        return Err(format!(
            "payment {} moved mint {} but the shop settles in {}; a refund is paid in the mint \
             that was received and never in another",
            payment.signature, payment.mint, shop.mint
        ));
    }
    if payment.amount_base_units == 0 {
        return Err(format!(
            "payment {} credited nothing, so a refund of it would move nothing",
            payment.signature
        ));
    }

    // Idempotency. Checked against every record ever kept rather than
    // today's, because a second refund of one payment is a drain whenever
    // it happens. The order reference is checked as well as the
    // signature: if a record names this order against some other
    // signature, the counter was reused and the safe answer is to stop.
    if let Some(prior) = already_refunded.iter().find(|r| {
        r.original_signature == payment.signature
            || (r.sales_point == order.sales_point && r.order_counter == order.order_counter)
    }) {
        return Err(format!(
            "order {}/{} has already been refunded: {} base units of {} were sent to {} at unix \
             time {}, against payment {}. Refusing to prepare a second refund",
            prior.sales_point,
            prior.order_counter,
            prior.amount_base_units,
            prior.mint,
            prior.destination_owner,
            prior.prepared_at_unix,
            prior.original_signature
        ));
    }

    // The destination, derived and never supplied. `source_owner` is the
    // owner of the token account the money left; the fee payer is not
    // used, because a relayer can pay a fee for funds they never held.
    let destination_owner = payment.source_owner.clone().ok_or_else(|| {
        format!(
            "payment {} does not identify a single sending token account, which happens when \
             money arrives through a swap or a router, so the original payer cannot be \
             determined from chain data and this refund must be addressed by a human",
            payment.signature
        )
    })?;
    let destination_owner = validate_pubkey(&destination_owner).map_err(|e| {
        format!("the payer recorded for payment {} is not a valid Solana address: {e}", payment.signature)
    })?;
    if destination_owner == merchant {
        return Err(format!(
            "payment {} appears to have come from the merchant's own wallet, and paying \
             ourselves is not a refund",
            payment.signature
        ));
    }

    // The window.
    if policy.refund_window_secs == 0 {
        return Err(
            "refunds are switched off: refund_window_secs is configured as 0, so no payment is \
             inside the window"
                .to_string(),
        );
    }
    let paid_at = payment.block_time_unix.ok_or_else(|| {
        format!(
            "payment {} carries no block time, so there is no way to show it falls inside the \
             {} second refund window; an age that cannot be proved is refused rather than \
             assumed",
            payment.signature, policy.refund_window_secs
        )
    })?;
    let age = now_unix.checked_sub(paid_at).ok_or_else(|| {
        format!("the age of payment {} does not compute", payment.signature)
    })?;
    if age < 0 {
        return Err(format!(
            "payment {} is dated {paid_at}, which is after the current time {now_unix}; a clock \
             that disagrees with the ledger cannot be used to enforce a refund window",
            payment.signature
        ));
    }
    if age > policy.refund_window_secs as i64 {
        return Err(format!(
            "payment {} is {age} seconds old and the refund window is {} seconds; the operator \
             can widen it with the refund_window_secs config key",
            payment.signature, policy.refund_window_secs
        ));
    }

    // The rolling daily ceiling. Records dated in the future count too:
    // a clock that runs ahead must not be a way to buy more headroom.
    let amount = payment.amount_base_units;
    let spent_today: u128 = already_refunded
        .iter()
        .filter(|r| {
            r.mint == shop.mint
                && match now_unix.checked_sub(r.prepared_at_unix) {
                    Some(delta) => delta <= REFUND_DAY_SECS,
                    None => true,
                }
        })
        .map(|r| r.amount_base_units as u128)
        .sum();
    let would_be = spent_today + amount as u128;
    if would_be > policy.max_refund_per_day_base_units as u128 {
        return Err(format!(
            "a refund of {amount} base units would take the last {REFUND_DAY_SECS} seconds to \
             {would_be}, over the configured ceiling of {} base units per day; the operator can \
             raise it with the max_refund_per_day_base_units config key",
            policy.max_refund_per_day_base_units
        ));
    }

    // A tripwire rather than a feature. The refund is the whole received
    // amount because that is the only amount this module can reach, so
    // this comparison is true today by construction. It is written down
    // so that any future change which introduces a partial amount fails
    // closed against the policy instead of quietly shipping the parameter
    // this module exists to not have.
    if amount != payment.amount_base_units && !policy.allow_partial_refunds {
        return Err(format!(
            "a partial refund of {amount} against a payment of {} was constructed, but partial \
             refunds are not permitted; set allow_partial_refunds only after reviewing how that \
             amount is chosen",
            payment.amount_base_units
        ));
    }

    let owner_bytes = decode_pubkey(&merchant)?;
    let destination_owner_bytes = decode_pubkey(&destination_owner)?;
    let mint_bytes = decode_pubkey(&payment.mint)?;
    let token_program = decode_pubkey(TOKEN_PROGRAM_ID)?;
    let ata_program = decode_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID)?;

    let source_ata = associated_token_address(&owner_bytes, &mint_bytes, &token_program)?;
    let destination_ata =
        associated_token_address(&destination_owner_bytes, &mint_bytes, &token_program)?;

    let mut transfer_data = Vec::with_capacity(10);
    transfer_data.push(IX_TRANSFER_CHECKED);
    transfer_data.extend_from_slice(&amount.to_le_bytes());
    transfer_data.push(shop.decimals);

    // Built through `message::compile_message` rather than by hand. The
    // accounts here are named by meaning, and the compiler does the
    // index bookkeeping, so there is no literal index in this file to
    // transpose into a transfer that still signs and pays the wrong
    // account.
    let instructions = vec![
        Instruction {
            program_id: ata_program,
            accounts: vec![
                AccountMeta::signer_writable(owner_bytes),
                AccountMeta::writable(destination_ata),
                AccountMeta::readonly(destination_owner_bytes),
                AccountMeta::readonly(mint_bytes),
                AccountMeta::readonly(SYSTEM_PROGRAM_ID),
                AccountMeta::readonly(token_program),
            ],
            data: vec![IX_CREATE_IDEMPOTENT],
        },
        Instruction {
            program_id: token_program,
            accounts: vec![
                AccountMeta::writable(source_ata),
                AccountMeta::readonly(mint_bytes),
                AccountMeta::writable(destination_ata),
                AccountMeta::signer_writable(owner_bytes),
            ],
            data: transfer_data,
        },
    ];

    let message = compile_message(&owner_bytes, &instructions, recent_blockhash)?;

    let prepared = PreparedRefund {
        message,
        sales_point: order.sales_point,
        order_counter: order.order_counter,
        original_signature: payment.signature.clone(),
        amount_base_units: amount,
        mint: payment.mint.clone(),
        decimals: shop.decimals,
        destination_owner,
        destination_ata: encode_pubkey(&destination_ata),
        source_ata: encode_pubkey(&source_ata),
        merchant,
        creates_destination_account: true,
        blockhash: recent_blockhash.trim().to_string(),
        prepared_at_unix: now_unix,
    };

    // Never hand back bytes this module cannot read back. Running the
    // parser here means a `PreparedRefund` that exists at all is one
    // whose message agrees with its own derived fields, so a later
    // disagreement in `render_approval` can only mean the bytes were
    // altered in between.
    check_message_matches(&prepared)?;
    Ok(prepared)
}

/// What a compiled refund message actually says, read back out of it.
///
/// Every field here came from the bytes. Nothing was carried over from
/// the values used to build them, which is the whole reason this type
/// exists separately from `PreparedRefund`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefundMessageFacts {
    pub amount_base_units: u64,
    pub decimals: u8,
    pub mint: String,
    pub source_ata: String,
    pub destination_ata: String,
    /// The signer, which for a refund is the merchant paying out.
    pub owner: String,
    pub blockhash: String,
    pub creates_destination_account: bool,
}

/// One instruction as it appears in a serialized message.
struct RawInstruction {
    program_index: u8,
    accounts: Vec<u8>,
    data: Vec<u8>,
}

/// Read a shortvec length and the number of bytes it occupied.
fn read_shortvec(bytes: &[u8], at: usize) -> Result<(usize, usize), String> {
    let mut value = 0usize;
    let mut consumed = 0usize;
    loop {
        let byte = *bytes
            .get(at + consumed)
            .ok_or_else(|| "truncated shortvec length".to_string())?;
        value |= ((byte & 0x7f) as usize) << (consumed * 7);
        consumed += 1;
        if byte & 0x80 == 0 {
            return Ok((value, consumed));
        }
        if consumed > 3 {
            return Err("shortvec length is too long".to_string());
        }
    }
}

/// Parse a compiled refund message back into the facts it asserts.
///
/// Refuses on the strength of the parsed bytes, not anyone's account of
/// them. Anything but one `TransferChecked`, optionally preceded by one
/// `CreateIdempotent` for the same destination and mint, is refused: an
/// unexpected third instruction is the shape of an attack.
///
/// It is public so that a reviewer, a test, or a second implementation
/// can check a refund's bytes without trusting anything this module says
/// about them.
pub fn parse_refund_message(msg: &[u8]) -> Result<RefundMessageFacts, String> {
    if msg.is_empty() {
        return Err("refund message is empty".to_string());
    }
    // A legacy message begins with a small signature count, so the high
    // bit is never set. Set means a versioned message, which this module
    // does not build and will not vouch for.
    if msg[0] & 0x80 != 0 {
        return Err(
            "refund message is a versioned message; this module builds legacy messages, so \
             these are not bytes it produced"
                .to_string(),
        );
    }
    let header = msg
        .get(0..3)
        .ok_or_else(|| "truncated message header".to_string())?;
    let required_signatures = header[0];
    let readonly_signed = header[1];
    if required_signatures != 1 {
        return Err(format!(
            "refund message requires {required_signatures} signatures; a refund is signed by \
             the merchant alone, so anything else is not a refund this module built"
        ));
    }
    if readonly_signed != 0 {
        return Err("refund message expects a signer that pays no fee".to_string());
    }
    let mut cursor = 3usize;

    let (key_count, consumed) = read_shortvec(msg, cursor)?;
    cursor += consumed;
    let mut keys: Vec<[u8; 32]> = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let key: [u8; 32] = msg
            .get(cursor..cursor + 32)
            .ok_or_else(|| "truncated account key".to_string())?
            .try_into()
            .map_err(|_| "account key is not 32 bytes".to_string())?;
        keys.push(key);
        cursor += 32;
    }
    if keys.is_empty() {
        return Err("refund message has no accounts".to_string());
    }

    let blockhash: [u8; 32] = msg
        .get(cursor..cursor + 32)
        .ok_or_else(|| "truncated recent blockhash".to_string())?
        .try_into()
        .map_err(|_| "blockhash is not 32 bytes".to_string())?;
    cursor += 32;

    let (instruction_count, consumed) = read_shortvec(msg, cursor)?;
    cursor += consumed;
    let mut instructions = Vec::with_capacity(instruction_count);
    for _ in 0..instruction_count {
        let program_index = *msg
            .get(cursor)
            .ok_or_else(|| "truncated program index".to_string())?;
        cursor += 1;
        let (account_count, consumed) = read_shortvec(msg, cursor)?;
        cursor += consumed;
        let accounts = msg
            .get(cursor..cursor + account_count)
            .ok_or_else(|| "truncated instruction accounts".to_string())?
            .to_vec();
        cursor += account_count;
        let (data_len, consumed) = read_shortvec(msg, cursor)?;
        cursor += consumed;
        let data = msg
            .get(cursor..cursor + data_len)
            .ok_or_else(|| "truncated instruction data".to_string())?
            .to_vec();
        cursor += data_len;
        instructions.push(RawInstruction {
            program_index,
            accounts,
            data,
        });
    }

    // A correct parse lands exactly on the end. Leftover bytes mean the
    // structure was misread, and a misread structure is the failure mode
    // that ends with a signature on something unexpected.
    if cursor != msg.len() {
        return Err(format!(
            "refund message did not parse cleanly: {} bytes left over",
            msg.len() - cursor
        ));
    }

    let token_program = decode_pubkey(TOKEN_PROGRAM_ID)?;
    let ata_program = decode_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID)?;
    let key_at = |index: u8| -> Result<[u8; 32], String> {
        keys.get(index as usize)
            .copied()
            .ok_or_else(|| format!("instruction names account index {index}, which does not exist"))
    };

    let mut transfer: Option<&RawInstruction> = None;
    let mut create: Option<&RawInstruction> = None;
    for ix in &instructions {
        let program = key_at(ix.program_index)?;
        if program == token_program {
            if ix.data.first() != Some(&IX_TRANSFER_CHECKED) {
                return Err(format!(
                    "refund message carries token instruction {:?}, but a refund is a \
                     TransferChecked and nothing else",
                    ix.data.first()
                ));
            }
            if ix.data.len() != 10 {
                return Err(format!(
                    "TransferChecked data is {} bytes rather than 10",
                    ix.data.len()
                ));
            }
            if ix.accounts.len() != 4 {
                return Err(format!(
                    "TransferChecked names {} accounts rather than 4",
                    ix.accounts.len()
                ));
            }
            if transfer.replace(ix).is_some() {
                return Err(
                    "refund message carries more than one transfer; a refund moves money once"
                        .to_string(),
                );
            }
        } else if program == ata_program {
            if ix.data != [IX_CREATE_IDEMPOTENT] {
                return Err(
                    "refund message carries an associated token account instruction that is not \
                     CreateIdempotent"
                        .to_string(),
                );
            }
            if ix.accounts.len() != 6 {
                return Err(format!(
                    "CreateIdempotent names {} accounts rather than 6",
                    ix.accounts.len()
                ));
            }
            if create.replace(ix).is_some() {
                return Err("refund message creates a token account twice".to_string());
            }
        } else {
            return Err(format!(
                "refund message calls program {}, which a refund never needs; refusing to read \
                 it as a refund",
                encode_pubkey(&program)
            ));
        }
    }

    let transfer = transfer.ok_or_else(|| {
        "refund message contains no TransferChecked, so it moves no money".to_string()
    })?;

    let source_ata = key_at(transfer.accounts[0])?;
    let mint = key_at(transfer.accounts[1])?;
    let destination_ata = key_at(transfer.accounts[2])?;
    let owner = key_at(transfer.accounts[3])?;
    if owner != keys[0] {
        return Err(format!(
            "the account authorizing the transfer is {} but the fee payer is {}; a refund is \
             authorized by the wallet that pays for it",
            encode_pubkey(&owner),
            encode_pubkey(&keys[0])
        ));
    }

    if let Some(create) = create {
        // The creation must be for the same account, the same mint, and
        // funded by the same signer the transfer pays from. Otherwise a
        // transaction could create one account and pay another.
        if key_at(create.accounts[0])? != owner {
            return Err("the token account creation is funded by someone other than the merchant"
                .to_string());
        }
        if key_at(create.accounts[1])? != destination_ata {
            return Err(
                "the token account being created is not the account the refund pays".to_string(),
            );
        }
        if key_at(create.accounts[3])? != mint {
            return Err("the token account being created is for a different mint".to_string());
        }
    }

    let amount_base_units = u64::from_le_bytes(
        transfer.data[1..9]
            .try_into()
            .map_err(|_| "TransferChecked amount is not eight bytes".to_string())?,
    );

    Ok(RefundMessageFacts {
        amount_base_units,
        decimals: transfer.data[9],
        mint: encode_pubkey(&mint),
        source_ata: encode_pubkey(&source_ata),
        destination_ata: encode_pubkey(&destination_ata),
        owner: encode_pubkey(&owner),
        blockhash: bs58::encode(blockhash).into_string(),
        creates_destination_account: create.is_some(),
    })
}

/// Check a prepared refund against its own bytes.
///
/// Separated out because both `prepare_refund` and `render_approval` need
/// it and neither may skip it: the first so that no unreadable message
/// ever escapes, the second so that no text is ever rendered for bytes it
/// does not describe.
fn check_message_matches(prepared: &PreparedRefund) -> Result<RefundMessageFacts, String> {
    let facts = parse_refund_message(&prepared.message)?;

    let mismatch = |field: &str, in_bytes: String, derived: &str| {
        format!(
            "refusing to describe this refund: the {field} in the transaction bytes is \
             {in_bytes} but the prepared refund says {derived}. The bytes are the thing being \
             signed, so a disagreement means the description is wrong or the bytes were altered"
        )
    };

    if facts.amount_base_units != prepared.amount_base_units {
        return Err(mismatch(
            "amount",
            facts.amount_base_units.to_string(),
            &prepared.amount_base_units.to_string(),
        ));
    }
    if facts.decimals != prepared.decimals {
        return Err(mismatch(
            "decimals",
            facts.decimals.to_string(),
            &prepared.decimals.to_string(),
        ));
    }
    if facts.mint != prepared.mint {
        return Err(mismatch("mint", facts.mint.clone(), &prepared.mint));
    }
    if facts.source_ata != prepared.source_ata {
        return Err(mismatch(
            "source token account",
            facts.source_ata.clone(),
            &prepared.source_ata,
        ));
    }
    if facts.destination_ata != prepared.destination_ata {
        return Err(mismatch(
            "destination token account",
            facts.destination_ata.clone(),
            &prepared.destination_ata,
        ));
    }
    if facts.owner != prepared.merchant {
        return Err(mismatch("signer", facts.owner.clone(), &prepared.merchant));
    }
    if facts.blockhash != prepared.blockhash {
        return Err(mismatch(
            "blockhash",
            facts.blockhash.clone(),
            &prepared.blockhash,
        ));
    }
    if facts.creates_destination_account != prepared.creates_destination_account {
        return Err(mismatch(
            "account creation",
            facts.creates_destination_account.to_string(),
            &prepared.creates_destination_account.to_string(),
        ));
    }

    // The destination wallet is the one fact a human cares about that the
    // bytes do not contain: a transfer names a token account, not its
    // owner. So it is re-derived here from the address the text is about
    // to print. If someone printed one wallet while the bytes paid the
    // token account of another, this is where it stops.
    let owner_bytes = decode_pubkey(&prepared.destination_owner)?;
    let mint_bytes = decode_pubkey(&facts.mint)?;
    let token_program = decode_pubkey(TOKEN_PROGRAM_ID)?;
    let rederived = encode_pubkey(&associated_token_address(
        &owner_bytes,
        &mint_bytes,
        &token_program,
    )?);
    if rederived != facts.destination_ata {
        return Err(format!(
            "refusing to describe this refund: it would name {} as the payee, but that wallet's \
             token account for this mint is {rederived} and the transaction pays {}",
            prepared.destination_owner, facts.destination_ata
        ));
    }

    Ok(facts)
}

/// Render the text a human approves a refund against.
///
/// Everything above the line is read back out of the signable bytes by
/// `parse_refund_message`, cross-checked, and printed from the parsed
/// values. If the two diverge this refuses rather than renders.
///
/// Below the line are the two facts not in the transaction, the payment
/// signature and the order it settled, labelled as unverifiable.
pub fn render_approval(prepared: &PreparedRefund) -> Result<String, String> {
    let facts = check_message_matches(prepared)?;

    let ui = base_units_to_decimal(&facts.amount_base_units.to_string(), facts.decimals);
    let mut text = String::new();
    text.push_str("REFUND, AWAITING YOUR SIGNATURE\n");
    text.push_str("Read these from the transaction you are about to sign:\n");
    text.push_str(&format!(
        "  Sending      {ui} ({} base units at {} decimals)\n",
        facts.amount_base_units, facts.decimals
    ));
    text.push_str(&format!("  Of mint      {}\n", facts.mint));
    text.push_str(&format!(
        "  From         {} (the shop's token account, owned by {})\n",
        facts.source_ata, facts.owner
    ));
    text.push_str(&format!(
        "  To           {} (the token account of wallet {})\n",
        facts.destination_ata, prepared.destination_owner
    ));
    text.push_str(&format!("  Blockhash    {}\n", facts.blockhash));
    if facts.creates_destination_account {
        text.push_str(
            "  Also         creates that token account if it does not exist yet, which costs \
             the shop about 0.00204 SOL in rent and nothing if it already exists\n",
        );
    }
    text.push_str("  Nothing else is in this transaction.\n");

    text.push_str("\nNot in the transaction, so not checked against it:\n");
    text.push_str(&format!(
        "  This refunds payment {}, order {}/{}.\n",
        prepared.original_signature, prepared.sales_point, prepared.order_counter
    ));
    text.push_str(
        "  Open that signature in an explorer to confirm the same amount arrived from the same \
         wallet.\n",
    );

    let json_block = json!({
        "from_bytes": {
            "amount_base_units": facts.amount_base_units,
            "amount_ui": ui,
            "decimals": facts.decimals,
            "mint": facts.mint,
            "source_token_account": facts.source_ata,
            "destination_token_account": facts.destination_ata,
            "signer": facts.owner,
            "blockhash": facts.blockhash,
            "creates_destination_account": facts.creates_destination_account,
        },
        "not_in_bytes": {
            "destination_wallet": prepared.destination_owner,
            "original_signature": prepared.original_signature,
            "sales_point": prepared.sales_point,
            "order_counter": prepared.order_counter,
        }
    });

    Ok(format!("{text}\n{json_block}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quote::{MAX_ORDER_COUNTER, MAX_SALES_POINT, MIN_SALES_POINT};
    use crate::settle::parse_settlement_payment;
    use serde_json::Value;

    const MERCHANT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const CUSTOMER: &str = "GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const USDT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

    /// Mainnet-verified associated token accounts from the pda vectors.
    const MERCHANT_ATA: &str = "FGETo8T8wMcN2wCjav8VK6eh3dLk63evNDPxzLSJra8B";
    const CUSTOMER_ATA: &str = "6u6tm3d9Vf4QUDdbtMaV21qsmPHorJebdyDT6ZJ9h5JY";

    const BLOCKHASH: &str = "GXUnrX52iuQTFTqqCMDwoL6o8uMqfdFoodnXCsNGGoRr";
    const NOW: i64 = 1_750_000_000;

    /// Order 3/47 on a ten dollar sale, and 3/48 on a twenty five.
    const PAID_47: u64 = 10_000_347;
    const PAID_48: u64 = 25_000_348;

    fn sig(byte: u8) -> String {
        bs58::encode([byte; 64]).into_string()
    }

    fn shop() -> ShopConfig {
        ShopConfig::from_section(&HashMap::from([
            ("merchant_address".to_string(), MERCHANT.to_string()),
            ("mint".to_string(), USDC.to_string()),
            ("mint_decimals".to_string(), "6".to_string()),
            ("sales_point".to_string(), "3".to_string()),
        ]))
        .unwrap()
    }

    fn open_policy() -> RefundPolicy {
        RefundPolicy::from_section(&HashMap::new())
    }

    /// A jsonParsed `getTransaction` body for a plain SPL transfer into
    /// the merchant's account, so every payment used in these tests is
    /// one the settle parser produced from chain data rather than one a
    /// test hand-built.
    fn transfer_body(mint: &str, amount: u64, block_time: Option<i64>) -> String {
        let customer_pre = 500_000_000u64;
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "slot": 301_455_912u64,
                "blockTime": block_time,
                "meta": {
                    "err": null,
                    "fee": 5000,
                    "preTokenBalances": [
                        {"accountIndex": 1, "mint": mint, "owner": CUSTOMER,
                         "uiTokenAmount": {"amount": customer_pre.to_string(), "decimals": 6}},
                        {"accountIndex": 2, "mint": mint, "owner": MERCHANT,
                         "uiTokenAmount": {"amount": "0", "decimals": 6}}
                    ],
                    "postTokenBalances": [
                        {"accountIndex": 1, "mint": mint, "owner": CUSTOMER,
                         "uiTokenAmount": {"amount": (customer_pre - amount).to_string(),
                                           "decimals": 6}},
                        {"accountIndex": 2, "mint": mint, "owner": MERCHANT,
                         "uiTokenAmount": {"amount": amount.to_string(), "decimals": 6}}
                    ]
                },
                "transaction": {"message": {"accountKeys": [
                    {"pubkey": CUSTOMER, "signer": true, "writable": true},
                    {"pubkey": CUSTOMER_ATA}, {"pubkey": MERCHANT_ATA}
                ]}}
            }
        })
        .to_string()
    }

    fn payment_at(sig_byte: u8, amount: u64, block_time: Option<i64>) -> ReceivedPayment {
        parse_settlement_payment(
            &sig(sig_byte),
            MERCHANT,
            USDC,
            &transfer_body(USDC, amount, block_time),
        )
        .unwrap()
        .expect("the merchant received money")
    }

    fn payment(sig_byte: u8, amount: u64) -> ReceivedPayment {
        payment_at(sig_byte, amount, Some(NOW))
    }

    fn prepare(
        order: OrderRef,
        receipts: &[ReceivedPayment],
        policy: &RefundPolicy,
        records: &[RefundRecord],
        now: i64,
    ) -> Result<PreparedRefund, String> {
        prepare_refund(
            order,
            receipts,
            &shop(),
            policy,
            records,
            MERCHANT,
            BLOCKHASH,
            now,
        )
    }

    fn order_47() -> OrderRef {
        OrderRef::new(3, 47).unwrap()
    }

    #[test]
    fn a_refund_derives_the_original_amount_and_the_original_payer() {
        let receipts = vec![payment(1, PAID_47)];
        let prepared = prepare(order_47(), &receipts, &open_policy(), &[], NOW).unwrap();

        // Exactly what arrived, tag included, and not a rounded version
        // of it.
        assert_eq!(prepared.amount_base_units, PAID_47);
        assert_eq!(prepared.mint, USDC);
        assert_eq!(prepared.decimals, 6);
        // The wallet the money left, derived from the balance deltas.
        assert_eq!(prepared.destination_owner, CUSTOMER);
        assert_eq!(prepared.destination_ata, CUSTOMER_ATA);
        assert_eq!(prepared.source_ata, MERCHANT_ATA);
        assert_eq!(prepared.merchant, MERCHANT);
        assert_eq!(prepared.original_signature, sig(1));
        assert_eq!(prepared.sales_point, 3);
        assert_eq!(prepared.order_counter, 47);
    }

    #[test]
    fn the_compiled_message_is_exactly_the_expected_bytes() {
        // Asserted position by position the way message.rs and token.rs
        // do, because the layout is what the token program executes and a
        // transposed index is a transfer that still signs.
        let receipts = vec![payment(1, PAID_47)];
        let msg = prepare(order_47(), &receipts, &open_policy(), &[], NOW)
            .unwrap()
            .message;

        let merchant = decode_pubkey(MERCHANT).unwrap();
        let mint = decode_pubkey(USDC).unwrap();
        let token_program = decode_pubkey(TOKEN_PROGRAM_ID).unwrap();
        let ata_program = decode_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID).unwrap();
        let source_ata = decode_pubkey(MERCHANT_ATA).unwrap();
        let destination_ata = decode_pubkey(CUSTOMER_ATA).unwrap();
        let customer = decode_pubkey(CUSTOMER).unwrap();

        // One signature, no readonly signers, five readonly unsigned.
        assert_eq!(&msg[0..3], &[1, 0, 5]);
        assert_eq!(msg[3], 8, "eight account keys");
        // Canonical order: fee payer, writables, then readonlys.
        assert_eq!(&msg[4..36], &merchant);
        assert_eq!(&msg[36..68], &destination_ata);
        assert_eq!(&msg[68..100], &source_ata);
        assert_eq!(&msg[100..132], &customer);
        assert_eq!(&msg[132..164], &mint);
        assert_eq!(&msg[164..196], &SYSTEM_PROGRAM_ID);
        assert_eq!(&msg[196..228], &token_program);
        assert_eq!(&msg[228..260], &ata_program);
        assert_eq!(
            &msg[260..292],
            bs58::decode(BLOCKHASH).into_vec().unwrap().as_slice()
        );

        // Two instructions. CreateIdempotent on the ATA program, then
        // TransferChecked with accounts [source, mint, dest, owner].
        assert_eq!(msg[292], 2);
        assert_eq!(&msg[293..303], &[7, 6, 0, 1, 3, 4, 5, 6, 1, IX_CREATE_IDEMPOTENT]);
        assert_eq!(&msg[303..310], &[6, 4, 2, 4, 1, 0, 10]);
        assert_eq!(msg[310], IX_TRANSFER_CHECKED);
        assert_eq!(&msg[311..319], &PAID_47.to_le_bytes());
        assert_eq!(msg[319], 6, "decimals come from shop config");
        assert_eq!(msg.len(), 320);
    }

    #[test]
    fn no_reachable_input_can_name_a_different_amount_or_destination() {
        // The property the module exists for, stated as a sweep. The
        // order reference is the only lever a caller has, so every value
        // it can take is tried, and each one either refuses or produces a
        // refund whose amount and payee came from a payment in the list.
        // There is no argument for an amount or an address to vary,
        // which is why this test can be exhaustive at all.
        let receipts = vec![payment(1, PAID_47), payment(2, PAID_48)];
        let policy = open_policy();
        let mut accepted = 0;
        for sales_point in MIN_SALES_POINT..=MAX_SALES_POINT {
            for order_counter in 0..=MAX_ORDER_COUNTER {
                let order = OrderRef {
                    sales_point,
                    order_counter,
                };
                if let Ok(prepared) = prepare(order, &receipts, &policy, &[], NOW) {
                    let backing = receipts
                        .iter()
                        .find(|r| r.signature == prepared.original_signature)
                        .expect("a refund must name a payment from the list");
                    assert_eq!(prepared.amount_base_units, backing.amount_base_units);
                    assert_eq!(
                        Some(prepared.destination_owner.as_str()),
                        backing.source_owner.as_deref()
                    );
                    assert_eq!(prepared.mint, backing.mint);
                    accepted += 1;
                }
            }
        }
        assert_eq!(accepted, 2, "exactly the two paid orders are refundable");
    }

    #[test]
    fn a_second_refund_of_the_same_order_is_refused() {
        // A double refund is a drain, so this is the refusal that matters
        // most in the module.
        let receipts = vec![payment(1, PAID_47)];
        let policy = open_policy();
        let first = prepare(order_47(), &receipts, &policy, &[], NOW).unwrap();
        let records = vec![first.record()];

        let err = prepare(order_47(), &receipts, &policy, &records, NOW).unwrap_err();
        assert!(err.contains("already been refunded"), "{err}");
        // Still refused later in the day, and still refused when the
        // caller asks again with a fresh clock.
        let err = prepare(order_47(), &receipts, &policy, &records, NOW + 3_600).unwrap_err();
        assert!(err.contains("already been refunded"), "{err}");
    }

    #[test]
    fn a_refund_outside_the_window_is_refused_at_the_boundary() {
        let receipts = vec![payment(1, PAID_47)];
        let policy = RefundPolicy::from_section(&HashMap::from([(
            "refund_window_secs".to_string(),
            "900".to_string(),
        )]));
        assert!(prepare(order_47(), &receipts, &policy, &[], NOW + 900).is_ok());
        let err = prepare(order_47(), &receipts, &policy, &[], NOW + 901).unwrap_err();
        assert!(err.contains("refund window"), "{err}");
        assert!(err.contains("refund_window_secs"), "{err}");
    }

    #[test]
    fn a_window_of_zero_switches_refunds_off() {
        let receipts = vec![payment(1, PAID_47)];
        let policy = RefundPolicy::from_section(&HashMap::from([(
            "refund_window_secs".to_string(),
            "0".to_string(),
        )]));
        let err = prepare(order_47(), &receipts, &policy, &[], NOW).unwrap_err();
        assert!(err.contains("switched off"), "{err}");
    }

    #[test]
    fn a_payment_with_no_block_time_cannot_be_placed_in_the_window() {
        let receipts = vec![payment_at(1, PAID_47, None)];
        let err = prepare(order_47(), &receipts, &open_policy(), &[], NOW).unwrap_err();
        assert!(err.contains("no block time"), "{err}");
    }

    #[test]
    fn a_payment_dated_in_the_future_is_refused_rather_than_trusted() {
        let receipts = vec![payment_at(1, PAID_47, Some(NOW + 60))];
        let err = prepare(order_47(), &receipts, &open_policy(), &[], NOW).unwrap_err();
        assert!(err.contains("after the current time"), "{err}");
    }

    #[test]
    fn the_daily_ceiling_is_enforced_across_several_refunds() {
        // Thirty dollars of headroom, then a ten dollar refund and a
        // twenty five dollar one.
        let receipts = vec![payment(1, PAID_47), payment(2, PAID_48)];
        let policy = RefundPolicy::from_section(&HashMap::from([(
            "max_refund_per_day_base_units".to_string(),
            "30000000".to_string(),
        )]));

        let first = prepare(order_47(), &receipts, &policy, &[], NOW).unwrap();
        let records = vec![first.record()];

        let order_48 = OrderRef::new(3, 48).unwrap();
        let err = prepare(order_48, &receipts, &policy, &records, NOW).unwrap_err();
        assert!(err.contains("ceiling"), "{err}");
        assert!(err.contains("max_refund_per_day_base_units"), "{err}");

        // The window rolls: once the earlier refund is more than a day
        // old it stops counting, and the same refund goes through. The
        // payment has to be recent for its own window, so it is dated
        // alongside the later clock.
        let later = NOW + REFUND_DAY_SECS + 1;
        let fresh = vec![payment_at(2, PAID_48, Some(later))];
        assert!(prepare(order_48, &fresh, &policy, &records, later).is_ok());
    }

    #[test]
    fn a_ceiling_counts_refunds_dated_in_the_future() {
        // A clock that runs ahead must not buy headroom.
        let receipts = vec![payment(1, PAID_47)];
        let policy = RefundPolicy::from_section(&HashMap::from([(
            "max_refund_per_day_base_units".to_string(),
            "15000000".to_string(),
        )]));
        let records = vec![RefundRecord {
            sales_point: 9,
            order_counter: 1,
            original_signature: sig(9),
            amount_base_units: 10_000_000,
            mint: USDC.to_string(),
            destination_owner: CUSTOMER.to_string(),
            prepared_at_unix: NOW + 10 * REFUND_DAY_SECS,
        }];
        let err = prepare(order_47(), &receipts, &policy, &records, NOW).unwrap_err();
        assert!(err.contains("ceiling"), "{err}");
    }

    #[test]
    fn a_refund_of_an_unpaid_order_is_refused() {
        // Order 3/47 was quoted and never paid, so the receipts hold
        // somebody else's order entirely.
        let receipts = vec![payment(2, PAID_48)];
        let err = prepare(order_47(), &receipts, &open_policy(), &[], NOW).unwrap_err();
        assert!(err.contains("never paid"), "{err}");

        // And with no chain data at all, which is the state a caller
        // relaying "I paid, refund me" would be in.
        let err = prepare(order_47(), &[], &open_policy(), &[], NOW).unwrap_err();
        assert!(err.contains("nothing to refund"), "{err}");
    }

    #[test]
    fn a_payment_with_no_single_sender_is_refused_rather_than_guessed() {
        // Money that arrived through a router: two accounts fell, so no
        // one of them is the payer.
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "slot": 1u64,
                "blockTime": NOW,
                "meta": {
                    "err": null,
                    "fee": 5000,
                    "preTokenBalances": [
                        {"accountIndex": 1, "mint": USDC, "owner": CUSTOMER,
                         "uiTokenAmount": {"amount": "9000000", "decimals": 6}},
                        {"accountIndex": 2, "mint": USDC, "owner": USDT,
                         "uiTokenAmount": {"amount": "9000000", "decimals": 6}},
                        {"accountIndex": 3, "mint": USDC, "owner": MERCHANT,
                         "uiTokenAmount": {"amount": "0", "decimals": 6}}
                    ],
                    "postTokenBalances": [
                        {"accountIndex": 1, "mint": USDC, "owner": CUSTOMER,
                         "uiTokenAmount": {"amount": "8000000", "decimals": 6}},
                        {"accountIndex": 2, "mint": USDC, "owner": USDT,
                         "uiTokenAmount": {"amount": "0", "decimals": 6}},
                        {"accountIndex": 3, "mint": USDC,  "owner": MERCHANT,
                         "uiTokenAmount": {"amount": "10000347", "decimals": 6}}
                    ]
                },
                "transaction": {"message": {"accountKeys": [{"pubkey": CUSTOMER}]}}
            }
        })
        .to_string();
        let routed = parse_settlement_payment(&sig(4), MERCHANT, USDC, &body)
            .unwrap()
            .unwrap();
        assert_eq!(routed.amount_base_units, PAID_47);
        assert_eq!(routed.source_owner, None, "no single sender");

        let err = prepare(order_47(), &[routed], &open_policy(), &[], NOW).unwrap_err();
        assert!(err.contains("original payer cannot be determined"), "{err}");
    }

    #[test]
    fn money_that_arrived_elsewhere_or_in_another_mint_is_not_refundable() {
        // Built by hand rather than parsed, because the settle parser
        // will not produce either shape. They guard the checks directly.
        let base = payment(1, PAID_47);

        let mut wrong_merchant = base.clone();
        wrong_merchant.merchant = CUSTOMER.to_string();
        let err = prepare(order_47(), &[wrong_merchant], &open_policy(), &[], NOW).unwrap_err();
        assert!(err.contains("not this shop's money") || err.contains("rather than the configured merchant"), "{err}");

        let mut wrong_mint = base;
        wrong_mint.mint = USDT.to_string();
        let err = prepare(order_47(), &[wrong_mint], &open_policy(), &[], NOW).unwrap_err();
        assert!(err.contains("settles in"), "{err}");
    }

    #[test]
    fn a_refund_to_the_merchant_itself_is_refused() {
        let mut self_paid = payment(1, PAID_47);
        self_paid.source_owner = Some(MERCHANT.to_string());
        let err = prepare(order_47(), &[self_paid], &open_policy(), &[], NOW).unwrap_err();
        assert!(err.contains("not a refund"), "{err}");
    }

    #[test]
    fn a_signer_that_is_not_the_configured_merchant_is_refused() {
        let receipts = vec![payment(1, PAID_47)];
        let err = prepare_refund(
            order_47(),
            &receipts,
            &shop(),
            &open_policy(),
            &[],
            CUSTOMER,
            BLOCKHASH,
            NOW,
        )
        .unwrap_err();
        assert!(err.contains("refusing to prepare"), "{err}");
    }

    #[test]
    fn two_payments_sharing_a_tag_are_ambiguous_and_refused() {
        // The counter cycled while both were still on the books.
        let receipts = vec![payment(1, PAID_47), payment(5, PAID_47)];
        let err = prepare(order_47(), &receipts, &open_policy(), &[], NOW).unwrap_err();
        assert!(err.contains("two payments carry the tag"), "{err}");
    }

    #[test]
    fn the_approval_text_matches_what_the_bytes_contain() {
        let receipts = vec![payment(1, PAID_47)];
        let prepared = prepare(order_47(), &receipts, &open_policy(), &[], NOW).unwrap();
        let text = render_approval(&prepared).unwrap();

        // Everything the human reads is in the message they are signing.
        let facts = parse_refund_message(&prepared.message).unwrap();
        assert_eq!(facts.amount_base_units, PAID_47);
        assert_eq!(facts.mint, USDC);
        assert_eq!(facts.source_ata, MERCHANT_ATA);
        assert_eq!(facts.destination_ata, CUSTOMER_ATA);
        assert_eq!(facts.owner, MERCHANT);
        assert_eq!(facts.blockhash, BLOCKHASH);
        assert!(facts.creates_destination_account);

        assert!(text.contains("10.000347"), "{text}");
        assert!(text.contains("10000347 base units"), "{text}");
        assert!(text.contains(CUSTOMER_ATA), "{text}");
        assert!(text.contains(CUSTOMER), "the payee wallet is named");
        assert!(text.contains(MERCHANT_ATA), "{text}");
        assert!(text.contains(USDC), "{text}");
        assert!(text.contains(BLOCKHASH), "{text}");
        assert!(text.contains(&sig(1)), "the originating payment is named");
        assert!(text.contains("Not in the transaction"), "{text}");
        assert!(text.contains("0.00204 SOL"), "rent is disclosed");

        // The JSON block separates checked facts from unchecked context
        // so a reader cannot confuse the two.
        let json_start = text.find('{').unwrap();
        let parsed: Value = serde_json::from_str(&text[json_start..]).unwrap();
        assert_eq!(parsed["from_bytes"]["amount_base_units"], PAID_47);
        assert_eq!(parsed["from_bytes"]["destination_token_account"], CUSTOMER_ATA);
        assert_eq!(parsed["not_in_bytes"]["original_signature"], sig(1));
    }

    #[test]
    fn tampering_with_either_side_makes_the_approval_refuse_to_render() {
        // The point of parsing the bytes back: the text cannot drift from
        // the thing being signed in either direction.
        let receipts = vec![payment(1, PAID_47)];
        let prepared = prepare(order_47(), &receipts, &open_policy(), &[], NOW).unwrap();

        // Alter the amount inside the transaction. The derived fields
        // still say the honest number, and rendering must stop.
        let mut tampered_bytes = prepared.clone();
        let amount_at = tampered_bytes.message.len() - 9;
        tampered_bytes.message[amount_at..amount_at + 8]
            .copy_from_slice(&999_999_999u64.to_le_bytes());
        let err = render_approval(&tampered_bytes).unwrap_err();
        assert!(err.contains("amount"), "{err}");
        assert!(err.contains("thing being signed"), "{err}");

        // Alter the description instead. Same refusal, from the other
        // side, which is the case where a summary lies about honest bytes.
        let mut tampered_text = prepared.clone();
        tampered_text.amount_base_units = 1;
        assert!(render_approval(&tampered_text).is_err());

        // Rename the payee without touching the bytes. This is the attack
        // the re-derivation exists for: the token account in the message
        // no longer belongs to the wallet the text would print.
        let mut tampered_payee = prepared;
        tampered_payee.destination_owner = MERCHANT.to_string();
        let err = render_approval(&tampered_payee).unwrap_err();
        assert!(err.contains("as the payee"), "{err}");
    }

    #[test]
    fn the_parser_refuses_a_message_carrying_anything_extra() {
        let receipts = vec![payment(1, PAID_47)];
        let prepared = prepare(order_47(), &receipts, &open_policy(), &[], NOW).unwrap();

        // Trailing bytes mean the structure was misread.
        let mut extra = prepared.message.clone();
        extra.push(0xFF);
        let err = parse_refund_message(&extra).unwrap_err();
        assert!(err.contains("left over"), "{err}");

        // An instruction against some other program. The message claims
        // three instructions and appends a call to the system program.
        let mut smuggled = prepared.message.clone();
        smuggled[292] = 3;
        smuggled.extend_from_slice(&[5, 1, 0, 4, 2, 0, 0, 0]);
        let err = parse_refund_message(&smuggled).unwrap_err();
        assert!(err.contains("which a refund never needs"), "{err}");

        // Truncation anywhere is an error rather than a partial read.
        for cut in [0, 3, 100, 300, 319] {
            assert!(parse_refund_message(&prepared.message[..cut]).is_err());
        }
    }

    #[test]
    fn the_policy_defaults_are_the_restrictive_ones() {
        // The empty section is not an edge case, it is what a shop runs
        // with before anyone configures it.
        let policy = RefundPolicy::from_section(&HashMap::new());
        assert_eq!(policy.refund_window_secs, DEFAULT_REFUND_WINDOW_SECS);
        assert_eq!(
            policy.max_refund_per_day_base_units,
            DEFAULT_MAX_REFUND_PER_DAY_BASE_UNITS
        );
        assert!(
            !policy.allow_partial_refunds,
            "partial refunds are off unless an operator turns them on"
        );
    }

    #[test]
    fn policy_overrides_are_read_and_nonsense_falls_back() {
        let section = HashMap::from([
            ("refund_window_secs".to_string(), "3600".to_string()),
            (
                "max_refund_per_day_base_units".to_string(),
                "250000000".to_string(),
            ),
            ("allow_partial_refunds".to_string(), "true".to_string()),
        ]);
        let policy = RefundPolicy::from_section(&section);
        assert_eq!(policy.refund_window_secs, 3_600);
        assert_eq!(policy.max_refund_per_day_base_units, 250_000_000);
        assert!(policy.allow_partial_refunds);

        for bad in ["soon", "", "-1", "lots"] {
            let section = HashMap::from([
                ("refund_window_secs".to_string(), bad.to_string()),
                ("max_refund_per_day_base_units".to_string(), bad.to_string()),
                ("allow_partial_refunds".to_string(), bad.to_string()),
            ]);
            let policy = RefundPolicy::from_section(&section);
            assert_eq!(policy.refund_window_secs, DEFAULT_REFUND_WINDOW_SECS);
            assert_eq!(
                policy.max_refund_per_day_base_units,
                DEFAULT_MAX_REFUND_PER_DAY_BASE_UNITS
            );
            assert!(!policy.allow_partial_refunds, "{bad:?} must not enable partials");
        }
    }

    #[test]
    fn an_order_reference_outside_the_tag_range_is_refused() {
        let receipts = vec![payment(1, PAID_47)];
        let bad = OrderRef {
            sales_point: 0,
            order_counter: 47,
        };
        assert!(prepare(bad, &receipts, &open_policy(), &[], NOW).is_err());
        assert!(OrderRef::new(0, 1).is_err());
        assert!(OrderRef::new(1, 100).is_err());
    }

    #[test]
    fn an_order_reference_can_be_taken_from_a_sale_or_a_payment() {
        let sale = ConfirmedSale {
            signature: sig(1),
            slot: 1,
            block_time_unix: Some(NOW),
            sales_point: 3,
            order_counter: 47,
            sku: "RICE-5KG".to_string(),
            quantity: 1,
            // Deliberately absurd, to show the refund does not read it.
            amount_base_units: 999_999_999,
            mint: USDC.to_string(),
            payer: CUSTOMER.to_string(),
        };
        assert_eq!(OrderRef::from_sale(&sale).unwrap(), order_47());

        let receipts = vec![payment(1, PAID_47)];
        let prepared = prepare(
            OrderRef::from_sale(&sale).unwrap(),
            &receipts,
            &open_policy(),
            &[],
            NOW,
        )
        .unwrap();
        assert_eq!(
            prepared.amount_base_units, PAID_47,
            "the amount comes from the ledger, not from the sale struct"
        );

        assert_eq!(
            OrderRef::from_payment(&receipts[0]).unwrap(),
            Some(order_47())
        );
        // An untagged transfer names no order.
        let untagged = payment(6, 10_000_000);
        assert_eq!(OrderRef::from_payment(&untagged).unwrap(), None);
    }
}
