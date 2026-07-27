//! Settlement: finding payments on chain and matching them to quotes.
//!
//! A quote is a promise the shop made. Settlement is the only place that
//! decides the promise was kept, and the rule it works by is that a sale
//! is confirmed by the ledger or it is not confirmed at all.
//!
//! Why that rule is written down rather than assumed. The agent talks to
//! customers, and a customer is an untrusted source of text. "I already
//! paid", "the transfer went through, check again", "my wallet says
//! confirmed" are all things a real customer says honestly and a thief
//! says deliberately, and no amount of reading the message distinguishes
//! them. So nothing in this module accepts a payment claim as an input.
//! There is no `mark_paid`, no `confirm(signature)` that trusts its
//! argument, and no function that takes an amount and believes it. The
//! only way to reach `Settlement::Confirmed` is to hand this module the
//! raw body of an RPC response and let it do the arithmetic. The model
//! selects which transaction to look at; the code decides what that
//! transaction means.
//!
//! The same reasoning explains why the merchant address and the mint are
//! not parameters a caller chooses freely in practice. They come from
//! `catalog::ShopConfig`, which reads them from operator config, and this
//! module derives the receiving token account itself with
//! `pda::associated_token_address` rather than accepting an account to
//! watch. A caller who could name the account being polled could point
//! the shop at an address they control. They still could not fake a sale,
//! because the amount is credited only when chain data shows the merchant
//! as the owner of the account that gained it, but making the wrong thing
//! hard to express is cheaper than relying on the last check to catch it.
//!
//! How the amount is read is a decision worth stating. The naive route is
//! to walk the instruction list looking for an SPL transfer, and it is
//! wrong in both directions: it misses money that arrived through a swap,
//! a router, or any program that moves tokens by CPI, and it counts money
//! that an inner instruction later moved back out. Balance deltas do not
//! have that problem. `meta.preTokenBalances` and `meta.postTokenBalances`
//! are the ledger's own before and after for every token account the
//! transaction touched, so the difference across the merchant's accounts
//! is what the merchant actually ended up with, whatever path it took.
//!
//! Everything that is not a clean match becomes an exception rather than
//! an error or a silent drop. An underpayment is a customer who owes the
//! difference, an overpayment is a customer owed change, an untagged
//! transfer is someone sending a round number to the shop address, and a
//! payment against an expired quote is a real person who paid late. Each
//! of those needs a human, and each of them carries the signature so the
//! human can open it in an explorer and see the same facts this module
//! saw.
//!
//! One consequence of tagging is worth stating before it surprises
//! someone reading an exceptions queue. The tag lives in the digits below
//! a cent, so a shortfall smaller than a cent does not arrive as a
//! shortfall at all: it arrives as a different tag. Ten dollars forty
//! seven, one base unit light, is 10.000346, which reads as order 46 and
//! not as order 47 underpaid. `Underpaid` and `Overpaid` therefore report
//! discrepancies that are whole cents, the granularity a customer can
//! actually get wrong, and anything finer surfaces as `NoMatchingQuote`
//! or as a mismatch against whichever other order shares those digits.
//!
//! That is not a hole, because the property being defended is narrower
//! and stronger: a quote confirms only when the received amount equals
//! its `amount_due_base_units` exactly. Every other amount, larger,
//! smaller, or shifted by a single base unit, produces an exception. So
//! an attacker who shaves the amount cannot land on a confirmed sale for
//! less money; the worst they achieve is a queue entry with their
//! signature on it.

use serde_json::{json, Value};

use crate::address::{decode_pubkey, encode_pubkey, validate_pubkey};
use crate::pda::associated_token_address;
use crate::quote::{decode_amount, Quote};
use crate::rpc::{parse_result_value, TOKEN_PROGRAM_ID};
use crate::tx::validate_signature;

/// The largest page `getSignaturesForAddress` will return.
pub const MAX_SIGNATURE_LIMIT: u32 = 1_000;

/// A sensible page size for a poll. Small enough that a busy shop still
/// gets a fast response, large enough that a quiet one needs one call.
pub const DEFAULT_SIGNATURE_LIMIT: u32 = 100;

/// Settlement reads at `finalized` and nothing softer.
///
/// A transaction that is confirmed but not yet finalized can still be
/// dropped by a fork. Handing a customer their goods and then watching
/// the payment disappear is the exact failure this module exists to
/// prevent, and the few extra seconds of latency cost nothing next to it.
pub const SETTLEMENT_COMMITMENT: &str = "finalized";

/// One entry from `getSignaturesForAddress`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRecord {
    pub signature: String,
    pub slot: u64,
    /// Absent on very old entries, so callers must tolerate `None`
    /// rather than treating a missing time as now.
    pub block_time_unix: Option<i64>,
    /// `None` means the transaction succeeded. `Some` carries the error
    /// as the RPC reported it.
    pub error: Option<String>,
}

impl SignatureRecord {
    /// True when this signature is worth fetching in full.
    ///
    /// A failed transaction moved no money. Its fee was still charged and
    /// it still appears in the account's history, so it must be filtered
    /// out explicitly rather than assumed away.
    pub fn is_candidate(&self) -> bool {
        self.error.is_none()
    }
}

/// A payment that chain data shows arriving at the merchant.
///
/// Every field here was read out of an RPC response. None of it was
/// supplied by a caller, which is the property that makes it safe to act
/// on. In particular `amount_base_units` is a balance delta computed from
/// the ledger, never a number anyone asserted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedPayment {
    pub signature: String,
    pub slot: u64,
    pub block_time_unix: Option<i64>,
    /// The merchant address the money arrived at, echoed back so a
    /// downstream reader does not have to reconstruct the context.
    pub merchant: String,
    /// The mint that moved. Checked against the shop's settlement mint
    /// again at match time.
    pub mint: String,
    /// Net increase across the merchant's token accounts for this mint,
    /// in the mint's smallest unit.
    pub amount_base_units: u64,
    /// The fee payer, account index zero. This is the presumed customer
    /// and it is informational only: it identifies who to talk to, and it
    /// never influences whether the sale is confirmed.
    pub payer: String,
    /// Owner of the token account the money left, when exactly one such
    /// account is identifiable. Also informational. A transfer routed
    /// through a swap has several, and then this is `None` rather than a
    /// guess.
    pub source_owner: Option<String>,
}

/// What a payment turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settlement {
    /// The ledger shows exactly the amount an open quote asked for.
    Confirmed(ConfirmedSale),
    /// Money arrived but something needs a human.
    Exception(SettlementException),
}

impl Settlement {
    /// The signature this outcome came from, in either case, so a caller
    /// can log or link it without matching on the variant.
    pub fn signature(&self) -> &str {
        match self {
            Settlement::Confirmed(sale) => &sale.signature,
            Settlement::Exception(exception) => &exception.signature,
        }
    }

    pub fn is_confirmed(&self) -> bool {
        matches!(self, Settlement::Confirmed(_))
    }
}

/// A sale the ledger proves was paid in full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedSale {
    pub signature: String,
    pub slot: u64,
    pub block_time_unix: Option<i64>,
    pub sales_point: u8,
    pub order_counter: u8,
    pub sku: String,
    pub quantity: u32,
    /// What was received, which for a confirmed sale is exactly the
    /// quote's `amount_due_base_units`.
    pub amount_base_units: u64,
    pub mint: String,
    /// Presumed customer, for the receipt. Not part of the proof.
    pub payer: String,
}

/// A payment that arrived and could not be turned into a sale.
///
/// The signature is mandatory on every exception. An exception a human
/// cannot open in an explorer is an exception they cannot resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementException {
    pub signature: String,
    pub slot: u64,
    pub block_time_unix: Option<i64>,
    pub amount_base_units: u64,
    pub mint: String,
    pub payer: String,
    pub reason: ExceptionReason,
}

/// Why a payment did not confirm a sale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExceptionReason {
    /// The low digits carry no sales point, so this transfer did not come
    /// from a quote we issued. Common and harmless: someone sent a round
    /// number to the shop address.
    Untagged,
    /// The tag decodes but no open quote carries it. Either the quote was
    /// already settled, or it was issued by a terminal whose open quotes
    /// this caller does not hold.
    NoMatchingQuote { sales_point: u8, order_counter: u8 },
    /// Less arrived than the quote asked for. Never confirms: a shop that
    /// rounds a shortfall up is a shop that can be drained one cent at a
    /// time.
    ///
    /// Reachable only when the shortfall is whole cents, since a smaller
    /// one alters the tag and lands somewhere else entirely. See the
    /// module documentation.
    Underpaid {
        expected: u64,
        received: u64,
        shortfall: u64,
    },
    /// More arrived than the quote asked for. Also never confirms, for a
    /// different reason: the customer is owed change, and quietly keeping
    /// it is theft even when it is convenient.
    Overpaid {
        expected: u64,
        received: u64,
        excess: u64,
    },
    /// A real customer paid a quote that had already died. Worth its own
    /// kind because the answer is a business decision, honor it or refund
    /// it, and not something code should make.
    QuoteExpired {
        sales_point: u8,
        order_counter: u8,
        expires_at_unix: i64,
    },
    /// The money that moved is not the mint the shop settles in.
    WrongMint { expected: String, received: String },
}

/// Derive the merchant's associated token account for the settlement
/// mint under the classic SPL Token program.
///
/// Derived rather than configured on purpose. An operator who pastes the
/// wrong receiving account into config would watch an address that never
/// receives anything and see a shop that reports no sales all day, and
/// the derivation removes that failure mode entirely.
pub fn merchant_token_account(merchant: &str, mint: &str) -> Result<String, String> {
    merchant_token_account_for_program(merchant, mint, TOKEN_PROGRAM_ID)
}

/// Same derivation against an explicit token program, for shops settling
/// in a Token-2022 mint.
pub fn merchant_token_account_for_program(
    merchant: &str,
    mint: &str,
    token_program: &str,
) -> Result<String, String> {
    let owner = decode_pubkey(merchant)
        .map_err(|e| format!("merchant address is not a valid Solana address: {e}"))?;
    let mint_bytes =
        decode_pubkey(mint).map_err(|e| format!("mint is not a valid Solana address: {e}"))?;
    let program = decode_pubkey(token_program)
        .map_err(|e| format!("token program is not a valid Solana address: {e}"))?;
    let ata = associated_token_address(&owner, &mint_bytes, &program)?;
    Ok(encode_pubkey(&ata))
}

/// Build a `getSignaturesForAddress` request for the merchant's token
/// account, under the classic SPL Token program.
///
/// `until` is the newest signature already processed. Passing it makes
/// the poll incremental: the node walks backwards from the tip and stops
/// there, so a shop that polls every few seconds reads a handful of
/// entries rather than the whole history. Passing `None` reads the most
/// recent `limit` entries, which is what a cold start wants.
pub fn signatures_request(
    merchant: &str,
    mint: &str,
    until: Option<&str>,
    limit: u32,
) -> Result<String, String> {
    signatures_request_for_program(merchant, mint, TOKEN_PROGRAM_ID, until, limit)
}

/// Same request against an explicit token program.
pub fn signatures_request_for_program(
    merchant: &str,
    mint: &str,
    token_program: &str,
    until: Option<&str>,
    limit: u32,
) -> Result<String, String> {
    let account = merchant_token_account_for_program(merchant, mint, token_program)?;
    if limit == 0 {
        return Err("a signature page of zero would poll nothing".to_string());
    }
    if limit > MAX_SIGNATURE_LIMIT {
        return Err(format!(
            "limit {limit} exceeds the {MAX_SIGNATURE_LIMIT} the RPC will return"
        ));
    }

    let mut config = json!({
        "limit": limit,
        "commitment": SETTLEMENT_COMMITMENT,
    });
    if let Some(until) = until {
        // Validated rather than passed through: a malformed cursor makes
        // the node ignore the bound and return the whole page, which
        // would silently reprocess history instead of erroring.
        let until = validate_signature(until)
            .map_err(|e| format!("until cursor is not a valid signature: {e}"))?;
        config["until"] = Value::String(until);
    }

    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [account, config]
    })
    .to_string())
}

/// Parse a `getSignaturesForAddress` response into every entry it holds,
/// failures included, so a caller that wants to report them can.
pub fn parse_signatures(body: &str) -> Result<Vec<SignatureRecord>, String> {
    let result = parse_result_value(body)?;
    let entries = result
        .as_array()
        .ok_or_else(|| "getSignaturesForAddress result is not an array".to_string())?;

    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        let signature = entry
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| "signature entry missing signature".to_string())?
            .to_string();
        let slot = entry.get("slot").and_then(Value::as_u64).unwrap_or(0);
        let block_time_unix = entry.get("blockTime").and_then(Value::as_i64);
        let error = match entry.get("err") {
            None | Some(Value::Null) => None,
            Some(e) => Some(e.to_string()),
        };
        records.push(SignatureRecord {
            signature,
            slot,
            block_time_unix,
            error,
        });
    }
    Ok(records)
}

/// Parse a `getSignaturesForAddress` response and keep only the entries
/// worth fetching.
///
/// Failed transactions are dropped here rather than deeper in, because a
/// failed transaction moved no money and every later stage would have to
/// remember that. Dropping them once, at the edge, means the rest of the
/// module only ever sees transfers that happened.
pub fn candidate_signatures(body: &str) -> Result<Vec<SignatureRecord>, String> {
    Ok(parse_signatures(body)?
        .into_iter()
        .filter(SignatureRecord::is_candidate)
        .collect())
}

/// Build the `getTransaction` request for a candidate signature.
///
/// Same shape as `tx::tx_request` with one addition: settlement pins the
/// commitment to finalized, because this response is what a sale is
/// confirmed from and a rolled back transfer must never reach the match
/// step at all.
pub fn settlement_tx_request(signature: &str) -> Result<String, String> {
    let sig = validate_signature(signature)?;
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTransaction",
        "params": [
            sig,
            {
                "encoding": "jsonParsed",
                "maxSupportedTransactionVersion": 0,
                "commitment": SETTLEMENT_COMMITMENT
            }
        ]
    })
    .to_string())
}

/// One token account's before and after for a single mint.
struct TokenDelta {
    owner: String,
    delta: i128,
}

/// Read `preTokenBalances` and `postTokenBalances` into a per-account
/// delta for one mint.
///
/// Entries are keyed by `accountIndex`, and an index may appear in only
/// one of the two lists: a token account created by this transaction has
/// no pre entry, and one closed by it has no post entry. Missing means
/// zero on that side, which is the correct reading in both cases.
fn token_deltas(meta: &Value, mint: &str) -> Result<Vec<TokenDelta>, String> {
    use std::collections::BTreeMap;

    // (owner, pre, post) keyed by account index.
    let mut by_index: BTreeMap<u64, (String, i128, i128)> = BTreeMap::new();

    for (key, is_post) in [("preTokenBalances", false), ("postTokenBalances", true)] {
        let entries = match meta.get(key).and_then(Value::as_array) {
            Some(entries) => entries,
            // A transaction that touched no token account has neither
            // list. That is not malformed, it just means nothing here.
            None => continue,
        };
        for entry in entries {
            if entry.get("mint").and_then(Value::as_str) != Some(mint) {
                continue;
            }
            let index = entry
                .get("accountIndex")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("{key} entry missing accountIndex"))?;
            let raw = entry
                .pointer("/uiTokenAmount/amount")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{key} entry missing uiTokenAmount.amount"))?;
            // The RPC sends base units as a decimal string precisely so
            // it does not lose precision in a JSON number, so it is
            // parsed as an integer and never through a float.
            let amount: i128 = raw
                .parse()
                .map_err(|_| format!("{key} entry amount {raw:?} is not an integer"))?;
            let owner = entry
                .get("owner")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();

            let slot = by_index
                .entry(index)
                .or_insert_with(|| (String::new(), 0, 0));
            // Older responses omit `owner` on the pre side, so whichever
            // side carries it wins rather than the last one seen.
            if slot.0.is_empty() && !owner.is_empty() {
                slot.0 = owner;
            }
            if is_post {
                slot.2 = amount;
            } else {
                slot.1 = amount;
            }
        }
    }

    Ok(by_index
        .into_values()
        .map(|(owner, pre, post)| TokenDelta {
            owner,
            delta: post - pre,
        })
        .collect())
}

/// Read a confirmed transaction and report what the merchant received.
///
/// `Ok(None)` covers every "nothing for us here" case: the node does not
/// have the transaction, the transaction failed, or the merchant's
/// balance in the settlement mint did not go up. None of those is an
/// error, and all of them are normal while polling an account that also
/// sees unrelated traffic.
///
/// The merchant address and the mint come from operator config. They are
/// the thing being checked against, so a caller who could vary them could
/// check against the wrong thing, and this function is never called with
/// values taken from customer text.
pub fn parse_settlement_payment(
    signature: &str,
    merchant: &str,
    settlement_mint: &str,
    body: &str,
) -> Result<Option<ReceivedPayment>, String> {
    let merchant = validate_pubkey(merchant)
        .map_err(|e| format!("merchant address is not a valid Solana address: {e}"))?;
    let mint = validate_pubkey(settlement_mint)
        .map_err(|e| format!("settlement mint is not a valid Solana address: {e}"))?;
    let signature = validate_signature(signature)?;

    let result = parse_result_value(body)?;
    if result.is_null() {
        return Ok(None);
    }

    let slot = result
        .get("slot")
        .and_then(Value::as_u64)
        .ok_or_else(|| "getTransaction result missing slot".to_string())?;
    let block_time_unix = result.get("blockTime").and_then(Value::as_i64);
    let meta = result
        .get("meta")
        .ok_or_else(|| "getTransaction result missing meta".to_string())?;

    // Belt and braces with the signature filter. A caller may have
    // fetched this transaction some other way, and a failed transaction
    // must never be readable as a payment no matter how it arrived.
    if !matches!(meta.get("err"), None | Some(Value::Null)) {
        return Ok(None);
    }

    let deltas = token_deltas(meta, &mint)?;
    let mut received: i128 = 0;
    let mut sources: Vec<String> = Vec::new();
    for entry in &deltas {
        if entry.owner == merchant {
            // Summed rather than taking the first match, because a
            // merchant may hold more than one account for a mint and an
            // internal move between two of them nets to zero, which is
            // the truthful answer.
            received += entry.delta;
        } else if entry.delta < 0 && !entry.owner.is_empty() {
            sources.push(entry.owner.clone());
        }
    }

    if received <= 0 {
        return Ok(None);
    }
    let amount_base_units = u64::try_from(received)
        .map_err(|_| format!("received amount {received} does not fit in u64"))?;

    let payer = result
        .pointer("/transaction/message/accountKeys/0")
        .and_then(|key| {
            key.get("pubkey")
                .and_then(Value::as_str)
                .or_else(|| key.as_str())
        })
        .unwrap_or_default()
        .to_string();

    // One decrease is a plain transfer and names the customer's token
    // account owner. Several means a swap or a router, where no single
    // account is "the source", so nothing is claimed.
    let source_owner = if sources.len() == 1 {
        Some(sources.remove(0))
    } else {
        None
    };

    Ok(Some(ReceivedPayment {
        signature,
        slot,
        block_time_unix,
        merchant,
        mint,
        amount_base_units,
        payer,
        source_owner,
    }))
}

/// Decide what a received payment means against the open quotes.
///
/// Takes a `ReceivedPayment` that came out of `parse_settlement_payment`
/// and nothing else. There is deliberately no overload that accepts an
/// amount, because an amount is exactly what a customer would want to
/// choose, and a function that accepted one would be a function that can
/// be talked into confirming a sale nobody paid for.
///
/// The order of the checks matters. Mint first, since a payment in the
/// wrong token is not a payment at all. Then the tag, then the quote,
/// then expiry, then the amount. Expiry outranks the amount because a
/// dead quote cannot be honored however much arrived, and reporting it as
/// an underpayment would send a human looking for a shortfall that is not
/// the problem.
pub fn match_payment(
    payment: &ReceivedPayment,
    open_quotes: &[Quote],
    settlement_mint: &str,
    now_unix: i64,
) -> Settlement {
    let exception = |reason: ExceptionReason| {
        Settlement::Exception(SettlementException {
            signature: payment.signature.clone(),
            slot: payment.slot,
            block_time_unix: payment.block_time_unix,
            amount_base_units: payment.amount_base_units,
            mint: payment.mint.clone(),
            payer: payment.payer.clone(),
            reason,
        })
    };

    if payment.mint != settlement_mint {
        return exception(ExceptionReason::WrongMint {
            expected: settlement_mint.to_string(),
            received: payment.mint.clone(),
        });
    }

    let (price, tag) = match decode_amount(payment.amount_base_units) {
        Ok(Some(decoded)) => decoded,
        // `Ok(None)` is an untagged transfer, a normal event. The `Err`
        // arm is structurally unreachable, since both tag components come
        // from a modulo that bounds them into range, but an unattributable
        // amount is an unattributable amount either way and it belongs in
        // the same queue rather than aborting a poll.
        Ok(None) | Err(_) => return exception(ExceptionReason::Untagged),
    };

    let matched = open_quotes
        .iter()
        .filter(|q| q.sales_point == tag.sales_point && q.order_counter == tag.order_counter)
        // Two open quotes carrying one tag is a caller bug, since the
        // counter is what keeps them apart. If it happens, prefer the one
        // the payment actually settles so the bug costs a sale no one
        // made rather than a sale someone did.
        .max_by_key(|q| {
            (
                q.amount_due_base_units == payment.amount_base_units,
                q.issued_at_unix,
            )
        });

    let quote = match matched {
        Some(quote) => quote,
        None => {
            return exception(ExceptionReason::NoMatchingQuote {
                sales_point: tag.sales_point,
                order_counter: tag.order_counter,
            })
        }
    };

    if quote.mint != payment.mint {
        return exception(ExceptionReason::WrongMint {
            expected: quote.mint.clone(),
            received: payment.mint.clone(),
        });
    }

    if quote.is_expired(now_unix) {
        return exception(ExceptionReason::QuoteExpired {
            sales_point: quote.sales_point,
            order_counter: quote.order_counter,
            expires_at_unix: quote.expires_at_unix,
        });
    }

    let expected = quote.amount_due_base_units;
    let received = payment.amount_base_units;
    if received < expected {
        return exception(ExceptionReason::Underpaid {
            expected,
            received,
            shortfall: expected - received,
        });
    }
    if received > expected {
        return exception(ExceptionReason::Overpaid {
            expected,
            received,
            excess: received - expected,
        });
    }

    // The price component equalling the subtotal is implied once the
    // amounts are equal, since both are their subtotal plus the same tag.
    // Asserted rather than dropped so that a future change to the
    // encoding cannot quietly break the equivalence.
    debug_assert_eq!(price, quote.subtotal_base_units);

    Settlement::Confirmed(ConfirmedSale {
        signature: payment.signature.clone(),
        slot: payment.slot,
        block_time_unix: payment.block_time_unix,
        sales_point: quote.sales_point,
        order_counter: quote.order_counter,
        sku: quote.sku.clone(),
        quantity: quote.quantity,
        amount_base_units: received,
        mint: payment.mint.clone(),
        payer: payment.payer.clone(),
    })
}

/// Read one `getTransaction` response and settle it in a single step.
///
/// `Ok(None)` means the transaction moved nothing to the merchant in the
/// settlement mint, so there is nothing to record. Anything that did move
/// money comes back as a `Settlement`, confirmed or exceptional.
///
/// This is the whole path from an RPC body to a decision, and it is the
/// only path. A caller cannot skip the parse and assert an outcome.
pub fn settle_transaction(
    signature: &str,
    merchant: &str,
    settlement_mint: &str,
    body: &str,
    open_quotes: &[Quote],
    now_unix: i64,
) -> Result<Option<Settlement>, String> {
    let payment = match parse_settlement_payment(signature, merchant, settlement_mint, body)? {
        Some(payment) => payment,
        None => return Ok(None),
    };
    Ok(Some(match_payment(
        &payment,
        open_quotes,
        settlement_mint,
        now_unix,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quote::issue_quote;

    const MERCHANT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const CUSTOMER: &str = "GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const USDT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

    /// The merchant's USDC associated token account, from pda's mainnet
    /// vectors, so the fixtures name a real derived account.
    const MERCHANT_ATA: &str = "FGETo8T8wMcN2wCjav8VK6eh3dLk63evNDPxzLSJra8B";
    const CUSTOMER_ATA: &str = "6u6tm3d9Vf4QUDdbtMaV21qsmPHorJebdyDT6ZJ9h5JY";

    const TEN_USDC: u64 = 10_000_000;
    const NOW: i64 = 1_750_000_000;

    fn sig(byte: u8) -> String {
        bs58::encode([byte; 64]).into_string()
    }

    /// Terminal 3, order 47, ten dollars: amount due is 10.000347.
    fn open_quote() -> Quote {
        issue_quote(3, 47, "RICE-5KG", 1, TEN_USDC, USDC, NOW - 60, 900).unwrap()
    }

    /// A jsonParsed `getTransaction` body shaped like a real mainnet
    /// response for an SPL transfer into the merchant's ATA.
    ///
    /// `pre` and `post` are the merchant's balance either side, so a test
    /// sets the received amount by choosing the difference rather than by
    /// stating it, the same way the parser reads it.
    fn transfer_body(mint: &str, pre: u64, post: u64) -> String {
        let customer_pre = 500_000_000u64;
        let moved = post - pre;
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "slot": 301_455_912u64,
                "blockTime": NOW,
                "meta": {
                    "err": null,
                    "fee": 5000,
                    "computeUnitsConsumed": 4645,
                    "preBalances": [1_000_000_000u64, 2_039_280u64, 2_039_280u64, 1u64],
                    "postBalances": [999_995_000u64, 2_039_280u64, 2_039_280u64, 1u64],
                    "preTokenBalances": [
                        {
                            "accountIndex": 1,
                            "mint": mint,
                            "owner": CUSTOMER,
                            "programId": TOKEN_PROGRAM_ID,
                            "uiTokenAmount": {
                                "amount": customer_pre.to_string(),
                                "decimals": 6,
                                "uiAmount": 500.0,
                                "uiAmountString": "500"
                            }
                        },
                        {
                            "accountIndex": 2,
                            "mint": mint,
                            "owner": MERCHANT,
                            "programId": TOKEN_PROGRAM_ID,
                            "uiTokenAmount": {
                                "amount": pre.to_string(),
                                "decimals": 6,
                                "uiAmount": 0.0,
                                "uiAmountString": "0"
                            }
                        }
                    ],
                    "postTokenBalances": [
                        {
                            "accountIndex": 1,
                            "mint": mint,
                            "owner": CUSTOMER,
                            "programId": TOKEN_PROGRAM_ID,
                            "uiTokenAmount": {
                                "amount": (customer_pre - moved).to_string(),
                                "decimals": 6,
                                "uiAmount": 490.0,
                                "uiAmountString": "490"
                            }
                        },
                        {
                            "accountIndex": 2,
                            "mint": mint,
                            "owner": MERCHANT,
                            "programId": TOKEN_PROGRAM_ID,
                            "uiTokenAmount": {
                                "amount": post.to_string(),
                                "decimals": 6,
                                "uiAmount": 10.0,
                                "uiAmountString": "10"
                            }
                        }
                    ],
                    "logMessages": [
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA invoke [1]",
                        "Program log: Instruction: TransferChecked",
                        "Program TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA success"
                    ]
                },
                "transaction": {
                    "message": {
                        "accountKeys": [
                            {"pubkey": CUSTOMER, "signer": true, "writable": true,
                             "source": "transaction"},
                            {"pubkey": CUSTOMER_ATA, "signer": false, "writable": true,
                             "source": "transaction"},
                            {"pubkey": MERCHANT_ATA, "signer": false, "writable": true,
                             "source": "transaction"},
                            {"pubkey": TOKEN_PROGRAM_ID, "signer": false, "writable": false,
                             "source": "transaction"}
                        ]
                    }
                }
            }
        })
        .to_string()
    }

    /// A body where the merchant receives exactly `amount`.
    fn paid(amount: u64) -> String {
        transfer_body(USDC, 0, amount)
    }

    #[test]
    fn merchant_ata_matches_the_mainnet_derivation() {
        // The account being polled is derived, never configured, so this
        // pins the derivation the poller depends on.
        assert_eq!(
            merchant_token_account(MERCHANT, USDC).unwrap(),
            MERCHANT_ATA
        );
    }

    #[test]
    fn signature_request_targets_the_derived_ata() {
        let req = signatures_request(MERCHANT, USDC, None, DEFAULT_SIGNATURE_LIMIT).unwrap();
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "getSignaturesForAddress");
        // Not the merchant wallet: token history lives on the ATA.
        assert_eq!(v["params"][0], MERCHANT_ATA);
        assert_eq!(v["params"][1]["limit"], DEFAULT_SIGNATURE_LIMIT);
        assert_eq!(v["params"][1]["commitment"], SETTLEMENT_COMMITMENT);
        assert!(v["params"][1].get("until").is_none());
    }

    #[test]
    fn until_cursor_makes_the_poll_incremental() {
        let cursor = sig(7);
        let req = signatures_request(MERCHANT, USDC, Some(&cursor), 25).unwrap();
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["params"][1]["until"], cursor.as_str());
        assert_eq!(v["params"][1]["limit"], 25);
    }

    #[test]
    fn a_malformed_cursor_is_refused_rather_than_ignored() {
        // A node given a bad `until` returns the full page, which would
        // silently reprocess history.
        let err = signatures_request(MERCHANT, USDC, Some("not-a-signature"), 25).unwrap_err();
        assert!(err.contains("until cursor"), "{err}");
    }

    #[test]
    fn nonsense_page_sizes_are_refused() {
        assert!(signatures_request(MERCHANT, USDC, None, 0).is_err());
        assert!(signatures_request(MERCHANT, USDC, None, MAX_SIGNATURE_LIMIT + 1).is_err());
        assert!(signatures_request(MERCHANT, USDC, None, MAX_SIGNATURE_LIMIT).is_ok());
    }

    #[test]
    fn failed_signatures_are_dropped_from_the_candidate_list() {
        let good = sig(1);
        let bad = sig(2);
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": [
                {"signature": good, "slot": 301_455_912u64, "blockTime": NOW,
                 "err": null, "memo": null, "confirmationStatus": "finalized"},
                {"signature": bad, "slot": 301_455_900u64, "blockTime": NOW - 10,
                 "err": {"InstructionError": [0, {"Custom": 1}]}, "memo": null,
                 "confirmationStatus": "finalized"}
            ]
        })
        .to_string();

        // Both entries survive the plain parse, with their error status.
        let all = parse_signatures(&body).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].block_time_unix, Some(NOW));
        assert!(all[1]
            .error
            .as_deref()
            .unwrap()
            .contains("InstructionError"));

        // A failed transaction moved no money, so it is never a candidate.
        let candidates = candidate_signatures(&body).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].signature, good);
    }

    #[test]
    fn tx_request_pins_finalized_and_json_parsed() {
        let s = sig(1);
        let req = settlement_tx_request(&s).unwrap();
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "getTransaction");
        assert_eq!(v["params"][0], s.as_str());
        assert_eq!(v["params"][1]["encoding"], "jsonParsed");
        assert_eq!(v["params"][1]["maxSupportedTransactionVersion"], 0);
        assert_eq!(v["params"][1]["commitment"], SETTLEMENT_COMMITMENT);
    }

    #[test]
    fn the_amount_comes_from_the_balance_delta() {
        let amount = 10_000_347;
        let payment = parse_settlement_payment(&sig(1), MERCHANT, USDC, &paid(amount))
            .unwrap()
            .expect("merchant received money");
        assert_eq!(payment.amount_base_units, amount);
        assert_eq!(payment.mint, USDC);
        assert_eq!(payment.merchant, MERCHANT);
        // Fee payer is the presumed customer, and the token account it
        // left belongs to the same person here.
        assert_eq!(payment.payer, CUSTOMER);
        assert_eq!(payment.source_owner.as_deref(), Some(CUSTOMER));
        assert_eq!(payment.block_time_unix, Some(NOW));
    }

    #[test]
    fn a_pre_existing_merchant_balance_does_not_inflate_the_amount() {
        // The merchant already held 40 USDC and receives 10.000347 more.
        let body = transfer_body(USDC, 40_000_000, 50_000_347);
        let payment = parse_settlement_payment(&sig(1), MERCHANT, USDC, &body)
            .unwrap()
            .unwrap();
        assert_eq!(payment.amount_base_units, 10_000_347);
    }

    #[test]
    fn exact_payment_confirms_the_sale() {
        let quote = open_quote();
        assert_eq!(quote.amount_due_base_units, 10_000_347);
        let settlement = settle_transaction(
            &sig(1),
            MERCHANT,
            USDC,
            &paid(quote.amount_due_base_units),
            std::slice::from_ref(&quote),
            NOW,
        )
        .unwrap()
        .expect("money arrived");

        match settlement {
            Settlement::Confirmed(sale) => {
                assert_eq!(sale.sku, "RICE-5KG");
                assert_eq!(sale.quantity, 1);
                assert_eq!(sale.sales_point, 3);
                assert_eq!(sale.order_counter, 47);
                assert_eq!(sale.amount_base_units, quote.amount_due_base_units);
                assert_eq!(sale.signature, sig(1));
                assert_eq!(sale.payer, CUSTOMER);
            }
            other => panic!("expected a confirmed sale, got {other:?}"),
        }
    }

    #[test]
    fn a_sub_cent_shortfall_moves_the_tag_and_still_never_confirms() {
        // Rounding a shortfall up is how a shop gets drained a cent at a
        // time, so the smallest unit short must not confirm. It does not,
        // but it does not report as an underpayment either: the missing
        // unit comes out of the tag, so 10.000347 becomes 10.000346,
        // which reads as order 46. This is the documented consequence of
        // spending the low digits on identity, pinned here so nobody
        // reads the exceptions queue and thinks it is a bug.
        let quote = open_quote();
        let short = quote.amount_due_base_units - 1;
        let settlement = settle_transaction(
            &sig(1),
            MERCHANT,
            USDC,
            &paid(short),
            std::slice::from_ref(&quote),
            NOW,
        )
        .unwrap()
        .unwrap();
        assert!(!settlement.is_confirmed());
        match settlement {
            Settlement::Exception(e) => {
                assert_eq!(
                    e.reason,
                    ExceptionReason::NoMatchingQuote {
                        sales_point: 3,
                        order_counter: 46,
                    }
                );
                // Every exception is openable in an explorer.
                assert_eq!(e.signature, sig(1));
                assert_eq!(e.amount_base_units, short);
            }
            other => panic!("expected an exception, got {other:?}"),
        }
    }

    #[test]
    fn a_sub_cent_shortfall_that_lands_on_another_open_order_still_never_confirms() {
        // The awkward case: order 46 is also open, at a different price,
        // so the shaved payment finds a quote. It must not be honored as
        // either sale, and here it reads as a large overpayment of the
        // cheaper one, which is exactly the sort of thing a human should
        // look at.
        let cheaper = issue_quote(3, 46, "OIL-1L", 1, 3_500_000, USDC, NOW - 120, 900).unwrap();
        let quote = open_quote();
        let short = quote.amount_due_base_units - 1;
        let settlement = settle_transaction(
            &sig(1),
            MERCHANT,
            USDC,
            &paid(short),
            &[cheaper, quote],
            NOW,
        )
        .unwrap()
        .unwrap();
        assert!(!settlement.is_confirmed(), "got {settlement:?}");
        match settlement {
            Settlement::Exception(e) => assert!(
                matches!(e.reason, ExceptionReason::Overpaid { .. }),
                "got {:?}",
                e.reason
            ),
            other => panic!("expected an exception, got {other:?}"),
        }
    }

    #[test]
    fn only_the_exact_amount_ever_confirms() {
        // The property the whole module rests on, checked by sweeping a
        // window of amounts around the one that is due. Every open quote
        // in the book is offered, so a near miss has every chance to
        // match something, and none of them may confirm.
        let quotes = vec![
            issue_quote(3, 46, "OIL-1L", 1, 3_500_000, USDC, NOW - 120, 900).unwrap(),
            open_quote(),
            issue_quote(3, 48, "RICE-5KG", 2, TEN_USDC, USDC, NOW - 30, 900).unwrap(),
        ];
        let due = quotes[1].amount_due_base_units;
        let mut confirmed = Vec::new();
        for amount in (due - 500)..=(due + 500) {
            let settlement =
                settle_transaction(&sig(1), MERCHANT, USDC, &paid(amount), &quotes, NOW)
                    .unwrap()
                    .unwrap();
            if settlement.is_confirmed() {
                confirmed.push(amount);
            }
        }
        assert_eq!(confirmed, vec![due], "only the exact amount may confirm");
    }

    #[test]
    fn a_meaningfully_short_payment_reports_the_shortfall() {
        let quote = open_quote();
        // Nine dollars against a ten dollar quote, tag intact.
        let short = 9_000_347;
        let settlement = settle_transaction(
            &sig(1),
            MERCHANT,
            USDC,
            &paid(short),
            std::slice::from_ref(&quote),
            NOW,
        )
        .unwrap()
        .unwrap();
        match settlement {
            Settlement::Exception(e) => assert_eq!(
                e.reason,
                ExceptionReason::Underpaid {
                    expected: 10_000_347,
                    received: short,
                    shortfall: 1_000_000,
                }
            ),
            other => panic!("expected an exception, got {other:?}"),
        }
    }

    #[test]
    fn overpayment_is_flagged_rather_than_pocketed() {
        let quote = open_quote();
        let over = quote.amount_due_base_units + 500_000;
        let settlement = settle_transaction(
            &sig(1),
            MERCHANT,
            USDC,
            &paid(over),
            std::slice::from_ref(&quote),
            NOW,
        )
        .unwrap()
        .unwrap();
        assert!(!settlement.is_confirmed());
        match settlement {
            Settlement::Exception(e) => assert_eq!(
                e.reason,
                ExceptionReason::Overpaid {
                    expected: quote.amount_due_base_units,
                    received: over,
                    excess: 500_000,
                }
            ),
            other => panic!("expected an exception, got {other:?}"),
        }
    }

    #[test]
    fn an_untagged_payment_is_an_exception_not_an_error() {
        // Someone sent a round ten dollars to the shop address.
        let settlement = settle_transaction(
            &sig(1),
            MERCHANT,
            USDC,
            &paid(TEN_USDC),
            &[open_quote()],
            NOW,
        )
        .expect("an untagged transfer is not an error")
        .expect("money still arrived");
        match settlement {
            Settlement::Exception(e) => {
                assert_eq!(e.reason, ExceptionReason::Untagged);
                assert_eq!(e.amount_base_units, TEN_USDC);
                assert_eq!(e.signature, sig(1));
            }
            other => panic!("expected an untagged exception, got {other:?}"),
        }
    }

    #[test]
    fn a_tag_with_no_open_quote_is_its_own_exception() {
        // Terminal 9, order 12, against a book holding only 3/47.
        let settlement = settle_transaction(
            &sig(1),
            MERCHANT,
            USDC,
            &paid(10_000_912),
            &[open_quote()],
            NOW,
        )
        .unwrap()
        .unwrap();
        match settlement {
            Settlement::Exception(e) => assert_eq!(
                e.reason,
                ExceptionReason::NoMatchingQuote {
                    sales_point: 9,
                    order_counter: 12,
                }
            ),
            other => panic!("expected no matching quote, got {other:?}"),
        }
    }

    #[test]
    fn a_failed_transaction_is_never_a_payment() {
        let quote = open_quote();
        let body = paid(quote.amount_due_base_units).replace(
            r#""err":null"#,
            r#""err":{"InstructionError":[0,{"Custom":1}]}"#,
        );
        // The fixture must actually carry the failure, otherwise this
        // test proves nothing.
        assert!(body.contains("InstructionError"));
        assert_eq!(
            settle_transaction(&sig(1), MERCHANT, USDC, &body, &[quote], NOW).unwrap(),
            None,
            "a failed transaction moved no money"
        );
    }

    #[test]
    fn a_transfer_in_another_mint_is_ignored() {
        // The right amount, the right tag, the wrong token. Someone can
        // send a worthless mint in the exact shape of a payment.
        let quote = open_quote();
        let body = transfer_body(USDT, 0, quote.amount_due_base_units);
        assert_eq!(
            settle_transaction(&sig(1), MERCHANT, USDC, &body, &[quote], NOW).unwrap(),
            None
        );
    }

    #[test]
    fn a_payment_in_the_wrong_mint_reaching_the_matcher_is_flagged() {
        // Guards the matcher directly, in case a payment is ever built
        // from a parse against a different mint.
        let payment =
            parse_settlement_payment(&sig(1), MERCHANT, USDT, &transfer_body(USDT, 0, 10_000_347))
                .unwrap()
                .unwrap();
        match match_payment(&payment, &[open_quote()], USDC, NOW) {
            Settlement::Exception(e) => assert_eq!(
                e.reason,
                ExceptionReason::WrongMint {
                    expected: USDC.to_string(),
                    received: USDT.to_string(),
                }
            ),
            other => panic!("expected a wrong mint exception, got {other:?}"),
        }
    }

    #[test]
    fn a_late_payment_is_flagged_as_expired_not_confirmed() {
        let quote = open_quote();
        let after_expiry = quote.expires_at_unix + 1;
        let settlement = settle_transaction(
            &sig(1),
            MERCHANT,
            USDC,
            &paid(quote.amount_due_base_units),
            std::slice::from_ref(&quote),
            after_expiry,
        )
        .unwrap()
        .unwrap();
        assert!(!settlement.is_confirmed(), "a dead quote never confirms");
        match settlement {
            Settlement::Exception(e) => assert_eq!(
                e.reason,
                ExceptionReason::QuoteExpired {
                    sales_point: 3,
                    order_counter: 47,
                    expires_at_unix: quote.expires_at_unix,
                }
            ),
            other => panic!("expected an expiry exception, got {other:?}"),
        }
    }

    #[test]
    fn expiry_outranks_the_amount_so_the_human_sees_the_real_problem() {
        let quote = open_quote();
        let settlement = settle_transaction(
            &sig(1),
            MERCHANT,
            USDC,
            &paid(quote.amount_due_base_units - 1_000_000),
            std::slice::from_ref(&quote),
            quote.expires_at_unix,
        )
        .unwrap()
        .unwrap();
        match settlement {
            Settlement::Exception(e) => assert!(
                matches!(e.reason, ExceptionReason::QuoteExpired { .. }),
                "expected expiry to dominate, got {:?}",
                e.reason
            ),
            other => panic!("expected an exception, got {other:?}"),
        }
    }

    #[test]
    fn a_quote_still_live_one_second_before_expiry_confirms() {
        let quote = open_quote();
        let settlement = settle_transaction(
            &sig(1),
            MERCHANT,
            USDC,
            &paid(quote.amount_due_base_units),
            std::slice::from_ref(&quote),
            quote.expires_at_unix - 1,
        )
        .unwrap()
        .unwrap();
        assert!(settlement.is_confirmed());
    }

    #[test]
    fn the_right_quote_is_picked_out_of_a_book_of_open_ones() {
        let quotes = vec![
            issue_quote(3, 46, "OIL-1L", 1, 3_500_000, USDC, NOW - 120, 900).unwrap(),
            open_quote(),
            issue_quote(3, 48, "RICE-5KG", 2, TEN_USDC, USDC, NOW - 30, 900).unwrap(),
        ];
        // Pay the middle one.
        let settlement =
            settle_transaction(&sig(1), MERCHANT, USDC, &paid(10_000_347), &quotes, NOW)
                .unwrap()
                .unwrap();
        match settlement {
            Settlement::Confirmed(sale) => {
                assert_eq!(sale.order_counter, 47);
                assert_eq!(sale.sku, "RICE-5KG");
                assert_eq!(sale.quantity, 1);
            }
            other => panic!("expected a confirmed sale, got {other:?}"),
        }
        // And the first one, at a different price under a different tag.
        let settlement =
            settle_transaction(&sig(2), MERCHANT, USDC, &paid(3_500_346), &quotes, NOW)
                .unwrap()
                .unwrap();
        match settlement {
            Settlement::Confirmed(sale) => assert_eq!(sale.sku, "OIL-1L"),
            other => panic!("expected a confirmed sale, got {other:?}"),
        }
    }

    #[test]
    fn a_transfer_that_gives_the_merchant_nothing_is_not_a_payment() {
        // The merchant's balance is unchanged, so nothing arrived even
        // though the transaction touched their account.
        let body = transfer_body(USDC, 10_000_000, 10_000_000);
        assert_eq!(
            parse_settlement_payment(&sig(1), MERCHANT, USDC, &body).unwrap(),
            None
        );
    }

    #[test]
    fn an_outgoing_transfer_is_not_a_payment() {
        // Merchant balance falls. A negative delta must never be read as
        // a receipt, whatever its magnitude.
        let body = transfer_body(USDC, 10_000_347, 10_000_347).replace(
            r#""amount":"10000347","decimals":6,"uiAmount":10.0"#,
            r#""amount":"347","decimals":6,"uiAmount":0.0"#,
        );
        let parsed = parse_settlement_payment(&sig(1), MERCHANT, USDC, &body).unwrap();
        assert_eq!(parsed, None);
    }

    #[test]
    fn money_arriving_through_a_program_is_still_counted() {
        // No SPL transfer instruction anywhere, only balance deltas, as
        // happens when a payment is routed through a swap. Reading the
        // instruction list would miss this entirely.
        let quote = open_quote();
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "slot": 301_455_999u64,
                "blockTime": NOW,
                "meta": {
                    "err": null,
                    "fee": 5000,
                    "preTokenBalances": [
                        {"accountIndex": 5, "mint": USDC, "owner": "RouterPoolOwner1111111111111111111111111111",
                         "programId": TOKEN_PROGRAM_ID,
                         "uiTokenAmount": {"amount": "900000000", "decimals": 6,
                                           "uiAmount": 900.0, "uiAmountString": "900"}}
                    ],
                    "postTokenBalances": [
                        {"accountIndex": 5, "mint": USDC, "owner": "RouterPoolOwner1111111111111111111111111111",
                         "programId": TOKEN_PROGRAM_ID,
                         "uiTokenAmount": {"amount": "889999653", "decimals": 6,
                                           "uiAmount": 889.999653, "uiAmountString": "889.999653"}},
                        {"accountIndex": 6, "mint": USDC, "owner": MERCHANT,
                         "programId": TOKEN_PROGRAM_ID,
                         "uiTokenAmount": {"amount": "10000347", "decimals": 6,
                                           "uiAmount": 10.000347, "uiAmountString": "10.000347"}}
                    ],
                    "logMessages": ["Program JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4 invoke [1]"]
                },
                "transaction": {"message": {"accountKeys": [
                    {"pubkey": CUSTOMER, "signer": true, "writable": true}
                ]}}
            }
        })
        .to_string();

        // The merchant's account did not exist before, so it has no pre
        // entry and the whole post balance is the delta.
        let settlement = settle_transaction(&sig(3), MERCHANT, USDC, &body, &[quote], NOW)
            .unwrap()
            .unwrap();
        assert!(settlement.is_confirmed(), "got {settlement:?}");
    }

    #[test]
    fn an_internal_move_between_merchant_accounts_nets_to_zero() {
        // Two accounts, both the merchant's, one gaining what the other
        // loses. Taking the first positive entry would invent a sale.
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
                        {"accountIndex": 1, "mint": USDC, "owner": MERCHANT,
                         "uiTokenAmount": {"amount": "10000347", "decimals": 6}},
                        {"accountIndex": 2, "mint": USDC, "owner": MERCHANT,
                         "uiTokenAmount": {"amount": "0", "decimals": 6}}
                    ],
                    "postTokenBalances": [
                        {"accountIndex": 1, "mint": USDC, "owner": MERCHANT,
                         "uiTokenAmount": {"amount": "0", "decimals": 6}},
                        {"accountIndex": 2, "mint": USDC, "owner": MERCHANT,
                         "uiTokenAmount": {"amount": "10000347", "decimals": 6}}
                    ]
                },
                "transaction": {"message": {"accountKeys": [{"pubkey": MERCHANT}]}}
            }
        })
        .to_string();
        assert_eq!(
            parse_settlement_payment(&sig(1), MERCHANT, USDC, &body).unwrap(),
            None
        );
    }

    #[test]
    fn a_transaction_the_node_does_not_have_is_not_an_error() {
        let body = r#"{"jsonrpc":"2.0","result":null,"id":1}"#;
        assert_eq!(
            settle_transaction(&sig(1), MERCHANT, USDC, body, &[open_quote()], NOW).unwrap(),
            None
        );
    }

    #[test]
    fn rpc_errors_surface_rather_than_reading_as_no_payment() {
        // A rate limited node must not look like a quiet shop.
        let body = r#"{"jsonrpc":"2.0","error":{"code":-32005,"message":"Node is behind"},"id":1}"#;
        let err = settle_transaction(&sig(1), MERCHANT, USDC, body, &[], NOW).unwrap_err();
        assert!(err.contains("-32005"), "{err}");
        assert!(parse_signatures("<html>rate limited</html>").is_err());
    }

    #[test]
    fn a_malformed_token_amount_is_refused_rather_than_guessed() {
        let body = paid(10_000_347).replace(r#""amount":"10000347""#, r#""amount":"lots""#);
        let err = parse_settlement_payment(&sig(1), MERCHANT, USDC, &body).unwrap_err();
        assert!(err.contains("not an integer"), "{err}");
    }

    #[test]
    fn bad_addresses_and_signatures_are_refused_at_the_door() {
        assert!(parse_settlement_payment(&sig(1), "pay-me", USDC, &paid(1)).is_err());
        assert!(parse_settlement_payment(&sig(1), MERCHANT, "not-a-mint", &paid(1)).is_err());
        assert!(parse_settlement_payment("nope", MERCHANT, USDC, &paid(1)).is_err());
    }

    #[test]
    fn a_claim_of_payment_has_no_way_into_this_module() {
        // The point of the design, stated as a test: with an open quote
        // and no chain data showing money at the merchant, nothing
        // confirms. There is no argument a caller relaying customer text
        // could set to change this outcome.
        let quote = open_quote();
        // A transaction where the customer pays somebody else entirely.
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
                         "uiTokenAmount": {"amount": "10000347", "decimals": 6}},
                        {"accountIndex": 2, "mint": USDC, "owner": "SomeoneElse11111111111111111111111111111111",
                         "uiTokenAmount": {"amount": "0", "decimals": 6}}
                    ],
                    "postTokenBalances": [
                        {"accountIndex": 1, "mint": USDC, "owner": CUSTOMER,
                         "uiTokenAmount": {"amount": "0", "decimals": 6}},
                        {"accountIndex": 2, "mint": USDC, "owner": "SomeoneElse11111111111111111111111111111111",
                         "uiTokenAmount": {"amount": "10000347", "decimals": 6}}
                    ]
                },
                "transaction": {"message": {"accountKeys": [{"pubkey": CUSTOMER}]}}
            }
        })
        .to_string();
        assert_eq!(
            settle_transaction(&sig(1), MERCHANT, USDC, &body, &[quote], NOW).unwrap(),
            None,
            "the exact amount, paid to the wrong address, is not a sale"
        );
    }
}
