//! The daily ledger: confirmed transactions turned into accounting events.
//!
//! At daily close the shop hashes its ledger and anchors that hash on
//! chain. An auditor who trusts nothing we say can re-derive the same
//! ledger from the same chain data and check that it hashes to the same
//! value. That check is only worth something if normalization is a pure
//! function of chain state, so determinism here is not a nicety, it is
//! the whole audit property.
//!
//! It is also the anti-tampering property, and that is the reason this
//! module is written the way it is. A shop agent reads customer messages
//! all day, which means it reads text an attacker wrote. If any number
//! in the ledger were model authored, a persuasive message would be a
//! path to a falsified book. No number here is model authored. Every
//! amount is a difference between two integers the RPC reported, every
//! address is copied out of the response, and the sort order is fixed by
//! the data rather than by whatever order the node happened to serialize
//! its arrays in. There is no argument to this module that a customer
//! can influence, so there is no surface on which to lie.
//!
//! Three rules follow from that and are enforced throughout.
//!
//! Work from balance deltas, never from the instruction list. Decoding
//! instructions means knowing every program that might move value, and
//! the day a customer pays through a program we have never heard of the
//! books would silently under-report. `meta.preBalances` against
//! `meta.postBalances`, and `meta.preTokenBalances` against
//! `meta.postTokenBalances`, are ground truth: they capture the net
//! effect of the transaction whatever routed it.
//!
//! Attribute to the owner, not the token account. A merchant's
//! associated token account is not their wallet, and a ledger row naming
//! an ATA tells a human nothing. Token balance entries carry an `owner`
//! field, and that is what a row is keyed on.
//!
//! Nothing that moved value is dropped. When a movement cannot be
//! attributed, it is emitted as `EventKind::Unclassified` rather than
//! skipped, because a book that quietly omits value it did not
//! understand is worse than a book with an exception on it. An exception
//! gets looked at; a silent omission does not.
//!
//! Determinism is achieved by construction, not by hoping. There is no
//! `HashMap` in this module, because `HashMap` iteration order is
//! unspecified and would leak into output; accumulation uses `BTreeMap`,
//! which iterates in key order. There is no floating point, so no amount
//! depends on rounding mode; token amounts are read from the integer
//! `amount` string and the `uiAmount` float in the same response is
//! deliberately never touched. There is no clock: the only time in an
//! event is the block time the chain reported. And the final output is
//! put through a total order over every field, so two runs on the same
//! bytes cannot differ.
//!
//! One distinction is worth drawing, because it separates a real
//! determinism bug from a test that asks for the impossible. The order
//! of entries inside `preTokenBalances` and `postTokenBalances` is free:
//! each entry names the account it describes, so a node may emit them in
//! any order and the result must not move. The order of `accountKeys` is
//! not free: position zero is the fee payer by protocol, and the token
//! balance entries reference the other positions by index, so permuting
//! that list describes a different transaction rather than the same one
//! written differently. This module is indifferent to the first and
//! reads the second exactly as the protocol defines it, and both
//! properties are pinned by tests.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::address::validate_pubkey;
use crate::rpc::parse_result_value;

/// The mint identifier used for native SOL.
///
/// Deliberately not the wrapped SOL mint. Native lamports and wrapped
/// SOL are different assets in a book: one is the account balance, the
/// other is an SPL token that happens to track it, and a transaction can
/// move both in opposite directions. Reusing the wSOL mint would net
/// those two into one line and lose the distinction. `"SOL"` cannot
/// collide with a real mint, because a mint is 32 bytes of base58 and
/// this is three characters.
pub const NATIVE_SOL_MINT: &str = "SOL";

/// What an event says happened to the merchant's money.
///
/// The declaration order of these variants is part of the ledger sort
/// key, so reordering them changes the hash of every day that contains
/// more than one kind of event for a mint. Add new variants at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventKind {
    /// Value arrived at the merchant.
    Revenue,
    /// Value left the merchant.
    ///
    /// A refund to a customer and a payout to a supplier are the same
    /// shape in balance deltas, and this module has no order book with
    /// which to tell them apart. Rather than guess, it records that
    /// value left and leaves the business classification to a later step
    /// that can match the amount against an issued quote. Guessing here
    /// would put a number in the book that no auditor could re-derive.
    Payout,
    /// Network fee the merchant paid.
    FeePaid,
    /// Value moved but could not be attributed to an owner. Surfaced so
    /// a human sees it, never dropped.
    Unclassified,
}

impl EventKind {
    /// Stable text form, used in the canonical line that gets hashed.
    /// These strings are part of the anchored hash and must not change.
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::Revenue => "revenue",
            EventKind::Payout => "payout",
            EventKind::FeePaid => "fee_paid",
            EventKind::Unclassified => "unclassified",
        }
    }
}

/// One normalized accounting event.
///
/// Amounts are signed from the merchant's point of view and are always
/// in the mint's smallest unit: positive means value arrived, negative
/// means value left. `i128` rather than `i64` because a delta on a mint
/// with large supply and few decimals can exceed `u64` when subtracted,
/// and because there is no reason to court an overflow in a book.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEvent {
    /// The transaction this event was derived from.
    pub signature: String,
    /// Block time as the chain reported it. `None` when the node did not
    /// return one, which happens outside its retention of block times.
    /// It is left absent rather than filled from a clock, because a
    /// locally invented timestamp would not survive re-derivation.
    pub block_time_unix: Option<i64>,
    pub kind: EventKind,
    /// Mint of the asset that moved, or `NATIVE_SOL_MINT` for lamports.
    pub mint: String,
    /// Signed amount in the mint's smallest unit.
    pub amount_base_units: i128,
    /// The other side, when it is unambiguous. `None` when the
    /// transaction had several accounts on the opposite side of the
    /// movement, because naming one of them would be a guess.
    pub counterparty: Option<String>,
}

impl LedgerEvent {
    /// The total order events are sorted by.
    ///
    /// Every field participates, so the order is total rather than
    /// merely deterministic under the sort implementation: two events
    /// that compare equal here are equal, so no tie can be broken by
    /// input order.
    fn sort_key(&self) -> (&str, &str, EventKind, i128, Option<&str>) {
        (
            &self.signature,
            &self.mint,
            self.kind,
            self.amount_base_units,
            self.counterparty.as_deref(),
        )
    }

    /// The event as one canonical line of text.
    ///
    /// This is the form that gets hashed at daily close, so it is fixed:
    /// tab separated, fields in this order, absent values written as a
    /// single hyphen, integers in base ten with no separators. Anything
    /// that changes this changes every historical anchor.
    pub fn canonical_line(&self) -> String {
        let time = match self.block_time_unix {
            Some(t) => t.to_string(),
            None => "-".to_string(),
        };
        let counterparty = self.counterparty.as_deref().unwrap_or("-");
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            self.signature,
            time,
            self.kind.as_str(),
            self.mint,
            self.amount_base_units,
            counterparty
        )
    }
}

/// Put events into the canonical ledger order, in place.
///
/// Callers that assemble events from several sources must run this last.
/// It is idempotent and depends on nothing but the events themselves.
pub fn sort_events(events: &mut [LedgerEvent]) {
    events.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
}

/// Normalize one `getTransaction` (jsonParsed) response into events for
/// `merchant_owner`.
///
/// The merchant address is the wallet, not a token account: SPL movement
/// is matched on the `owner` field of the token balance entries, so an
/// ATA the shop has never enumerated still books correctly.
///
/// A response whose `result` is null is an error rather than an empty
/// day. The signature came from the chain in the first place, so a node
/// that cannot return it is a node outside its retention window, and a
/// ledger silently missing a transaction would still hash cleanly and
/// still be wrong.
pub fn normalize_transaction(
    merchant_owner: &str,
    signature: &str,
    body: &str,
) -> Result<Vec<LedgerEvent>, String> {
    let merchant = validate_pubkey(merchant_owner)
        .map_err(|e| format!("merchant address is not a valid Solana address: {e}"))?;

    let result = parse_result_value(body)?;
    if result.is_null() {
        return Err(format!(
            "transaction {} is not available from this node, so the ledger cannot be \
             derived from it; a day is either complete or it is not a day",
            signature.trim()
        ));
    }
    let meta = result
        .get("meta")
        .ok_or_else(|| "getTransaction result has no meta, so nothing can be booked".to_string())?;

    // Prefer the signature the response itself carries. Re-derivation
    // should depend on chain data wherever chain data is available, and
    // the caller's argument is only a fallback for a node that omits it.
    let signature = result
        .pointer("/transaction/signatures/0")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| signature.trim().to_string());
    let block_time_unix = result.get("blockTime").and_then(Value::as_i64);

    let account_keys = account_keys(&result);
    let fee_lamports = meta.get("fee").and_then(Value::as_u64).unwrap_or(0) as i128;
    // The fee payer is always the first account key. Only the fee payer
    // is charged, so a merchant who did not sign pays nothing here.
    let merchant_paid_fee = account_keys.first().map(String::as_str) == Some(merchant.as_str());

    let mut events = Vec::new();
    if merchant_paid_fee && fee_lamports != 0 {
        events.push(LedgerEvent {
            signature: signature.clone(),
            block_time_unix,
            kind: EventKind::FeePaid,
            mint: NATIVE_SOL_MINT.to_string(),
            amount_base_units: -fee_lamports,
            counterparty: None,
        });
    }

    // A failed transaction reverted every balance change it attempted,
    // but the fee was still taken. Booking anything else from its meta
    // would invent a sale that never happened, so the fee is the entire
    // ledger effect of a failure.
    let failed = !matches!(meta.get("err"), None | Some(Value::Null));
    if failed {
        sort_events(&mut events);
        return Ok(events);
    }

    events.extend(sol_events(
        meta,
        &account_keys,
        &merchant,
        fee_lamports,
        &signature,
        block_time_unix,
    ));
    events.extend(token_events(meta, &merchant, &signature, block_time_unix)?);

    sort_events(&mut events);
    Ok(events)
}

/// Normalize a batch of transactions into one ordered ledger.
///
/// Each element is a signature and the raw `getTransaction` body for it.
/// The result is sorted across the whole batch, so the order in which
/// the caller fetched transactions cannot reach the output. That matters
/// because the caller fetches over a network, and network order is not
/// something an auditor can reproduce.
pub fn normalize_transactions(
    merchant_owner: &str,
    responses: &[(String, String)],
) -> Result<Vec<LedgerEvent>, String> {
    let mut events = Vec::new();
    for (signature, body) in responses {
        events.extend(normalize_transaction(merchant_owner, signature, body)?);
    }
    sort_events(&mut events);
    Ok(events)
}

/// jsonParsed account keys are objects carrying a pubkey plus flags,
/// though some nodes still return bare strings. Both are accepted.
fn account_keys(result: &Value) -> Vec<String> {
    result
        .pointer("/transaction/message/accountKeys")
        .and_then(Value::as_array)
        .map(|keys| {
            keys.iter()
                .map(|k| {
                    k.get("pubkey")
                        .and_then(Value::as_str)
                        .or_else(|| k.as_str())
                        .unwrap_or_default()
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Native SOL movement, with the fee netted out of the fee payer.
///
/// This is where the double counting question is settled. The fee is
/// already inside the fee payer's SOL delta: `postBalances[0]` has it
/// subtracted. So the fee is added back to that account's delta before
/// classification, and accounted for once as its own `FeePaid` event.
/// The consequence is worth stating precisely, because a reconciliation
/// depends on it: for the fee payer, the `FeePaid` amount plus the SOL
/// event amount equals the raw delta the RPC reported, exactly. Nothing
/// is counted twice and nothing is lost.
///
/// The alternative, leaving the fee inside the SOL event, was rejected
/// because it makes a fee look like a tiny disposal of SOL and a shop
/// that paid ten thousand fees would show ten thousand phantom payouts.
/// A fee is a cost of doing business and belongs on its own line.
///
/// A residual of zero emits nothing: a transaction where the merchant
/// only paid the fee produces one `FeePaid` event and no SOL line,
/// rather than a line saying zero moved.
fn sol_events(
    meta: &Value,
    account_keys: &[String],
    merchant: &str,
    fee_lamports: i128,
    signature: &str,
    block_time_unix: Option<i64>,
) -> Vec<LedgerEvent> {
    let pre = meta
        .get("preBalances")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let post = meta
        .get("postBalances")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut deltas: Vec<(&str, i128)> = Vec::with_capacity(account_keys.len());
    for (i, account) in account_keys.iter().enumerate() {
        let before = pre.get(i).and_then(Value::as_u64).unwrap_or(0) as i128;
        let after = post.get(i).and_then(Value::as_u64).unwrap_or(0) as i128;
        let mut delta = after - before;
        // Index zero is the fee payer, and only the fee payer was
        // charged. Adding the fee back leaves the movement the
        // transaction actually performed.
        if i == 0 {
            delta += fee_lamports;
        }
        deltas.push((account.as_str(), delta));
    }

    let merchant_delta: i128 = deltas
        .iter()
        .filter(|(account, _)| *account == merchant)
        .map(|(_, delta)| *delta)
        .sum();
    if merchant_delta == 0 {
        return Vec::new();
    }

    let counterparty = sole_opposite(
        deltas
            .iter()
            .filter(|(account, _)| *account != merchant)
            .map(|(account, delta)| (*account, *delta)),
        merchant_delta,
    );

    vec![LedgerEvent {
        signature: signature.to_string(),
        block_time_unix,
        kind: kind_for(merchant_delta),
        mint: NATIVE_SOL_MINT.to_string(),
        amount_base_units: merchant_delta,
        counterparty,
    }]
}

/// SPL movement, netted per owner and mint.
///
/// Netting by owner and mint rather than by token account is what makes
/// the result independent of how many accounts a wallet holds for one
/// mint, and it handles an ATA created inside the transaction, which
/// appears only in `postTokenBalances`, without a special case: the
/// missing side simply contributes nothing.
fn token_events(
    meta: &Value,
    merchant: &str,
    signature: &str,
    block_time_unix: Option<i64>,
) -> Result<Vec<LedgerEvent>, String> {
    let pre = token_balances(meta, "preTokenBalances");
    let post = token_balances(meta, "postTokenBalances");

    // Older nodes omit `owner` on one side of the pair. Resolving the
    // owner by account index across both sides keeps such an entry
    // attributed instead of splitting one movement into a phantom
    // revenue and a matching exception.
    let mut owner_by_index: BTreeMap<u64, String> = BTreeMap::new();
    for entry in post.iter().chain(pre.iter()) {
        if let (Some(index), Some(owner)) = (
            entry.get("accountIndex").and_then(Value::as_u64),
            entry.get("owner").and_then(Value::as_str),
        ) {
            owner_by_index.entry(index).or_insert_with(|| owner.to_string());
        }
    }

    // BTreeMap, not HashMap: iteration order here reaches the output,
    // and HashMap does not promise one.
    let mut deltas: BTreeMap<(Option<String>, String), i128> = BTreeMap::new();
    for (entries, sign) in [(&post, 1i128), (&pre, -1i128)] {
        for entry in entries {
            let mint = entry
                .get("mint")
                .and_then(Value::as_str)
                .ok_or_else(|| "token balance entry has no mint".to_string())?
                .to_string();
            let owner = entry
                .get("owner")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    entry
                        .get("accountIndex")
                        .and_then(Value::as_u64)
                        .and_then(|i| owner_by_index.get(&i).cloned())
                });
            let amount = token_amount(entry)?;
            *deltas.entry((owner, mint)).or_insert(0) += sign * amount;
        }
    }

    let mut events = Vec::new();
    for ((owner, mint), delta) in &deltas {
        if *delta == 0 {
            continue;
        }
        match owner.as_deref() {
            Some(owner) if owner == merchant => {
                let counterparty = sole_opposite(
                    deltas.iter().filter_map(|((other, other_mint), other_delta)| {
                        match other.as_deref() {
                            Some(other) if other != merchant && other_mint == mint => {
                                Some((other, *other_delta))
                            }
                            _ => None,
                        }
                    }),
                    *delta,
                );
                events.push(LedgerEvent {
                    signature: signature.to_string(),
                    block_time_unix,
                    kind: kind_for(*delta),
                    mint: mint.clone(),
                    amount_base_units: *delta,
                    counterparty,
                });
            }
            // Somebody else's tokens moved. Their side of the merchant's
            // sale is not the merchant's ledger, so it is not booked.
            Some(_) => {}
            // No owner on either side of the pair. Value moved and this
            // module cannot say whose it was, which is exactly what
            // Unclassified is for: it goes in front of a human rather
            // than into a gap in the book.
            None => events.push(LedgerEvent {
                signature: signature.to_string(),
                block_time_unix,
                kind: EventKind::Unclassified,
                mint: mint.clone(),
                amount_base_units: *delta,
                counterparty: None,
            }),
        }
    }
    Ok(events)
}

fn token_balances(meta: &Value, key: &str) -> Vec<Value> {
    meta.get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Read a token amount as an integer.
///
/// The `amount` field is a decimal string of base units and is the only
/// field read. The sibling `uiAmount` is a JSON float, and a float is
/// not a thing to keep money in: it cannot represent every base unit of
/// a nine decimal mint, so a book built on it would drift by amounts too
/// small to notice and too real to ignore.
fn token_amount(entry: &Value) -> Result<i128, String> {
    let raw = entry
        .pointer("/uiTokenAmount/amount")
        .and_then(Value::as_str)
        .ok_or_else(|| "token balance entry has no uiTokenAmount.amount string".to_string())?;
    raw.parse::<i128>()
        .map_err(|_| format!("token amount {raw:?} is not an integer"))
}

/// Revenue when value arrived, payout when it left. Never called with
/// zero: a zero movement produces no event at all.
fn kind_for(delta: i128) -> EventKind {
    if delta > 0 {
        EventKind::Revenue
    } else {
        EventKind::Payout
    }
}

/// The single account on the other side of a movement, if there is
/// exactly one.
///
/// Ambiguity is reported as `None` rather than resolved by picking the
/// largest or the first. Both of those would be a guess, and a guessed
/// counterparty in an audited book is worse than an absent one: absent
/// is honest and re-derivable, a guess is neither.
fn sole_opposite<'a, I>(candidates: I, merchant_delta: i128) -> Option<String>
where
    I: Iterator<Item = (&'a str, i128)>,
{
    let mut found: Option<&str> = None;
    for (account, delta) in candidates {
        let opposite = (merchant_delta > 0 && delta < 0) || (merchant_delta < 0 && delta > 0);
        if !opposite {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(account);
    }
    found.map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MERCHANT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const CUSTOMER: &str = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";
    const SUPPLIER: &str = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const USDT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";
    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
    const MERCHANT_ATA: &str = "EbsiuGYVXSbnvzGdKq3T1kFbHhwKHkedeTaZzLYnUKPn";
    const MERCHANT_USDT_ATA: &str = "J2s2MRZgLzMTBjA1UfWrxRP3ZFrCwGCcqNbFwvS5C8jT";
    const CUSTOMER_ATA: &str = "GfVPzUxMDvhFJ1Xs6C9i47XQRSapTd8LHw5grGuTquyQ";
    const SUPPLIER_ATA: &str = "HXtBm8XZbxaTt41uqaKhwUAa6Z1aPyvJdsZVENiWsetf";

    const FEE: i128 = 5_000;

    fn sig() -> String {
        bs58::encode([7u8; 64]).into_string()
    }

    fn other_sig() -> String {
        bs58::encode([8u8; 64]).into_string()
    }

    /// Build a jsonParsed `getTransaction` body around a meta object.
    fn body_with(signature: &str, keys: &[&str], meta: Value) -> String {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "slot": 250_000_000,
                "blockTime": 1_750_000_000,
                "meta": meta,
                "transaction": {
                    "signatures": [signature],
                    "message": {
                        "accountKeys": keys.iter().map(|k| json!({
                            "pubkey": k,
                            "signer": false,
                            "writable": true,
                            "source": "transaction"
                        })).collect::<Vec<_>>()
                    }
                }
            }
        })
        .to_string()
    }

    /// A token balance entry as a node returns it, floats and all.
    fn token_balance(index: u64, owner: &str, mint: &str, amount: u64, decimals: u8) -> Value {
        // uiAmount is the float the RPC really sends. It is included so
        // the fixtures are honest, and never read.
        let ui = amount as f64 / 10f64.powi(decimals as i32);
        json!({
            "accountIndex": index,
            "mint": mint,
            "owner": owner,
            "programId": TOKEN_PROGRAM,
            "uiTokenAmount": {
                "amount": amount.to_string(),
                "decimals": decimals,
                "uiAmount": ui,
                "uiAmountString": ui.to_string()
            }
        })
    }

    /// Customer sends one SOL to the merchant and pays the fee.
    fn sol_in_body() -> String {
        body_with(
            &sig(),
            &[CUSTOMER, MERCHANT, SYSTEM_PROGRAM],
            json!({
                "err": null,
                "fee": FEE,
                "preBalances": [2_000_000_000u64, 10_000_000u64, 1u64],
                "postBalances": [999_995_000u64, 1_010_000_000u64, 1u64],
                "preTokenBalances": [],
                "postTokenBalances": []
            }),
        )
    }

    /// Merchant sends half a SOL to a supplier and pays the fee.
    fn sol_out_body() -> String {
        body_with(
            &sig(),
            &[MERCHANT, SUPPLIER, SYSTEM_PROGRAM],
            json!({
                "err": null,
                "fee": FEE,
                "preBalances": [1_000_000_000u64, 0u64, 1u64],
                "postBalances": [499_995_000u64, 500_000_000u64, 1u64],
                "preTokenBalances": [],
                "postTokenBalances": []
            }),
        )
    }

    /// Customer pays 10.000347 USDC to the merchant and pays the fee.
    fn spl_in_body() -> String {
        body_with(
            &sig(),
            &[CUSTOMER, CUSTOMER_ATA, MERCHANT_ATA, TOKEN_PROGRAM],
            json!({
                "err": null,
                "fee": FEE,
                "preBalances": [2_000_000_000u64, 2_039_280u64, 2_039_280u64, 1u64],
                "postBalances": [1_999_995_000u64, 2_039_280u64, 2_039_280u64, 1u64],
                "preTokenBalances": [
                    token_balance(1, CUSTOMER, USDC, 50_000_000, 6),
                    token_balance(2, MERCHANT, USDC, 0, 6)
                ],
                "postTokenBalances": [
                    token_balance(1, CUSTOMER, USDC, 39_999_653, 6),
                    token_balance(2, MERCHANT, USDC, 10_000_347, 6)
                ]
            }),
        )
    }

    /// Merchant refunds 4 USDC to a customer and pays the fee.
    fn spl_out_body() -> String {
        body_with(
            &sig(),
            &[MERCHANT, MERCHANT_ATA, CUSTOMER_ATA, TOKEN_PROGRAM],
            json!({
                "err": null,
                "fee": FEE,
                "preBalances": [1_000_000_000u64, 2_039_280u64, 2_039_280u64, 1u64],
                "postBalances": [999_995_000u64, 2_039_280u64, 2_039_280u64, 1u64],
                "preTokenBalances": [
                    token_balance(1, MERCHANT, USDC, 10_000_347, 6),
                    token_balance(2, CUSTOMER, USDC, 0, 6)
                ],
                "postTokenBalances": [
                    token_balance(1, MERCHANT, USDC, 6_000_347, 6),
                    token_balance(2, CUSTOMER, USDC, 4_000_000, 6)
                ]
            }),
        )
    }

    /// One transaction that takes USDC in and pays USDT out, a swap
    /// routed through a program this module knows nothing about.
    fn multi_mint_body() -> String {
        body_with(
            &sig(),
            &[
                MERCHANT,
                MERCHANT_ATA,
                CUSTOMER_ATA,
                MERCHANT_USDT_ATA,
                SUPPLIER_ATA,
                TOKEN_PROGRAM,
            ],
            json!({
                "err": null,
                "fee": FEE,
                "preBalances": [
                    1_000_000_000u64, 2_039_280u64, 2_039_280u64, 2_039_280u64, 2_039_280u64, 1u64
                ],
                "postBalances": [
                    999_995_000u64, 2_039_280u64, 2_039_280u64, 2_039_280u64, 2_039_280u64, 1u64
                ],
                "preTokenBalances": [
                    token_balance(1, MERCHANT, USDC, 0, 6),
                    token_balance(2, CUSTOMER, USDC, 25_000_000, 6),
                    token_balance(3, MERCHANT, USDT, 8_000_000, 6),
                    token_balance(4, SUPPLIER, USDT, 0, 6)
                ],
                "postTokenBalances": [
                    token_balance(1, MERCHANT, USDC, 25_000_000, 6),
                    token_balance(2, CUSTOMER, USDC, 0, 6),
                    token_balance(3, MERCHANT, USDT, 1_000_000, 6),
                    token_balance(4, SUPPLIER, USDT, 7_000_000, 6)
                ]
            }),
        )
    }

    fn normalize(body: &str) -> Vec<LedgerEvent> {
        normalize_transaction(MERCHANT, &sig(), body).expect("normalizes")
    }

    fn kinds(events: &[LedgerEvent]) -> Vec<EventKind> {
        events.iter().map(|e| e.kind).collect()
    }

    fn lines(events: &[LedgerEvent]) -> Vec<String> {
        events.iter().map(LedgerEvent::canonical_line).collect()
    }

    #[test]
    fn every_fixture_address_is_a_real_pubkey() {
        // The fixtures are meant to be what a node returns, so an
        // address in one that could never exist on chain would make a
        // passing test prove nothing.
        for address in [
            MERCHANT,
            CUSTOMER,
            SUPPLIER,
            USDC,
            USDT,
            TOKEN_PROGRAM,
            SYSTEM_PROGRAM,
            MERCHANT_ATA,
            MERCHANT_USDT_ATA,
            CUSTOMER_ATA,
            SUPPLIER_ATA,
        ] {
            assert!(validate_pubkey(address).is_ok(), "{address} is not a pubkey");
        }
    }

    #[test]
    fn plain_sol_transfer_in_is_revenue_attributed_to_the_sender() {
        let events = normalize(&sol_in_body());
        assert_eq!(kinds(&events), vec![EventKind::Revenue]);
        let event = &events[0];
        assert_eq!(event.mint, NATIVE_SOL_MINT);
        assert_eq!(event.amount_base_units, 1_000_000_000);
        assert_eq!(event.counterparty.as_deref(), Some(CUSTOMER));
        assert_eq!(event.block_time_unix, Some(1_750_000_000));
        assert_eq!(event.signature, sig());
        // The merchant did not sign, so the merchant paid no fee.
        assert!(!kinds(&events).contains(&EventKind::FeePaid));
    }

    #[test]
    fn sol_transfer_out_books_the_fee_separately_without_double_counting() {
        let events = normalize(&sol_out_body());
        assert_eq!(kinds(&events), vec![EventKind::Payout, EventKind::FeePaid]);

        let payout = &events[0];
        let fee = &events[1];
        assert_eq!(payout.amount_base_units, -500_000_000);
        assert_eq!(payout.counterparty.as_deref(), Some(SUPPLIER));
        assert_eq!(fee.amount_base_units, -FEE);
        assert_eq!(fee.mint, NATIVE_SOL_MINT);
        assert_eq!(fee.counterparty, None);

        // The property the whole fee decision rests on: the two SOL
        // lines sum to exactly the raw delta the RPC reported, so the
        // fee is counted once and the payout is clean of it.
        let raw_delta = 499_995_000i128 - 1_000_000_000i128;
        assert_eq!(payout.amount_base_units + fee.amount_base_units, raw_delta);
    }

    #[test]
    fn a_transaction_that_only_costs_a_fee_emits_no_zero_sol_line() {
        let body = body_with(
            &sig(),
            &[MERCHANT, SYSTEM_PROGRAM],
            json!({
                "err": null,
                "fee": FEE,
                "preBalances": [1_000_000_000u64, 1u64],
                "postBalances": [999_995_000u64, 1u64],
                "preTokenBalances": [],
                "postTokenBalances": []
            }),
        );
        let events = normalize(&body);
        assert_eq!(kinds(&events), vec![EventKind::FeePaid]);
        assert_eq!(events[0].amount_base_units, -FEE);
    }

    #[test]
    fn spl_transfer_in_is_attributed_to_the_owner_not_the_token_account() {
        let events = normalize(&spl_in_body());
        assert_eq!(kinds(&events), vec![EventKind::Revenue]);
        let event = &events[0];
        assert_eq!(event.mint, USDC);
        assert_eq!(event.amount_base_units, 10_000_347);
        // The ATAs are in the fixture and must not appear in the book.
        assert_eq!(event.counterparty.as_deref(), Some(CUSTOMER));
        assert!(!lines(&events).iter().any(|l| l.contains(MERCHANT_ATA)));
        assert!(!lines(&events).iter().any(|l| l.contains(CUSTOMER_ATA)));
    }

    #[test]
    fn spl_transfer_out_is_a_payout_plus_the_fee() {
        let events = normalize(&spl_out_body());
        // Sorted by mint: "EPjFW..." precedes "SOL" in byte order.
        assert_eq!(kinds(&events), vec![EventKind::Payout, EventKind::FeePaid]);
        let usdc = events.iter().find(|e| e.mint == USDC).expect("usdc line");
        assert_eq!(usdc.kind, EventKind::Payout);
        assert_eq!(usdc.amount_base_units, -4_000_000);
        assert_eq!(usdc.counterparty.as_deref(), Some(CUSTOMER));
        let fee = events.iter().find(|e| e.kind == EventKind::FeePaid).unwrap();
        assert_eq!(fee.amount_base_units, -FEE);
        // The SPL movement left the merchant's SOL untouched beyond the
        // fee, so there is no SOL payout line at all.
        assert_eq!(events.iter().filter(|e| e.mint == NATIVE_SOL_MINT).count(), 1);
    }

    #[test]
    fn a_failed_transaction_produces_the_fee_and_nothing_else() {
        // Same body as a successful sale, only the error is set. If any
        // revenue survived that, a failed payment would look like a
        // completed one.
        let body = spl_in_body().replace(
            r#""err":null"#,
            r#""err":{"InstructionError":[0,{"Custom":1}]}"#,
        );
        // The merchant did not sign this one, so not even a fee is due.
        let events = normalize_transaction(MERCHANT, &sig(), &body).unwrap();
        assert!(events.is_empty(), "{events:?}");

        let body = spl_out_body().replace(
            r#""err":null"#,
            r#""err":{"InstructionError":[0,{"Custom":1}]}"#,
        );
        let events = normalize(&body);
        assert_eq!(kinds(&events), vec![EventKind::FeePaid]);
        assert_eq!(events[0].amount_base_units, -FEE);
    }

    #[test]
    fn a_transaction_touching_several_mints_books_each_one() {
        let events = normalize(&multi_mint_body());
        let usdc = events.iter().find(|e| e.mint == USDC).expect("usdc line");
        let usdt = events.iter().find(|e| e.mint == USDT).expect("usdt line");
        assert_eq!(usdc.kind, EventKind::Revenue);
        assert_eq!(usdc.amount_base_units, 25_000_000);
        assert_eq!(usdc.counterparty.as_deref(), Some(CUSTOMER));
        assert_eq!(usdt.kind, EventKind::Payout);
        assert_eq!(usdt.amount_base_units, -7_000_000);
        assert_eq!(usdt.counterparty.as_deref(), Some(SUPPLIER));
        assert_eq!(
            kinds(&events),
            vec![EventKind::Revenue, EventKind::Payout, EventKind::FeePaid]
        );
    }

    #[test]
    fn an_ambiguous_counterparty_is_left_absent_rather_than_guessed() {
        // Two customers pay in the same transaction. Naming one of them
        // would be a number no auditor could re-derive.
        let body = body_with(
            &sig(),
            &[CUSTOMER, SUPPLIER, MERCHANT, SYSTEM_PROGRAM],
            json!({
                "err": null,
                "fee": FEE,
                "preBalances": [2_000_000_000u64, 2_000_000_000u64, 0u64, 1u64],
                "postBalances": [1_499_995_000u64, 1_500_000_000u64, 1_000_000_000u64, 1u64],
                "preTokenBalances": [],
                "postTokenBalances": []
            }),
        );
        let events = normalize(&body);
        assert_eq!(kinds(&events), vec![EventKind::Revenue]);
        assert_eq!(events[0].counterparty, None);
    }

    #[test]
    fn token_movement_with_no_owner_anywhere_is_surfaced_not_dropped() {
        let strip_owner = |mut entry: Value| {
            entry.as_object_mut().unwrap().remove("owner");
            entry
        };
        let body = body_with(
            &sig(),
            &[CUSTOMER, CUSTOMER_ATA, MERCHANT_ATA, TOKEN_PROGRAM],
            json!({
                "err": null,
                "fee": FEE,
                "preBalances": [2_000_000_000u64, 2_039_280u64, 2_039_280u64, 1u64],
                "postBalances": [1_999_995_000u64, 2_039_280u64, 2_039_280u64, 1u64],
                "preTokenBalances": [strip_owner(token_balance(2, MERCHANT, USDC, 0, 6))],
                "postTokenBalances": [
                    strip_owner(token_balance(2, MERCHANT, USDC, 10_000_347, 6))
                ]
            }),
        );
        let events = normalize(&body);
        assert_eq!(kinds(&events), vec![EventKind::Unclassified]);
        assert_eq!(events[0].amount_base_units, 10_000_347);
        assert_eq!(events[0].mint, USDC);
        assert_eq!(events[0].counterparty, None);
    }

    #[test]
    fn an_owner_named_on_only_one_side_still_attributes() {
        // A freshly created ATA has no pre entry, and some nodes omit
        // the owner on the side that existed. Resolving by account index
        // keeps this one movement rather than splitting it into a fake
        // revenue and a matching exception.
        let mut pre = token_balance(2, MERCHANT, USDC, 0, 6);
        pre.as_object_mut().unwrap().remove("owner");
        let body = body_with(
            &sig(),
            &[CUSTOMER, CUSTOMER_ATA, MERCHANT_ATA, TOKEN_PROGRAM],
            json!({
                "err": null,
                "fee": FEE,
                "preBalances": [2_000_000_000u64, 2_039_280u64, 0u64, 1u64],
                "postBalances": [1_999_995_000u64, 2_039_280u64, 2_039_280u64, 1u64],
                "preTokenBalances": [
                    token_balance(1, CUSTOMER, USDC, 50_000_000, 6),
                    pre
                ],
                "postTokenBalances": [
                    token_balance(1, CUSTOMER, USDC, 39_999_653, 6),
                    token_balance(2, MERCHANT, USDC, 10_000_347, 6)
                ]
            }),
        );
        let events = normalize(&body);
        let usdc = events.iter().find(|e| e.mint == USDC).expect("usdc line");
        assert_eq!(usdc.kind, EventKind::Revenue);
        assert_eq!(usdc.amount_base_units, 10_000_347);
        assert!(!kinds(&events).contains(&EventKind::Unclassified));
    }

    #[test]
    fn amounts_come_from_the_integer_string_not_the_ui_float() {
        // A node that reports a wrong or rounded uiAmount must not move
        // the book by one base unit.
        let mut body: Value = serde_json::from_str(&spl_in_body()).unwrap();
        for list in ["preTokenBalances", "postTokenBalances"] {
            let entries = body["result"]["meta"][list].as_array_mut().unwrap();
            for entry in entries {
                entry["uiTokenAmount"]["uiAmount"] = json!(999_999.999_f64);
                entry["uiTokenAmount"]["uiAmountString"] = json!("999999.999");
            }
        }
        let events = normalize(&body.to_string());
        assert_eq!(events[0].amount_base_units, 10_000_347);
    }

    #[test]
    fn normalizing_the_same_input_twice_is_byte_identical() {
        // The anchored hash is taken over these lines, so this is the
        // test that says the anchor means anything at all.
        for body in [
            sol_in_body(),
            sol_out_body(),
            spl_in_body(),
            spl_out_body(),
            multi_mint_body(),
        ] {
            let first = normalize(&body);
            let second = normalize(&body);
            assert_eq!(first, second);
            assert_eq!(lines(&first).join("\n"), lines(&second).join("\n"));
        }
    }

    #[test]
    fn shuffling_the_token_balance_lists_does_not_move_the_output() {
        // The order of entries inside preTokenBalances and
        // postTokenBalances carries no meaning: each entry names the
        // account it describes. A node is free to emit them in any
        // order, and a node on the other side of the world may pick a
        // different one. If that order reached the output, two honest
        // auditors would derive two different hashes from one piece of
        // chain state and the anchor would prove nothing.
        for original in [spl_in_body(), spl_out_body(), multi_mint_body()] {
            let expected = lines(&normalize(&original));
            let mut body: Value = serde_json::from_str(&original).unwrap();
            for list in ["preTokenBalances", "postTokenBalances"] {
                let entries = body["result"]["meta"][list]
                    .as_array()
                    .unwrap()
                    .iter()
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>();
                body["result"]["meta"][list] = json!(entries);
            }
            assert_eq!(lines(&normalize(&body.to_string())), expected);
        }
    }

    #[test]
    fn moving_accounts_to_different_slots_does_not_move_the_output() {
        // The account key list is not free-form the way the token
        // balance lists are: position zero is the fee payer by protocol
        // and the token balance entries reference the other positions by
        // index, so permuting it is a different transaction rather than
        // a reordering of the same one. What must not matter is which
        // of the remaining slots an account happens to occupy, so this
        // reverses everything below the fee payer and renumbers every
        // reference to match.
        let original = multi_mint_body();
        let expected = lines(&normalize(&original));
        let mut body: Value = serde_json::from_str(&original).unwrap();

        // Old slot i (i >= 1) becomes slot len - i, and slot zero stays.
        let remap = |i: usize, len: usize| if i == 0 { 0 } else { len - i };
        let permute = |values: &Vec<Value>| {
            let len = values.len();
            let mut out = values.clone();
            for (i, value) in values.iter().enumerate() {
                out[remap(i, len)] = value.clone();
            }
            out
        };

        let keys = body["result"]["transaction"]["message"]["accountKeys"]
            .as_array()
            .unwrap()
            .clone();
        let len = keys.len();
        body["result"]["transaction"]["message"]["accountKeys"] = json!(permute(&keys));
        for list in ["preBalances", "postBalances"] {
            let values = body["result"]["meta"][list].as_array().unwrap().clone();
            body["result"]["meta"][list] = json!(permute(&values));
        }
        for list in ["preTokenBalances", "postTokenBalances"] {
            let entries = body["result"]["meta"][list]
                .as_array()
                .unwrap()
                .iter()
                .cloned()
                .map(|mut entry| {
                    let index = entry["accountIndex"].as_u64().unwrap() as usize;
                    entry["accountIndex"] = json!(remap(index, len) as u64);
                    entry
                })
                .collect::<Vec<_>>();
            body["result"]["meta"][list] = json!(entries);
        }

        assert_eq!(lines(&normalize(&body.to_string())), expected);
    }

    #[test]
    fn a_batch_is_ordered_by_signature_regardless_of_fetch_order() {
        let a = (sig(), spl_in_body());
        let b = (
            other_sig(),
            body_with(
                &other_sig(),
                &[MERCHANT, SUPPLIER, SYSTEM_PROGRAM],
                json!({
                    "err": null,
                    "fee": FEE,
                    "preBalances": [1_000_000_000u64, 0u64, 1u64],
                    "postBalances": [499_995_000u64, 500_000_000u64, 1u64],
                    "preTokenBalances": [],
                    "postTokenBalances": []
                }),
            ),
        );
        let forward = normalize_transactions(MERCHANT, &[a.clone(), b.clone()]).unwrap();
        let reverse = normalize_transactions(MERCHANT, &[b, a]).unwrap();
        assert_eq!(forward, reverse);
        // Sorted by signature, and the fixtures were chosen so the two
        // differ: [7u8; 64] encodes below [8u8; 64].
        assert!(sig() < other_sig());
        assert_eq!(forward[0].signature, sig());
        assert_eq!(forward.last().unwrap().signature, other_sig());
    }

    #[test]
    fn a_missing_transaction_is_an_error_not_an_empty_day() {
        let body = r#"{"jsonrpc":"2.0","result":null,"id":1}"#;
        let err = normalize_transaction(MERCHANT, &sig(), body).unwrap_err();
        assert!(err.contains("not available"), "{err}");
    }

    #[test]
    fn an_rpc_error_is_surfaced_rather_than_booked_as_a_quiet_day() {
        let body = r#"{"jsonrpc":"2.0","error":{"code":-32004,"message":"Node unhealthy"},"id":1}"#;
        let err = normalize_transaction(MERCHANT, &sig(), body).unwrap_err();
        assert!(err.contains("-32004"), "{err}");
    }

    #[test]
    fn a_merchant_address_that_is_not_an_address_is_refused() {
        let err = normalize_transaction("pay-me-here", &sig(), &sol_in_body()).unwrap_err();
        assert!(err.contains("not a valid Solana address"), "{err}");
    }

    #[test]
    fn canonical_lines_are_fixed_in_shape() {
        let events = normalize(&sol_in_body());
        assert_eq!(
            events[0].canonical_line(),
            format!("{}\t1750000000\trevenue\tSOL\t1000000000\t{CUSTOMER}", sig())
        );
        let absent = LedgerEvent {
            signature: sig(),
            block_time_unix: None,
            kind: EventKind::Unclassified,
            mint: USDC.to_string(),
            amount_base_units: -1,
            counterparty: None,
        };
        assert_eq!(
            absent.canonical_line(),
            format!("{}\t-\tunclassified\t{USDC}\t-1\t-", sig())
        );
    }
}
