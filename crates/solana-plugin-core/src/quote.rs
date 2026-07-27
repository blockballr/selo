//! Quotes, and the payment amount encoding that makes them matchable.
//!
//! The agent holds no signing key, so it cannot sweep funds and every
//! sale lands at one fixed merchant address. That leaves a problem: a
//! stream of transfers arrives at a single account and something has to
//! decide which order each one paid for, without a database the shop
//! has to run and without asking the customer to attach a memo their
//! wallet may not even expose.
//!
//! The amount itself carries it. A price is cent-granular, but the mint
//! has more precision than that, and the digits below a cent are unused.
//! So the quote spends them deliberately: two digits name the sales
//! point, two more the order counter. Terminal 3's forty-seventh order
//! on a ten dollar total is quoted as 10.000347, and the payment that
//! arrives is self-identifying.
//!
//! Two consequences are worth naming because they are the reason for
//! this design rather than a random cents nonce.
//!
//! Collisions are removed structurally rather than made unlikely. Two
//! sales points cannot issue the same amount, because the sales point
//! is part of the number. Within one sales point the counter is what
//! distinguishes concurrent orders, so the only real constraint is that
//! a terminal must not have more open quotes at once than the counter
//! has room for, which `MAX_OPEN_PER_SALES_POINT` states and callers
//! enforce.
//!
//! Reconciliation per sales point becomes derivable from chain data
//! alone. An auditor who never sees our records can still attribute
//! every payment to the terminal that made the sale, because the
//! attribution is in the transfer amount rather than in a file we could
//! have edited.
//!
//! The cost to the customer is at most one cent, and in practice a tiny
//! fraction of one: the tag on a six-decimal mint is under 0.01 units.

/// Digits reserved at the bottom of the amount for the tag.
///
/// Four digits hold a two-digit sales point and a two-digit counter.
/// On a six-decimal mint such as USDC this is exactly the room below a
/// cent, so tagging never disturbs the price a customer was quoted.
pub const TAG_SCALE: u64 = 10_000;

/// Sales points are numbered from one so that a tag of zero is
/// recognizably absent. A payment whose low digits are below
/// `TAG_SCALE / 100` did not come from a quote we issued, and is sent
/// to the exceptions queue rather than guessed at.
pub const MIN_SALES_POINT: u8 = 1;

/// Two digits, so ninety nine terminals.
pub const MAX_SALES_POINT: u8 = 99;

/// Two digits, so a hundred counter values per sales point.
pub const MAX_ORDER_COUNTER: u8 = 99;

/// A sales point may not hold more open quotes at once than the counter
/// can distinguish. Callers enforce this when issuing; it is stated here
/// because it is a property of the encoding, not of the caller.
pub const MAX_OPEN_PER_SALES_POINT: usize = 100;

/// The sales point and order counter recovered from a payment amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmountTag {
    /// Which terminal issued the quote, one through ninety nine.
    pub sales_point: u8,
    /// Which order at that terminal, zero through ninety nine, cycling.
    pub order_counter: u8,
}

impl AmountTag {
    /// Build a tag, rejecting values the four digit field cannot hold.
    pub fn new(sales_point: u8, order_counter: u8) -> Result<Self, String> {
        if !(MIN_SALES_POINT..=MAX_SALES_POINT).contains(&sales_point) {
            return Err(format!(
                "sales point {sales_point} is outside {MIN_SALES_POINT} to {MAX_SALES_POINT}; \
                 sales point zero is reserved to mean untagged"
            ));
        }
        if order_counter > MAX_ORDER_COUNTER {
            return Err(format!(
                "order counter {order_counter} exceeds the maximum of {MAX_ORDER_COUNTER}"
            ));
        }
        Ok(Self { sales_point, order_counter })
    }

    /// The tag as it appears in the low digits of an amount.
    pub fn value(&self) -> u64 {
        self.sales_point as u64 * 100 + self.order_counter as u64
    }
}

/// Add the tag to a cent-granular price, giving the exact amount the
/// customer is asked to send.
///
/// `price_base_units` is the price in the mint's smallest unit and must
/// be a whole number of cents, meaning divisible by `TAG_SCALE`. A price
/// carrying digits of its own below a cent would be overwritten by the
/// tag, so that is refused rather than silently rounded: quoting a
/// customer a different number than the catalog holds is exactly the
/// class of bug this module exists to prevent.
pub fn encode_amount(price_base_units: u64, tag: AmountTag) -> Result<u64, String> {
    if price_base_units == 0 {
        return Err("a quote for zero is not a sale".to_string());
    }
    if price_base_units % TAG_SCALE != 0 {
        return Err(format!(
            "price {price_base_units} is not a whole number of cents on this mint, so the \
             tag would overwrite part of the price; prices must be a multiple of {TAG_SCALE}"
        ));
    }
    price_base_units
        .checked_add(tag.value())
        .ok_or_else(|| format!("price {price_base_units} overflows when tagged"))
}

/// Recover the price and the tag from an amount that arrived on chain.
///
/// Returns `Ok(None)` when the low digits carry no sales point, which
/// means this transfer did not come from a quote we issued. That is a
/// normal event, someone sending a round number to the shop address, and
/// it belongs in the exceptions queue rather than being reported as an
/// error.
pub fn decode_amount(amount_base_units: u64) -> Result<Option<(u64, AmountTag)>, String> {
    let tag_value = amount_base_units % TAG_SCALE;
    let price = amount_base_units - tag_value;
    let sales_point = (tag_value / 100) as u8;
    let order_counter = (tag_value % 100) as u8;
    if sales_point < MIN_SALES_POINT {
        return Ok(None);
    }
    // Reconstruct through the same constructor the issuing path uses, so
    // there is one definition of a valid tag rather than two.
    let tag = AmountTag::new(sales_point, order_counter)?;
    Ok(Some((price, tag)))
}

/// A quote issued to a customer, before any payment has arrived.
///
/// Every field is set from the catalog and the clock at issuance. None
/// of it is model authored: the agent chooses which item a customer
/// asked about, and this module decides what that costs. That split is
/// what keeps an injected instruction from producing a discount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quote {
    pub sales_point: u8,
    pub order_counter: u8,
    /// Catalog identifier of what was sold.
    pub sku: String,
    pub quantity: u32,
    /// Catalog price for one unit, in the mint's smallest unit.
    pub unit_price_base_units: u64,
    /// Quantity times unit price, before the tag is applied.
    pub subtotal_base_units: u64,
    /// What the customer must send, exactly. Subtotal plus the tag.
    pub amount_due_base_units: u64,
    /// The mint the shop settles in.
    pub mint: String,
    pub issued_at_unix: i64,
    /// After this instant the quote is dead and must be reissued rather
    /// than honored, because a shop pricing in a local currency is
    /// exposed to the rate moving between quote and payment.
    pub expires_at_unix: i64,
}

impl Quote {
    /// True once `now` has reached the expiry instant.
    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_at_unix
    }

    /// The tag this quote's amount carries.
    pub fn tag(&self) -> Result<AmountTag, String> {
        AmountTag::new(self.sales_point, self.order_counter)
    }
}

/// Issue a quote for `quantity` of an item at a known unit price.
///
/// The caller supplies the price from the catalog rather than from
/// anything a customer said, and supplies the clock. Both are deliberate:
/// this function has no way to reach a price of its own, so there is no
/// path by which a persuasive message becomes a cheaper quote.
#[allow(clippy::too_many_arguments)]
pub fn issue_quote(
    sales_point: u8,
    order_counter: u8,
    sku: &str,
    quantity: u32,
    unit_price_base_units: u64,
    mint: &str,
    now_unix: i64,
    ttl_secs: u32,
) -> Result<Quote, String> {
    if quantity == 0 {
        return Err("quantity must be at least one".to_string());
    }
    if ttl_secs == 0 {
        return Err("a quote with no lifetime cannot be paid".to_string());
    }
    let tag = AmountTag::new(sales_point, order_counter)?;

    let subtotal = unit_price_base_units
        .checked_mul(quantity as u64)
        .ok_or_else(|| format!("{quantity} at {unit_price_base_units} overflows"))?;
    let amount_due = encode_amount(subtotal, tag)?;

    let expires_at = now_unix
        .checked_add(ttl_secs as i64)
        .ok_or_else(|| "quote expiry overflows".to_string())?;

    Ok(Quote {
        sales_point,
        order_counter,
        sku: sku.to_string(),
        quantity,
        unit_price_base_units,
        subtotal_base_units: subtotal,
        amount_due_base_units: amount_due,
        mint: mint.to_string(),
        issued_at_unix: now_unix,
        expires_at_unix: expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    /// Ten dollars on a six decimal mint.
    const TEN_USDC: u64 = 10_000_000;

    #[test]
    fn encode_then_decode_is_exact_across_the_whole_range() {
        // The encoding is the only thing standing between a payment and
        // the wrong order, so every representable tag is checked rather
        // than a sample.
        for sales_point in MIN_SALES_POINT..=MAX_SALES_POINT {
            for order_counter in 0..=MAX_ORDER_COUNTER {
                let tag = AmountTag::new(sales_point, order_counter).unwrap();
                let amount = encode_amount(TEN_USDC, tag).unwrap();
                let (price, recovered) = decode_amount(amount).unwrap().expect("tagged");
                assert_eq!(price, TEN_USDC, "price survives tagging");
                assert_eq!(recovered, tag, "tag round trips");
            }
        }
    }

    #[test]
    fn distinct_tags_give_distinct_amounts_at_one_price() {
        // Structural collision freedom: this is the property that lets a
        // single receiving address serve every terminal at once.
        let mut seen = std::collections::HashSet::new();
        for sales_point in MIN_SALES_POINT..=MAX_SALES_POINT {
            for order_counter in 0..=MAX_ORDER_COUNTER {
                let tag = AmountTag::new(sales_point, order_counter).unwrap();
                let amount = encode_amount(TEN_USDC, tag).unwrap();
                assert!(seen.insert(amount), "amount {amount} issued twice");
            }
        }
    }

    #[test]
    fn the_tag_never_disturbs_the_quoted_price() {
        let tag = AmountTag::new(99, 99).unwrap();
        let amount = encode_amount(TEN_USDC, tag).unwrap();
        // Largest possible tag is still under one cent on a six decimal
        // mint, so the customer is never asked for a different price.
        assert!(amount - TEN_USDC < 10_000, "tag stays below a cent");
        assert_eq!(amount, 10_009_999);
    }

    #[test]
    fn an_untagged_amount_is_reported_as_such_not_as_an_error() {
        // A round payment to the shop address is a real thing that
        // happens and belongs in the exceptions queue.
        assert_eq!(decode_amount(TEN_USDC).unwrap(), None);
        // Low digits present but no sales point is still untagged.
        assert_eq!(decode_amount(TEN_USDC + 99).unwrap(), None);
    }

    #[test]
    fn a_price_finer_than_a_cent_is_refused_rather_than_rounded() {
        let tag = AmountTag::new(3, 47).unwrap();
        let err = encode_amount(TEN_USDC + 1, tag).unwrap_err();
        assert!(err.contains("whole number of cents"), "{err}");
    }

    #[test]
    fn sales_point_zero_is_rejected_because_it_means_untagged() {
        let err = AmountTag::new(0, 5).unwrap_err();
        assert!(err.contains("reserved"), "{err}");
    }

    #[test]
    fn out_of_range_tag_components_are_rejected() {
        assert!(AmountTag::new(100, 0).is_err());
        assert!(AmountTag::new(1, 100).is_err());
    }

    #[test]
    fn zero_price_is_not_a_sale() {
        let tag = AmountTag::new(1, 0).unwrap();
        assert!(encode_amount(0, tag).is_err());
    }

    #[test]
    fn issue_quote_produces_the_documented_example() {
        // Terminal 3's forty seventh order on a ten dollar total.
        let q = issue_quote(3, 47, "RICE-5KG", 1, TEN_USDC, USDC, 1_700_000_000, 900).unwrap();
        assert_eq!(q.amount_due_base_units, 10_000_347);
        assert_eq!(q.subtotal_base_units, TEN_USDC);
        assert_eq!(q.expires_at_unix, 1_700_000_900);
        let (price, tag) = decode_amount(q.amount_due_base_units).unwrap().unwrap();
        assert_eq!(price, TEN_USDC);
        assert_eq!(tag.sales_point, 3);
        assert_eq!(tag.order_counter, 47);
    }

    #[test]
    fn quantity_multiplies_the_unit_price() {
        let q = issue_quote(1, 0, "RICE-5KG", 3, TEN_USDC, USDC, 0, 900).unwrap();
        assert_eq!(q.subtotal_base_units, 30_000_000);
        assert_eq!(q.amount_due_base_units, 30_000_100);
    }

    #[test]
    fn quotes_expire_at_the_boundary() {
        let q = issue_quote(1, 0, "RICE-5KG", 1, TEN_USDC, USDC, 1_000, 900).unwrap();
        assert!(!q.is_expired(1_899), "still live one second before");
        assert!(q.is_expired(1_900), "dead at the expiry instant");
        assert!(q.is_expired(2_000));
    }

    #[test]
    fn a_quote_with_no_lifetime_is_refused() {
        assert!(issue_quote(1, 0, "X", 1, TEN_USDC, USDC, 0, 0).is_err());
    }

    #[test]
    fn zero_quantity_is_refused() {
        assert!(issue_quote(1, 0, "X", 0, TEN_USDC, USDC, 0, 900).is_err());
    }
}
