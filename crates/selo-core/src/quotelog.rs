//! The append-only record of what was quoted.
//!
//! The amount says which order was paid; this says what was in it.
//!
//! Append-only is adversarial, not architectural. If the record could be
//! edited, an injection reaching the agent at closing time could reprice
//! or delete the morning. This module exposes no mutation path. Appending
//! a false line forward is bounded by prices coming from operator config.

use std::collections::BTreeMap;

use crate::quote::{AmountTag, Quote};

/// One immutable line: a quote as it was issued.
///
/// Deliberately a snapshot rather than a reference to a mutable quote.
/// Copying the price and quantity in at issuance means a later change to
/// the catalog cannot retroactively alter what a past customer was told,
/// which is both an accounting requirement and a tamper barrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteEntry {
    pub sales_point: u8,
    pub order_counter: u8,
    pub sku: String,
    pub quantity: u32,
    pub unit_price_base_units: u64,
    pub subtotal_base_units: u64,
    /// The exact amount the customer was asked to send, tag included.
    pub amount_due_base_units: u64,
    pub mint: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

impl QuoteEntry {
    /// The tag that identifies payments against this quote.
    pub fn tag(&self) -> Result<AmountTag, String> {
        AmountTag::new(self.sales_point, self.order_counter)
    }

    /// True once `now` has reached the expiry instant.
    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_at_unix
    }
}

impl From<&Quote> for QuoteEntry {
    fn from(q: &Quote) -> Self {
        Self {
            sales_point: q.sales_point,
            order_counter: q.order_counter,
            sku: q.sku.clone(),
            quantity: q.quantity,
            unit_price_base_units: q.unit_price_base_units,
            subtotal_base_units: q.subtotal_base_units,
            amount_due_base_units: q.amount_due_base_units,
            mint: q.mint.clone(),
            issued_at_unix: q.issued_at_unix,
            expires_at_unix: q.expires_at_unix,
        }
    }
}

/// An append-only log of issued quotes.
///
/// The public surface is intentionally small: append, and read. There is
/// no update, no remove, and no index-based mutation, because every one
/// of those would be a lever for rewriting history.
#[derive(Debug, Clone, Default)]
pub struct QuoteLog {
    entries: Vec<QuoteEntry>,
    /// Highest counter issued per sales point, so the next one is chosen
    /// by this module rather than supplied by a caller. A caller-chosen
    /// counter could collide deliberately, aliasing a new order onto an
    /// old one's payment.
    next_counter: BTreeMap<u8, u8>,
}

impl QuoteLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild from previously persisted entries, preserving order.
    ///
    /// Used at startup to restore the day. Counters are recomputed from
    /// the entries themselves rather than trusted from a separate field,
    /// so a tampered counter cannot be smuggled in alongside honest lines.
    pub fn from_entries(entries: Vec<QuoteEntry>) -> Self {
        let mut next_counter = BTreeMap::new();
        for e in &entries {
            let next = e.order_counter.wrapping_add(1) % (crate::quote::MAX_ORDER_COUNTER + 1);
            next_counter.insert(e.sales_point, next);
        }
        Self { entries, next_counter }
    }

    /// The counter the next quote at this sales point will use.
    ///
    /// Cycles within the two digits the tag reserves. Cycling is safe
    /// only while a terminal has fewer open quotes than the counter has
    /// values, which `open_at` lets a caller check before issuing.
    pub fn next_counter(&self, sales_point: u8) -> u8 {
        self.next_counter.get(&sales_point).copied().unwrap_or(0)
    }

    /// Append an issued quote. The only way to add to the log.
    ///
    /// Refuses a quote whose tag duplicates one still open, because two
    /// live quotes sharing a tag would both match the same payment and
    /// there would be no honest way to decide which was paid.
    pub fn append(&mut self, quote: &Quote, now_unix: i64) -> Result<(), String> {
        let tag = quote.tag()?;
        if let Some(clash) = self.entries.iter().find(|e| {
            e.sales_point == tag.sales_point
                && e.order_counter == tag.order_counter
                && !e.is_expired(now_unix)
        }) {
            return Err(format!(
                "sales point {} already has an open quote at counter {} for {}; \
                 issuing another would make one payment match two orders",
                clash.sales_point, clash.order_counter, clash.sku
            ));
        }
        let entry = QuoteEntry::from(quote);
        let next = entry.order_counter.wrapping_add(1) % (crate::quote::MAX_ORDER_COUNTER + 1);
        self.next_counter.insert(entry.sales_point, next);
        self.entries.push(entry);
        Ok(())
    }

    /// Every entry, in issuance order.
    pub fn entries(&self) -> &[QuoteEntry] {
        &self.entries
    }

    /// Quotes still payable at `now`, at one sales point.
    pub fn open_at(&self, sales_point: u8, now_unix: i64) -> Vec<&QuoteEntry> {
        self.entries
            .iter()
            .filter(|e| e.sales_point == sales_point && !e.is_expired(now_unix))
            .collect()
    }

    /// Find the entry a tagged payment refers to, expired or not.
    ///
    /// Expiry is deliberately not filtered here. A customer who paid late
    /// is a real person owed a decision, and silently failing to find
    /// their order would strand their money. The caller decides what an
    /// expired match means.
    pub fn find_by_tag(&self, tag: AmountTag) -> Option<&QuoteEntry> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.sales_point == tag.sales_point && e.order_counter == tag.order_counter)
    }

    /// True when this sales point has no counter values left for a new
    /// order. Callers check before issuing rather than discovering the
    /// collision at append time.
    pub fn is_saturated(&self, sales_point: u8, now_unix: i64) -> bool {
        self.open_at(sales_point, now_unix).len() >= crate::quote::MAX_OPEN_PER_SALES_POINT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quote::issue_quote;

    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const TEN: u64 = 10_000_000;

    fn quote_at(sales_point: u8, counter: u8, sku: &str, now: i64) -> Quote {
        issue_quote(sales_point, counter, sku, 1, TEN, USDC, now, 900).unwrap()
    }

    #[test]
    fn appending_records_the_quote_verbatim() {
        let mut log = QuoteLog::new();
        let q = quote_at(3, 47, "RICE-5KG", 1_000);
        log.append(&q, 1_000).unwrap();

        let e = &log.entries()[0];
        assert_eq!(e.sku, "RICE-5KG");
        assert_eq!(e.amount_due_base_units, 10_000_347);
        assert_eq!(e.subtotal_base_units, TEN);
        assert_eq!(e.expires_at_unix, 1_900);
    }

    #[test]
    fn there_is_no_way_to_alter_an_entry_after_the_fact() {
        // This test documents an API property rather than a behavior:
        // entries() hands out a shared slice, so a caller holding the log
        // immutably cannot reach in and rewrite a past sale. If someone
        // later adds a mutable accessor, this intent should be revisited
        // deliberately rather than by accident.
        let mut log = QuoteLog::new();
        log.append(&quote_at(1, 0, "RICE-5KG", 0), 0).unwrap();
        let entries: &[QuoteEntry] = log.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sku, "RICE-5KG");
    }

    #[test]
    fn two_open_quotes_may_not_share_a_tag() {
        let mut log = QuoteLog::new();
        log.append(&quote_at(3, 47, "RICE-5KG", 1_000), 1_000).unwrap();
        let clash = quote_at(3, 47, "OIL-1L", 1_100);
        let err = log.append(&clash, 1_100).unwrap_err();
        assert!(err.contains("already has an open quote"), "{err}");
    }

    #[test]
    fn a_tag_is_reusable_once_the_earlier_quote_has_expired() {
        let mut log = QuoteLog::new();
        log.append(&quote_at(3, 47, "RICE-5KG", 1_000), 1_000).unwrap();
        // The first quote expires at 1900.
        let later = quote_at(3, 47, "OIL-1L", 2_000);
        log.append(&later, 2_000).unwrap();
        assert_eq!(log.entries().len(), 2);
    }

    #[test]
    fn counters_advance_and_cycle_within_the_tag_field() {
        let mut log = QuoteLog::new();
        assert_eq!(log.next_counter(5), 0);
        log.append(&quote_at(5, 0, "A", 0), 0).unwrap();
        assert_eq!(log.next_counter(5), 1);
        // At the top of the field the counter wraps rather than
        // overflowing out of the two digits the tag reserves.
        let mut log = QuoteLog::new();
        log.append(&quote_at(5, crate::quote::MAX_ORDER_COUNTER, "A", 0), 0)
            .unwrap();
        assert_eq!(log.next_counter(5), 0);
    }

    #[test]
    fn counters_are_tracked_per_sales_point() {
        let mut log = QuoteLog::new();
        log.append(&quote_at(1, 0, "A", 0), 0).unwrap();
        log.append(&quote_at(1, 1, "B", 0), 0).unwrap();
        log.append(&quote_at(2, 0, "C", 0), 0).unwrap();
        assert_eq!(log.next_counter(1), 2);
        assert_eq!(log.next_counter(2), 1);
        assert_eq!(log.next_counter(9), 0, "an unused terminal starts at zero");
    }

    #[test]
    fn open_at_filters_by_terminal_and_expiry() {
        let mut log = QuoteLog::new();
        log.append(&quote_at(1, 0, "A", 1_000), 1_000).unwrap();
        log.append(&quote_at(2, 0, "B", 1_000), 1_000).unwrap();
        assert_eq!(log.open_at(1, 1_000).len(), 1);
        assert_eq!(log.open_at(1, 1_899).len(), 1);
        assert_eq!(log.open_at(1, 1_900).len(), 0, "expired drops out");
    }

    #[test]
    fn an_expired_quote_is_still_findable_so_a_late_payer_is_not_stranded() {
        let mut log = QuoteLog::new();
        log.append(&quote_at(3, 47, "RICE-5KG", 1_000), 1_000).unwrap();
        let tag = AmountTag::new(3, 47).unwrap();
        // Long after expiry, the order is still identifiable.
        let found = log.find_by_tag(tag).expect("late payments must be traceable");
        assert_eq!(found.sku, "RICE-5KG");
    }

    #[test]
    fn find_by_tag_returns_the_most_recent_reuse() {
        let mut log = QuoteLog::new();
        log.append(&quote_at(3, 47, "RICE-5KG", 1_000), 1_000).unwrap();
        log.append(&quote_at(3, 47, "OIL-1L", 2_000), 2_000).unwrap();
        let tag = AmountTag::new(3, 47).unwrap();
        assert_eq!(log.find_by_tag(tag).unwrap().sku, "OIL-1L");
    }

    #[test]
    fn restoring_from_entries_recomputes_counters_rather_than_trusting_them() {
        let mut log = QuoteLog::new();
        log.append(&quote_at(4, 10, "A", 0), 0).unwrap();
        let restored = QuoteLog::from_entries(log.entries().to_vec());
        assert_eq!(restored.next_counter(4), 11);
        assert_eq!(restored.entries().len(), 1);
    }

    #[test]
    fn saturation_is_reported_before_a_collision_can_happen() {
        let mut log = QuoteLog::new();
        assert!(!log.is_saturated(1, 1_000));
        for counter in 0..=crate::quote::MAX_ORDER_COUNTER {
            log.append(&quote_at(1, counter, "A", 1_000), 1_000).unwrap();
        }
        assert!(log.is_saturated(1, 1_000), "a full terminal reports saturated");
        assert!(!log.is_saturated(1, 1_900), "expiry frees the field again");
    }
}
