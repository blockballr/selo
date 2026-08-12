//! # local Quote Store Schemas
//!
//! defines the data structures for active quote records, settlement status, and expiry lifecycle.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuoteStatus {
    Pending,
    Settled {
        tx_signature: String,
        settled_at: u64,
    },
    Expired,
    Closed, // manual overrides
    Refunded {
        signature: String,
        refunded_at: u64, // tracking refund
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuoteRecord {
    pub id: String,
    pub recipient: String,
    pub amount_lamports: u64,
    pub reference_pubkey: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: QuoteStatus,
    pub label: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundRecord {
    pub quote_id: String,
    pub recipient: String,
    pub amount_lamports: u64,
    pub original_signature: String,
    pub refund_signature: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeloStore {
    pub version: u32,
    pub updated_at: u64,
    pub quotes: Vec<QuoteRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSummary {
    pub total: usize,
    pub pending: usize,
    pub settled: usize,
    pub expired: usize,
}

impl SeloStore {
    pub fn new() -> Self {
        Self {
            version: 1,
            updated_at: 0,
            quotes: Vec::new(),
        }
    }

    pub fn add_quote(&mut self, quote: QuoteRecord) {
        self.quotes.push(quote);
    }

    pub fn get_pending_quotes(&self) -> Vec<&QuoteRecord> {
        self.quotes
            .iter()
            .filter(|q| matches!(q.status, QuoteStatus::Pending))
            .collect()
    }

    /// marks a pending quote as Settled by its unique quote ID.
    pub fn settle_quote(&mut self, quote_id: &str, tx_signature: String, settled_at: u64) -> bool {
        if let Some(quote) = self.quotes.iter_mut().find(|q| q.id == quote_id) {
            if matches!(quote.status, QuoteStatus::Pending) {
                quote.status = QuoteStatus::Settled {
                    tx_signature,
                    settled_at,
                };
                return true;
            }
        }
        false
    }

    pub fn prune_expired(&mut self, now_unix: u64) -> usize {
        let mut expired_count = 0;
        for quote in self.quotes.iter_mut() {
            if matches!(quote.status, QuoteStatus::Pending) && now_unix >= quote.expires_at {
                quote.status = QuoteStatus::Expired;
                expired_count += 1;
            }
        }
        expired_count
    }

    pub fn get_summary(&self) -> StoreSummary {
        let mut summary = StoreSummary {
            total: self.quotes.len(),
            pending: 0,
            settled: 0,
            expired: 0,
        };

        for q in &self.quotes {
            match q.status {
                QuoteStatus::Pending => summary.pending += 1,
                QuoteStatus::Settled { .. } => summary.settled += 1,
                QuoteStatus::Expired => summary.expired += 1,
                QuoteStatus::Closed => {}
                QuoteStatus::Refunded { .. } => {}
            }
        }

        summary
    }

    pub fn close_quote(&mut self, id: &str) -> bool {
        if let Some(quote) = self.quotes.iter_mut().find(|q| q.id == id) {
            if matches!(quote.status, QuoteStatus::Pending) {
                quote.status = QuoteStatus::Closed;
                return true;
            }
        }
        false
    }

    pub fn refund_quote(&mut self, id: &str, refund_signature: &str, refunded_at: u64) -> bool {
        if let Some(quote) = self.quotes.iter_mut().find(|q| q.id == id) {
            quote.status = QuoteStatus::Refunded {
                signature: refund_signature.to_string(),
                refunded_at,
            };
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prune_expired_quotes() {
        let mut store = SeloStore::new();
        let now = 1000;

        // Pending quote (valid)
        store.add_quote(QuoteRecord {
            id: "q_valid".to_string(),
            recipient: "rec1".to_string(),
            amount_lamports: 100,
            reference_pubkey: "ref1".to_string(),
            created_at: now,
            expires_at: now + 900,
            status: QuoteStatus::Pending,
            label: None,
            message: None,
        });

        // Expired quote
        store.add_quote(QuoteRecord {
            id: "q_expired".to_string(),
            recipient: "rec2".to_string(),
            amount_lamports: 200,
            reference_pubkey: "ref2".to_string(),
            created_at: now - 1000,
            expires_at: now - 100,
            status: QuoteStatus::Pending,
            label: None,
            message: None,
        });

        let pruned = store.prune_expired(now);
        assert_eq!(pruned, 1);

        let summary = store.get_summary();
        assert_eq!(summary.pending, 1);
        assert_eq!(summary.expired, 1);
        assert_eq!(summary.settled, 0);
    }
}
