//! local quote store schemas
//!
//! defines data structures for active quote records and settlement status.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuoteStatus {
    Pending,
    Settled {
        tx_signature: String,
        settled_at: u64,
    },
    Expired,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeloStore {
    pub version: u32,
    pub updated_at: u64,
    pub quotes: Vec<QuoteRecord>,
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
}
