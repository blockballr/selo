use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuoteStatus {
    Pending,
    Settled {
        tx_signature: String,
        settled_at: i64,
    },
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteRecord {
    pub id: String,
    pub sku: String,
    pub quantity: u32,
    pub amount_lamports: u64,
    pub reference_pubkey: String,
    pub created_at: i64,
    pub status: QuoteStatus,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StoreState {
    pub quotes: Vec<QuoteRecord>,
}

impl StoreState {
    pub fn new() -> Self {
        Self { quotes: Vec::new() }
    }

    pub fn add_quote(&mut self, record: QuoteRecord) {
        self.quotes.push(record);
    }

    pub fn find_quote(&self, id: &str) -> Option<&QuoteRecord> {
        self.quotes.iter().find(|q| q.id == id)
    }

    pub fn list_quotes(&self) -> &[QuoteRecord] {
        &self.quotes
    }
}
