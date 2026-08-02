use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaPayParams<'a> {
    pub recipient: &'a str,
    pub amount_lamports: u64,
    pub reference_pubkey: &'a str,
    pub label: Option<&'a str>,
    pub message: Option<&'a str>,
}

/// constructs a standard `solana:` protocol URI.
/// lamports to SOL decimal (1 SOL = 1,000,000,000 lamports).
pub fn build_solana_pay_url(params: &SolanaPayParams) -> String {
    let sol_amount = params.amount_lamports as f64 / 1_000_000_000.0;

    let mut url = format!(
        "solana:{}?amount={}&reference={}",
        params.recipient, sol_amount, params.reference_pubkey
    );

    if let Some(label) = params.label {
        let encoded_label = urlencoding_simple(label);
        url.push_str("&label=");
        url.push_str(&encoded_label);
    }

    if let Some(msg) = params.message {
        let encoded_msg = urlencoding_simple(msg);
        url.push_str("&message=");
        url.push_str(&encoded_msg);
    }

    url
}

fn urlencoding_simple(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            ' ' => "%20".to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_solana_pay_url() {
        let params = SolanaPayParams {
            recipient: "7Xw19aK4mQ2vB8pY3zN6jR5wL8kQ9tM4sP2vX1yZ3kL9",
            amount_lamports: 1_500_000_000, // 1.5 SOL
            reference_pubkey: "4zVm2bK9pQ2vB8pY3zN6jR5wL8kQ9tM4sP2vX1yZ3kL9",
            label: Some("Coffee Order"),
            message: Some("Invoice #1042"),
        };

        let uri = build_solana_pay_url(&params);
        assert_eq!(
            uri,
            "solana:7Xw19aK4mQ2vB8pY3zN6jR5wL8kQ9tM4sP2vX1yZ3kL9?amount=1.5&reference=4zVm2bK9pQ2vB8pY3zN6jR5wL8kQ9tM4sP2vX1yZ3kL9&label=Coffee%20Order&message=Invoice%20%231042"
        );
    }
}
