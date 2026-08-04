//! Durable Nonce Anchoring
//!
//! handles the creation and management of Durable Nonce instructions
//! to ensure transactions do not expire before reaching the cluster

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceState {
    pub nonce_address: String,
    pub authority: String,
    pub current_nonce: String,
}

/// rotating a durable nonce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceInstruction {
    pub program_id: String,
    pub nonce_account: String,
    pub authority: String,
}

impl NonceInstruction {
    pub fn new(nonce_account: &str, authority: &str) -> Self {
        Self {
            program_id: "11111111111111111111111111111111".to_string(), // System Program
            nonce_account: nonce_account.to_string(),
            authority: authority.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorTransactionData {
    pub nonce_account: String,
    pub authority: String,
    pub state_root: String,
    pub instructions: Vec<NonceInstruction>,
    pub description: String,
}

/// unsigned anchor transaction payload embedding the Poseidon state root and durable nonce
pub fn build_anchor_transaction(
    nonce_account: &str,
    authority: &str,
    state_root: &str,
) -> AnchorTransactionData {
    let nonce_ix = NonceInstruction::new(nonce_account, authority);
    AnchorTransactionData {
        nonce_account: nonce_account.to_string(),
        authority: authority.to_string(),
        state_root: state_root.to_string(),
        instructions: vec![nonce_ix],
        description: format!(
            "Unsigned anchor transaction for Poseidon BN254 state root: {}. Secured with durable nonce account: {}",
            state_root, nonce_account
        ),
    }
}

/// validates nonce account active status
pub fn is_nonce_ready(state: &NonceState) -> bool {
    !state.current_nonce.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_readiness() {
        let valid_state = NonceState {
            nonce_address: "DummyNonceAccount11111111111111111111111".to_string(),
            authority: "DummyAuth11111111111111111111111111111111".to_string(),
            current_nonce: "Gk8Z...blockhash".to_string(),
        };
        assert!(is_nonce_ready(&valid_state));

        let invalid_state = NonceState {
            nonce_address: "DummyNonceAccount11111111111111111111111".to_string(),
            authority: "DummyAuth11111111111111111111111111111111".to_string(),
            current_nonce: "".to_string(),
        };
        assert!(!is_nonce_ready(&invalid_state));
    }

    #[test]
    fn test_nonce_instruction_builder() {
        let instruction = NonceInstruction::new("TestNonceAcc", "TestAuthAcc");

        assert_eq!(instruction.program_id, "11111111111111111111111111111111");
        assert_eq!(instruction.nonce_account, "TestNonceAcc");
        assert_eq!(instruction.authority, "TestAuthAcc");
    }

    #[test]
    fn test_anchor_transaction_builder() {
        let tx_data = build_anchor_transaction("NonceAcc123", "AuthAcc456", "0x153d04");
        assert_eq!(tx_data.nonce_account, "NonceAcc123");
        assert_eq!(tx_data.authority, "AuthAcc456");
        assert_eq!(tx_data.state_root, "0x153d04");
        assert_eq!(tx_data.instructions.len(), 1);
    }
}
