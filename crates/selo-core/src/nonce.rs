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
}
