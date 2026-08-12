//! Durable Nonce Anchoring
//!
//! handles the creation and management of Durable Nonce instructions
//! to ensure transactions do not expire before reaching the cluster

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceState {
    pub nonce_address: String,
    pub authority: String,
    pub current_nonce: String,
}

/// Layout of a durable nonce account's data, as the System Program stores it
/// in bincode:
///
/// ```text
/// offset 0:  u32 Versions::Current   (1)
/// offset 4:  u32 State::Initialized  (1)
/// offset 8:  [u8; 32] authority
/// offset 40: [u8; 32] durable nonce blockhash
/// offset 72: u64 lamports_per_signature (not needed here)
/// ```
///
/// The full state is 80 bytes; the two variant discriminants at the front
/// are why the fields sit at 8 and 40 rather than 0 and 32.
const VERSIONS_DISCRIMINANT: usize = 4;
const STATE_DISCRIMINANT: usize = 4;
const AUTHORITY_BYTES: usize = 32;
const NONCE_BYTES: usize = 32;
const AUTHORITY_OFFSET: usize = VERSIONS_DISCRIMINANT + STATE_DISCRIMINANT;
const NONCE_OFFSET: usize = AUTHORITY_OFFSET + AUTHORITY_BYTES;
const NONCE_DATA_HEADER: usize = NONCE_OFFSET + NONCE_BYTES;

/// The bincode value for `Versions::Current`.
const VERSIONS_CURRENT: u32 = 1;
/// The bincode value for `State::Initialized`.
const STATE_INITIALIZED: u32 = 1;

/// Parse a `getAccountInfo` result for a nonce account into a `NonceState`.
///
/// The result is expected in the base64 encoding Solana's RPC returns by
/// default: `data` is `[encoded, "base64"]` and the account must have a
/// non-empty data blob. The stored authority must match `expected_authority`,
/// since advancing the nonce is gated on that authority and an anchor built
/// against the wrong one would fail at submission rather than at review.
pub fn nonce_state_from_account_info(
    nonce_address: &str,
    expected_authority: &str,
    result: &Value,
) -> Result<NonceState, String> {
    let value = result
        .get("value")
        .ok_or_else(|| "getAccountInfo returned no value".to_string())?;
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "nonce account has no data; the address does not hold a durable nonce".to_string()
        })?;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let bytes = STANDARD
        .decode(data)
        .map_err(|e| format!("nonce account data is not valid base64: {e}"))?;
    if bytes.len() < NONCE_DATA_HEADER {
        return Err(format!(
            "nonce account data is {} bytes, fewer than the {} a durable nonce needs",
            bytes.len(),
            NONCE_DATA_HEADER
        ));
    }
    let versions = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if versions != VERSIONS_CURRENT {
        return Err(format!(
            "nonce account has Versions::{versions}, not Current; this is not a usable durable nonce"
        ));
    }
    let state = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if state != STATE_INITIALIZED {
        return Err(format!(
            "nonce account has State::{state}, not Initialized; this is not an active durable nonce"
        ));
    }
    let authority = bs58::encode(&bytes[AUTHORITY_OFFSET..AUTHORITY_OFFSET + AUTHORITY_BYTES])
        .into_string();
    if authority != expected_authority {
        return Err(format!(
            "nonce account is governed by {authority}, not {expected_authority}; an anchor built \
             against the wrong authority cannot be advanced"
        ));
    }
    let current_nonce =
        bs58::encode(&bytes[NONCE_OFFSET..NONCE_DATA_HEADER]).into_string();

    Ok(NonceState {
        nonce_address: nonce_address.to_string(),
        authority,
        current_nonce,
    })
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

    #[test]
    fn parses_a_durable_nonce_account() {
        use serde_json::json;
        let authority = bs58::encode([7u8; 32]).into_string();
        let nonce = bs58::encode([9u8; 32]).into_string();
        // Real bincode layout: Versions::Current, State::Initialized, then
        // the 32-byte authority and 32-byte durable nonce at offsets 8/40.
        let mut blob = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes()); // Versions::Current
        blob.extend_from_slice(&1u32.to_le_bytes()); // State::Initialized
        blob.extend_from_slice(&[7u8; 32]); // authority
        blob.extend_from_slice(&[9u8; 32]); // durable nonce
        blob.extend_from_slice(&[0u8; 8]); // lamports per signature

        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let encoded = STANDARD.encode(&blob);

        let result = json!({ "value": { "data": [encoded, "base64"] } });
        let state =
            nonce_state_from_account_info("NonceAcc123", &authority, &result).unwrap();
        assert_eq!(state.nonce_address, "NonceAcc123");
        assert_eq!(state.authority, authority);
        assert_eq!(state.current_nonce, nonce);
    }

    #[test]
    fn refuses_a_nonce_account_with_the_wrong_authority() {
        use serde_json::json;
        let mut blob = Vec::new();
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&[7u8; 32]);
        blob.extend_from_slice(&[9u8; 32]);
        blob.extend_from_slice(&[0u8; 8]);

        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let encoded = STANDARD.encode(&blob);

        let result = json!({ "value": { "data": [encoded, "base64"] } });
        let err = nonce_state_from_account_info("NonceAcc123", "someone-else", &result)
            .unwrap_err();
        assert!(err.contains("not"), "{err}");
    }

    #[test]
    fn refuses_account_data_that_is_not_a_nonce() {
        use serde_json::json;
        // Not a Current nonce: the version discriminant is 3.
        let mut blob = Vec::new();
        blob.extend_from_slice(&3u32.to_le_bytes());
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&[7u8; 32]);
        blob.extend_from_slice(&[9u8; 32]);
        blob.extend_from_slice(&[0u8; 8]);

        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let encoded = STANDARD.encode(&blob);

        let result = json!({ "value": { "data": [encoded, "base64"] } });
        let err = nonce_state_from_account_info("NonceAcc123", "auth", &result).unwrap_err();
        assert!(err.contains("Versions"), "{err}");

        // Initialized but not Current... this is still refused because the
        // version discriminant is not Current.
        let mut blob2 = Vec::new();
        blob2.extend_from_slice(&1u32.to_le_bytes());
        blob2.extend_from_slice(&0u32.to_le_bytes()); // not Initialized
        blob2.extend_from_slice(&[7u8; 32]);
        blob2.extend_from_slice(&[9u8; 32]);
        blob2.extend_from_slice(&[0u8; 8]);
        let encoded2 = STANDARD.encode(&blob2);
        let result2 = json!({ "value": { "data": [encoded2, "base64"] } });
        let err2 = nonce_state_from_account_info("NonceAcc123", "auth", &result2).unwrap_err();
        assert!(err2.contains("State"), "{err2}");

        // No data at all.
        let empty = json!({ "value": { "data": null } });
        assert!(
            nonce_state_from_account_info("NonceAcc123", "auth", &empty).is_err()
        );
    }
}
