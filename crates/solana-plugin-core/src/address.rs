//! Base58 public key validation.

/// Validate that `s` is a plausible Solana public key: base58, 32 bytes.
///
/// Returns the canonical trimmed form on success so callers never embed
/// stray whitespace into an RPC request.
pub fn validate_pubkey(s: &str) -> Result<String, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("address is empty".to_string());
    }
    let bytes = bs58::decode(trimmed)
        .into_vec()
        .map_err(|_| format!("'{trimmed}' is not valid base58"))?;
    if bytes.len() != 32 {
        return Err(format!(
            "'{trimmed}' decodes to {} bytes, a Solana public key is 32",
            bytes.len()
        ));
    }
    Ok(trimmed.to_string())
}


/// Decode a base58 public key to its 32 raw bytes.
pub fn decode_pubkey(s: &str) -> Result<[u8; 32], String> {
    let valid = validate_pubkey(s)?;
    bs58::decode(&valid)
        .into_vec()
        .map_err(|_| "unreachable: validated address failed to decode".to_string())?
        .try_into()
        .map_err(|_| "unreachable: validated address is not 32 bytes".to_string())
}

/// Encode 32 raw bytes as a base58 public key.
pub fn encode_pubkey(bytes: &[u8; 32]) -> String {
    bs58::encode(bytes).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // The SPL Token program id, a well-known valid pubkey.
    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    #[test]
    fn accepts_known_pubkey() {
        assert_eq!(validate_pubkey(TOKEN_PROGRAM).unwrap(), TOKEN_PROGRAM);
    }

    #[test]
    fn trims_whitespace() {
        let padded = format!("  {TOKEN_PROGRAM}\n");
        assert_eq!(validate_pubkey(&padded).unwrap(), TOKEN_PROGRAM);
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_pubkey("   ").is_err());
    }

    #[test]
    fn rejects_non_base58() {
        assert!(validate_pubkey("not!valid@base58").is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        // Valid base58 but far too short to be 32 bytes.
        assert!(validate_pubkey("abc").is_err());
    }

    #[test]
    fn decode_encode_roundtrip() {
        let bytes = decode_pubkey(TOKEN_PROGRAM).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(encode_pubkey(&bytes), TOKEN_PROGRAM);
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert!(decode_pubkey("nope!").is_err());
    }
}
