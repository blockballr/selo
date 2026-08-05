//! SOL transfer construction: keypair handling, legacy message
//! serialization, signing, and the RPC requests around them.
//!
//! The Solana SDK does not build for the wasm32-wasip2 component target,
//! so the legacy transaction wire format is implemented here directly.
//! It is small and stable: a three-byte header, shortvec-prefixed account
//! keys, the recent blockhash, and shortvec-prefixed instructions. The
//! system program transfer instruction is a u32 discriminant (2) followed
//! by a u64 lamport amount, both little endian.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use crate::address::validate_pubkey;

/// The system program id: 32 zero bytes / standard base58 representation.
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// A parsed signing keypair plus its public key.
pub struct Keypair {
    signing: SigningKey,
}

impl Keypair {
    /// Parse a keypair from operator config. Two formats are accepted:
    /// the solana-cli id.json content (a JSON array of 64 bytes) and a
    /// base58 string of the 64-byte secret key as wallet apps export it.
    pub fn from_config_value(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("keypair value is empty".to_string());
        }
        let bytes: Vec<u8> = if trimmed.starts_with('[') {
            serde_json::from_str(trimmed)
                .map_err(|e| format!("keypair JSON array did not parse: {e}"))?
        } else {
            bs58::decode(trimmed)
                .into_vec()
                .map_err(|_| "keypair is neither a JSON array nor valid base58".to_string())?
        };
        let bytes: [u8; 64] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| format!("keypair is {} bytes, expected 64", v.len()))?;
        let signing = SigningKey::from_keypair_bytes(&bytes)
            .map_err(|e| format!("keypair bytes are not a valid ed25519 keypair: {e}"))?;
        Ok(Self { signing })
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn public_key_base58(&self) -> String {
        bs58::encode(self.public_key_bytes()).into_string()
    }

    /// Sign raw message bytes. Solana signs the serialized message
    /// directly, with no pre-hashing or domain separator, so this is
    /// usable for any transaction whose message bytes are known,
    /// including ones built elsewhere.
    pub fn sign_message(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// Encode a length as a Solana shortvec (compact-u16) prefix.
pub fn shortvec(n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(3);
    let mut val = n;
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if val == 0 {
            return out;
        }
    }
}

/// Build the legacy message bytes for a system transfer of `lamports`
/// from `from` to `to`, on `blockhash_b58`, with no priority fee.
pub fn build_transfer_message(
    from: &[u8; 32],
    to: &str,
    lamports: u64,
    blockhash_b58: &str,
) -> Result<Vec<u8>, String> {
    build_transfer_message_with_priority(from, to, lamports, blockhash_b58, None)
}

/// A priority fee bid: a price per compute unit and the unit ceiling it
/// is charged against. Both halves matter, since the fee paid is the
/// price multiplied by the limit requested, not by the units used.
#[derive(Debug, Clone, Copy)]
pub struct PriorityFee {
    pub micro_lamports_per_cu: u64,
    pub compute_units: u32,
}

/// Build a transfer message, optionally prefixed with compute budget
/// instructions that bid for block inclusion.
pub fn build_transfer_message_with_priority(
    from: &[u8; 32],
    to: &str,
    lamports: u64,
    blockhash_b58: &str,
    priority: Option<PriorityFee>,
) -> Result<Vec<u8>, String> {
    let to_addr = validate_pubkey(to)?;
    let to_bytes: [u8; 32] = bs58::decode(&to_addr)
        .into_vec()
        .map_err(|_| "unreachable: validated address failed to decode".to_string())?
        .try_into()
        .map_err(|_| "unreachable: validated address is not 32 bytes".to_string())?;
    if &to_bytes == from {
        return Err("source and destination are the same address".to_string());
    }
    let blockhash: [u8; 32] = bs58::decode(blockhash_b58.trim())
        .into_vec()
        .map_err(|_| format!("blockhash '{blockhash_b58}' is not valid base58"))?
        .try_into()
        .map_err(|_| format!("blockhash '{blockhash_b58}' does not decode to 32 bytes"))?;
    if lamports == 0 {
        return Err("transfer amount is zero lamports".to_string());
    }

    let compute_budget = priority
        .map(|_| crate::address::decode_pubkey(crate::priority::COMPUTE_BUDGET_PROGRAM_ID))
        .transpose()?;

    let mut msg = Vec::with_capacity(160);
    // Header: one signature, no readonly signed, and one readonly
    // unsigned per program account present.
    let readonly_unsigned = if compute_budget.is_some() { 2 } else { 1 };
    msg.extend_from_slice(&[1, 0, readonly_unsigned]);

    let key_count = if compute_budget.is_some() { 4 } else { 3 };
    msg.extend_from_slice(&shortvec(key_count));
    msg.extend_from_slice(from);
    msg.extend_from_slice(&to_bytes);
    msg.extend_from_slice(&SYSTEM_PROGRAM_ID);
    if let Some(cb) = &compute_budget {
        msg.extend_from_slice(cb);
    }
    msg.extend_from_slice(&blockhash);

    let instruction_count = if priority.is_some() { 3 } else { 1 };
    msg.extend_from_slice(&shortvec(instruction_count));

    if let Some(p) = priority {
        let cb_index = 3u8;
        for data in [
            crate::priority::set_compute_unit_limit_data(p.compute_units),
            crate::priority::set_compute_unit_price_data(p.micro_lamports_per_cu),
        ] {
            msg.push(cb_index);
            msg.extend_from_slice(&shortvec(0));
            msg.extend_from_slice(&shortvec(data.len()));
            msg.extend_from_slice(&data);
        }
    }

    // Transfer: system program, accounts [payer, destination], data is
    // the transfer discriminant (u32 = 2) then lamports (u64), little
    // endian.
    msg.push(2);
    msg.extend_from_slice(&shortvec(2));
    msg.extend_from_slice(&[0, 1]);
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    msg.extend_from_slice(&shortvec(data.len()));
    msg.extend_from_slice(&data);
    Ok(msg)
}

/// Sign `message` and assemble the full transaction, base64 encoded for
/// the sendTransaction wire format.
pub fn sign_and_encode(keypair: &Keypair, message: &[u8]) -> String {
    let signature = keypair.signing.sign(message);
    let mut tx = Vec::with_capacity(1 + 64 + message.len());
    tx.extend_from_slice(&shortvec(1));
    tx.extend_from_slice(&signature.to_bytes());
    tx.extend_from_slice(message);
    BASE64.encode(tx)
}

/// Build a `getLatestBlockhash` request.
pub fn blockhash_request() -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestBlockhash",
        "params": [{ "commitment": "finalized" }]
    })
    .to_string()
}

/// Parse a `getLatestBlockhash` response into the blockhash string.
pub fn parse_blockhash(body: &str) -> Result<String, String> {
    crate::rpc::parse_result_value(body)?
        .pointer("/value/blockhash")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "getLatestBlockhash result missing value.blockhash".to_string())
}

/// Build a `sendTransaction` request for a base64-encoded transaction.
pub fn send_request(tx_base64: &str) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": [tx_base64, { "encoding": "base64" }]
    })
    .to_string()
}

/// Parse a `sendTransaction` response into the transaction signature.
pub fn parse_send(body: &str) -> Result<String, String> {
    crate::rpc::parse_result_value(body)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "sendTransaction result is not a signature string".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn test_keypair() -> Keypair {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        Keypair { signing }
    }

    fn keypair_bytes(kp: &Keypair) -> [u8; 64] {
        kp.signing.to_keypair_bytes()
    }

    const DEST: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const BLOCKHASH: &str = "So11111111111111111111111111111111111111112";

    #[test]
    fn shortvec_matches_reference_encoding() {
        assert_eq!(shortvec(0), vec![0]);
        assert_eq!(shortvec(5), vec![5]);
        assert_eq!(shortvec(0x7f), vec![0x7f]);
        assert_eq!(shortvec(0x80), vec![0x80, 0x01]);
        assert_eq!(shortvec(0x3fff), vec![0xff, 0x7f]);
        assert_eq!(shortvec(0x4000), vec![0x80, 0x80, 0x01]);
    }

    #[test]
    fn keypair_roundtrips_both_config_formats() {
        let kp = test_keypair();
        let bytes = keypair_bytes(&kp);

        let as_json = serde_json::to_string(&bytes.to_vec()).unwrap();
        let from_json = Keypair::from_config_value(&as_json).unwrap();
        assert_eq!(from_json.public_key_base58(), kp.public_key_base58());

        let as_b58 = bs58::encode(bytes).into_string();
        let from_b58 = Keypair::from_config_value(&as_b58).unwrap();
        assert_eq!(from_b58.public_key_base58(), kp.public_key_base58());
    }

    #[test]
    fn keypair_rejects_bad_input() {
        assert!(Keypair::from_config_value("").is_err());
        assert!(Keypair::from_config_value("[1,2,3]").is_err());
        assert!(Keypair::from_config_value("zz not base58 !!").is_err());
    }

    #[test]
    fn message_layout_is_exact() {
        let kp = test_keypair();
        let from = kp.public_key_bytes();
        let msg = build_transfer_message(&from, DEST, 42, BLOCKHASH).unwrap();

        assert_eq!(&msg[0..3], &[1, 0, 1]);
        assert_eq!(msg[3], 3);
        assert_eq!(&msg[4..36], &from);
        let dest_bytes = bs58::decode(DEST).into_vec().unwrap();
        assert_eq!(&msg[36..68], dest_bytes.as_slice());
        assert_eq!(&msg[68..100], &SYSTEM_PROGRAM_ID);
        let bh = bs58::decode(BLOCKHASH).into_vec().unwrap();
        assert_eq!(&msg[100..132], bh.as_slice());
        assert_eq!(&msg[132..137], &[1, 2, 2, 0, 1]);
        assert_eq!(msg[137], 12);
        assert_eq!(&msg[138..142], &2u32.to_le_bytes());
        assert_eq!(&msg[142..150], &42u64.to_le_bytes());
        assert_eq!(msg.len(), 150);
    }

    #[test]
    fn rejects_self_transfer_and_zero_amount() {
        let kp = test_keypair();
        let from = kp.public_key_bytes();
        let self_addr = kp.public_key_base58();
        assert!(build_transfer_message(&from, &self_addr, 42, BLOCKHASH).is_err());
        assert!(build_transfer_message(&from, DEST, 0, BLOCKHASH).is_err());
    }

    #[test]
    fn signed_transaction_verifies() {
        let kp = test_keypair();
        let from = kp.public_key_bytes();
        let msg = build_transfer_message(&from, DEST, 42, BLOCKHASH).unwrap();
        let encoded = sign_and_encode(&kp, &msg);

        let tx = BASE64.decode(encoded).unwrap();
        assert_eq!(tx[0], 1);
        let sig = ed25519_dalek::Signature::from_bytes(tx[1..65].try_into().unwrap());
        let message = &tx[65..];
        assert_eq!(message, msg.as_slice());
        kp.signing.verifying_key().verify(message, &sig).unwrap();
    }

    #[test]
    fn blockhash_request_and_parse() {
        let req = blockhash_request();
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "getLatestBlockhash");

        let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},
            "value":{"blockhash":"9sHcv6xwn9YkB8nxTUGKDwPwNnmqVp5oJygUpKSHhHzk",
            "lastValidBlockHeight":100}},"id":1}"#;
        assert_eq!(
            parse_blockhash(body).unwrap(),
            "9sHcv6xwn9YkB8nxTUGKDwPwNnmqVp5oJygUpKSHhHzk"
        );
    }

    #[test]
    fn send_request_and_parse() {
        let req = send_request("dGVzdA==");
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "sendTransaction");
        assert_eq!(v["params"][1]["encoding"], "base64");

        let body = r#"{"jsonrpc":"2.0","result":"5Sig111","id":1}"#;
        assert_eq!(parse_send(body).unwrap(), "5Sig111");

        let err = r#"{"jsonrpc":"2.0","error":{"code":-32002,
            "message":"Transaction simulation failed: insufficient funds"},"id":1}"#;
        let msg = parse_send(err).unwrap_err();
        assert!(msg.contains("insufficient funds"));
    }

    #[test]
    fn priority_variant_layout_is_exact() {
        let kp = test_keypair();
        let from = kp.public_key_bytes();
        let p = PriorityFee {
            micro_lamports_per_cu: 50_000,
            compute_units: 1_000,
        };
        let msg =
            build_transfer_message_with_priority(&from, DEST, 42, BLOCKHASH, Some(p)).unwrap();

        assert_eq!(&msg[0..3], &[1, 0, 2]);
        assert_eq!(msg[3], 4, "four account keys");
        let cb = crate::address::decode_pubkey(crate::priority::COMPUTE_BUDGET_PROGRAM_ID).unwrap();
        assert_eq!(&msg[100..132], &cb);
        let ix_start = 4 + 4 * 32 + 32;
        assert_eq!(msg[ix_start], 3);
        assert_eq!(&msg[ix_start + 1..ix_start + 4], &[3, 0, 5]);
        assert_eq!(msg[ix_start + 4], 2, "SetComputeUnitLimit");
    }

    #[test]
    fn priority_absent_matches_plain_builder() {
        let kp = test_keypair();
        let from = kp.public_key_bytes();
        let plain = build_transfer_message(&from, DEST, 42, BLOCKHASH).unwrap();
        let none = build_transfer_message_with_priority(&from, DEST, 42, BLOCKHASH, None).unwrap();
        assert_eq!(plain, none);
        assert_eq!(plain.len(), 150);
    }

    #[test]
    fn priority_variant_still_validates_inputs() {
        let kp = test_keypair();
        let from = kp.public_key_bytes();
        let p = PriorityFee {
            micro_lamports_per_cu: 1,
            compute_units: 1,
        };
        assert!(build_transfer_message_with_priority(&from, DEST, 0, BLOCKHASH, Some(p)).is_err());
        assert!(
            build_transfer_message_with_priority(&from, "bad!", 1, BLOCKHASH, Some(p)).is_err()
        );
    }
}
