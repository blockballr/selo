//! Versioned (v0) transaction parsing and signing.
//!
//! Signing a blob an aggregator built is signing whatever they put in it,
//! so this parses far enough to check the fee payer is our wallet and that
//! ours is the only signature asked for.

use crate::address::encode_pubkey;

/// A parsed shortvec length and the number of bytes it occupied.
fn read_shortvec(bytes: &[u8], at: usize) -> Result<(usize, usize), String> {
    let mut value = 0usize;
    let mut consumed = 0usize;
    loop {
        let byte = *bytes
            .get(at + consumed)
            .ok_or_else(|| "truncated shortvec length".to_string())?;
        value |= ((byte & 0x7f) as usize) << (consumed * 7);
        consumed += 1;
        if byte & 0x80 == 0 {
            return Ok((value, consumed));
        }
        if consumed > 3 {
            return Err("shortvec length is too long".to_string());
        }
    }
}

/// What a caller needs to know before signing a transaction it did not
/// build itself.
#[derive(Debug, Clone)]
pub struct ParsedTransaction {
    /// None for a legacy transaction, Some(0) for v0.
    pub version: Option<u8>,
    pub required_signatures: u8,
    /// Byte range of the message inside the full transaction. This is
    /// exactly what gets signed.
    pub message_offset: usize,
    pub static_account_keys: Vec<[u8; 32]>,
    pub instruction_count: usize,
    pub address_table_lookup_count: usize,
}

impl ParsedTransaction {
    /// The fee payer is always the first account key.
    pub fn fee_payer(&self) -> Option<[u8; 32]> {
        self.static_account_keys.first().copied()
    }
}

/// Parse a serialized transaction: the signature array followed by the
/// message. Only as much of the message is decoded as is needed to
/// verify it before signing.
pub fn parse_transaction(tx: &[u8]) -> Result<ParsedTransaction, String> {
    let (sig_count, sig_len_bytes) = read_shortvec(tx, 0)?;
    let message_offset = sig_len_bytes + sig_count * 64;
    if tx.len() <= message_offset {
        return Err("transaction has no message after its signatures".to_string());
    }

    let msg = &tx[message_offset..];
    // A high bit on the first message byte marks a versioned message.
    // Legacy messages start with num_required_signatures, which is a
    // small count and so never has that bit set.
    let (version, mut cursor) = if msg[0] & 0x80 != 0 {
        (Some(msg[0] & 0x7f), 1usize)
    } else {
        (None, 0usize)
    };
    if let Some(v) = version {
        if v != 0 {
            return Err(format!(
                "transaction uses message version {v}, which this plugin cannot verify"
            ));
        }
    }

    let header = msg
        .get(cursor..cursor + 3)
        .ok_or_else(|| "truncated message header".to_string())?;
    let required_signatures = header[0];
    cursor += 3;

    let (key_count, consumed) = read_shortvec(msg, cursor)?;
    cursor += consumed;
    let mut static_account_keys = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        let key: [u8; 32] = msg
            .get(cursor..cursor + 32)
            .ok_or_else(|| "truncated account key".to_string())?
            .try_into()
            .map_err(|_| "account key is not 32 bytes".to_string())?;
        static_account_keys.push(key);
        cursor += 32;
    }

    // Recent blockhash.
    cursor += 32;
    if cursor > msg.len() {
        return Err("truncated recent blockhash".to_string());
    }

    let (instruction_count, consumed) = read_shortvec(msg, cursor)?;
    cursor += consumed;
    for _ in 0..instruction_count {
        // program id index
        cursor += 1;
        let (accounts, consumed) = read_shortvec(msg, cursor)?;
        cursor += consumed + accounts;
        let (data_len, consumed) = read_shortvec(msg, cursor)?;
        cursor += consumed + data_len;
        if cursor > msg.len() {
            return Err("truncated instruction".to_string());
        }
    }

    // Legacy messages stop here; v0 messages carry lookup tables.
    let address_table_lookup_count = if version.is_some() {
        let (count, consumed) = read_shortvec(msg, cursor)?;
        cursor += consumed;
        for _ in 0..count {
            cursor += 32; // lookup table account
            let (writable, consumed) = read_shortvec(msg, cursor)?;
            cursor += consumed + writable;
            let (readonly, consumed) = read_shortvec(msg, cursor)?;
            cursor += consumed + readonly;
            if cursor > msg.len() {
                return Err("truncated address table lookup".to_string());
            }
        }
        count
    } else {
        0
    };

    // A correct parse lands exactly on the end of the message. Leftover
    // bytes mean the structure was misread, which is the failure mode
    // most likely to end with a signature on something unexpected.
    if cursor != msg.len() {
        return Err(format!(
            "transaction did not parse cleanly: {} bytes left over after the message, so its structure is not what this plugin expects",
            msg.len().saturating_sub(cursor)
        ));
    }

    Ok(ParsedTransaction {
        version,
        required_signatures,
        message_offset,
        static_account_keys,
        instruction_count,
        address_table_lookup_count,
    })
}

/// Verify a transaction built elsewhere is safe for us to sign, then
/// sign it in place.
///
/// The checks are the whole point. A transaction whose fee payer is not
/// us, or which wants signatures we cannot supply, is refused rather
/// than signed and sent.
pub fn verify_and_sign(
    tx: &mut [u8],
    signer_pubkey: &[u8; 32],
    sign: impl FnOnce(&[u8]) -> [u8; 64],
) -> Result<ParsedTransaction, String> {
    let parsed = parse_transaction(tx)?;

    if parsed.required_signatures != 1 {
        return Err(format!(
            "transaction requires {} signatures but this plugin can only provide \
             the wallet's own, so it will not sign it",
            parsed.required_signatures
        ));
    }
    let fee_payer = parsed
        .fee_payer()
        .ok_or_else(|| "transaction has no account keys".to_string())?;
    if &fee_payer != signer_pubkey {
        return Err(format!(
            "refusing to sign: the transaction's fee payer is {} but the configured \
             wallet is {}",
            encode_pubkey(&fee_payer),
            encode_pubkey(signer_pubkey)
        ));
    }

    let signature = sign(&tx[parsed.message_offset..]);
    let slot = tx
        .get_mut(1..65)
        .ok_or_else(|| "transaction has no room for a signature".to_string())?;
    slot.copy_from_slice(&signature);
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shortvec(mut n: u16) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if n == 0 {
                return out;
            }
        }
    }

    /// Build a minimal v0 transaction with one instruction and one
    /// address table lookup.
    fn sample_v0(fee_payer: [u8; 32], required_sigs: u8) -> Vec<u8> {
        let mut msg = vec![0x80]; // v0
        msg.extend_from_slice(&[required_sigs, 0, 1]);
        msg.extend_from_slice(&shortvec(2));
        msg.extend_from_slice(&fee_payer);
        msg.extend_from_slice(&[9u8; 32]);
        msg.extend_from_slice(&[7u8; 32]); // blockhash
        msg.extend_from_slice(&shortvec(1));
        msg.push(1); // program index
        msg.extend_from_slice(&shortvec(1));
        msg.push(0);
        msg.extend_from_slice(&shortvec(3));
        msg.extend_from_slice(&[1, 2, 3]);
        // one lookup table: account, 2 writable, 1 readonly
        msg.extend_from_slice(&shortvec(1));
        msg.extend_from_slice(&[5u8; 32]);
        msg.extend_from_slice(&shortvec(2));
        msg.extend_from_slice(&[3, 4]);
        msg.extend_from_slice(&shortvec(1));
        msg.extend_from_slice(&[6]);

        let mut tx = shortvec(required_sigs as u16);
        tx.extend(std::iter::repeat(0u8).take(required_sigs as usize * 64));
        tx.extend_from_slice(&msg);
        tx
    }

    #[test]
    fn shortvec_reader_matches_writer() {
        for n in [0u16, 1, 0x7f, 0x80, 0x3fff, 0x4000] {
            let encoded = shortvec(n);
            let (value, consumed) = read_shortvec(&encoded, 0).unwrap();
            assert_eq!(value, n as usize);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn parses_v0_structure() {
        let payer = [1u8; 32];
        let tx = sample_v0(payer, 1);
        let p = parse_transaction(&tx).unwrap();
        assert_eq!(p.version, Some(0));
        assert_eq!(p.required_signatures, 1);
        assert_eq!(p.static_account_keys.len(), 2);
        assert_eq!(p.fee_payer(), Some(payer));
        assert_eq!(p.instruction_count, 1);
        assert_eq!(p.address_table_lookup_count, 1);
        // Message starts right after one signature.
        assert_eq!(p.message_offset, 1 + 64);
    }

    #[test]
    fn signs_and_places_signature() {
        let payer = [1u8; 32];
        let mut tx = sample_v0(payer, 1);
        let expected = [0xABu8; 64];
        let mut signed_bytes = Vec::new();
        let parsed = verify_and_sign(&mut tx, &payer, |msg| {
            signed_bytes = msg.to_vec();
            expected
        })
        .unwrap();
        // The signed bytes are exactly the message.
        assert_eq!(signed_bytes, tx[parsed.message_offset..].to_vec());
        assert_eq!(&tx[1..65], &expected);
    }

    #[test]
    fn refuses_when_fee_payer_is_not_us() {
        let mut tx = sample_v0([1u8; 32], 1);
        let err = verify_and_sign(&mut tx, &[2u8; 32], |_| [0u8; 64]).unwrap_err();
        assert!(err.contains("refusing to sign"));
        assert!(err.contains("fee payer"));
    }

    #[test]
    fn refuses_multi_signer_transactions() {
        let payer = [1u8; 32];
        let mut tx = sample_v0(payer, 2);
        let err = verify_and_sign(&mut tx, &payer, |_| [0u8; 64]).unwrap_err();
        assert!(err.contains("requires 2 signatures"));
    }

    #[test]
    fn rejects_unknown_message_version() {
        let mut tx = sample_v0([1u8; 32], 1);
        let offset = 1 + 64;
        tx[offset] = 0x81; // version 1
        let err = parse_transaction(&tx).unwrap_err();
        assert!(err.contains("version 1"));
    }

    #[test]
    fn rejects_truncated_input() {
        let tx = sample_v0([1u8; 32], 1);
        for cut in [0, 10, 70, 100] {
            assert!(parse_transaction(&tx[..cut.min(tx.len())]).is_err());
        }
    }

    #[test]
    fn parses_legacy_transaction_without_version() {
        // A legacy message begins with the header directly.
        let mut msg = vec![1u8, 0, 1];
        msg.extend_from_slice(&shortvec(1));
        msg.extend_from_slice(&[4u8; 32]);
        msg.extend_from_slice(&[7u8; 32]);
        msg.extend_from_slice(&shortvec(0));
        let mut tx = shortvec(1);
        tx.extend(std::iter::repeat(0u8).take(64));
        tx.extend_from_slice(&msg);

        let p = parse_transaction(&tx).unwrap();
        assert_eq!(p.version, None);
        assert_eq!(p.address_table_lookup_count, 0);
        assert_eq!(p.fee_payer(), Some([4u8; 32]));
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut tx = sample_v0([1u8; 32], 1);
        tx.push(0xFF);
        let err = parse_transaction(&tx).unwrap_err();
        assert!(err.contains("left over"));
    }
}
