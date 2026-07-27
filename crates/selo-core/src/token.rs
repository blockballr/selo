//! SPL token transfers.
//!
//! Tokens live in an account owned by the wallet, so a transfer derives
//! both sides and creates the recipient's if it does not exist.
//!
//! `TransferChecked` rather than `Transfer`: it carries the mint decimals,
//! so a mismatch fails the transaction instead of sending a thousand times
//! too much.

use serde_json::{json, Value};

use crate::address::{decode_pubkey, encode_pubkey};
use crate::pda::{associated_token_address, ASSOCIATED_TOKEN_PROGRAM_ID};
use crate::rpc::{parse_result_value, TOKEN_PROGRAM_ID};
use crate::transfer::{shortvec, SYSTEM_PROGRAM_ID};

/// `TransferChecked` in the SPL token instruction enum.
const IX_TRANSFER_CHECKED: u8 = 12;

/// `CreateIdempotent` in the associated token account program. It
/// succeeds whether or not the account already exists, which removes a
/// race between checking and creating.
const IX_CREATE_IDEMPOTENT: u8 = 1;

/// Everything needed to build a token transfer, resolved ahead of time.
pub struct TokenTransfer {
    pub owner: [u8; 32],
    pub source_ata: [u8; 32],
    pub destination_owner: [u8; 32],
    pub destination_ata: [u8; 32],
    pub mint: [u8; 32],
    pub amount: u64,
    pub decimals: u8,
    /// Include a create-if-missing instruction for the destination.
    pub create_destination: bool,
}

impl TokenTransfer {
    /// Resolve both token accounts for a transfer. Amount is in the
    /// mint's base units, matching what the token program expects.
    pub fn resolve(
        owner: &[u8; 32],
        destination_owner: &str,
        mint: &str,
        amount: u64,
        decimals: u8,
        create_destination: bool,
    ) -> Result<Self, String> {
        if amount == 0 {
            return Err("transfer amount is zero".to_string());
        }
        let mint_bytes = decode_pubkey(mint)?;
        let dest_owner = decode_pubkey(destination_owner)?;
        let token_program = decode_pubkey(TOKEN_PROGRAM_ID)?;
        if &dest_owner == owner {
            return Err("source and destination wallet are the same".to_string());
        }
        Ok(Self {
            owner: *owner,
            source_ata: associated_token_address(owner, &mint_bytes, &token_program)?,
            destination_owner: dest_owner,
            destination_ata: associated_token_address(&dest_owner, &mint_bytes, &token_program)?,
            mint: mint_bytes,
            amount,
            decimals,
            create_destination,
        })
    }

    pub fn source_ata_base58(&self) -> String {
        encode_pubkey(&self.source_ata)
    }

    pub fn destination_ata_base58(&self) -> String {
        encode_pubkey(&self.destination_ata)
    }

    /// Serialize the legacy message for this transfer.
    ///
    /// Account order follows the required grouping: writable signed,
    /// readonly signed, writable unsigned, then readonly unsigned. The
    /// header counts each group so the runtime can reconstruct which
    /// accounts are writable without a separate table.
    pub fn build_message(&self, blockhash_b58: &str) -> Result<Vec<u8>, String> {
        let blockhash: [u8; 32] = bs58::decode(blockhash_b58.trim())
            .into_vec()
            .map_err(|_| format!("blockhash '{blockhash_b58}' is not valid base58"))?
            .try_into()
            .map_err(|_| format!("blockhash '{blockhash_b58}' does not decode to 32 bytes"))?;

        let token_program = decode_pubkey(TOKEN_PROGRAM_ID)?;
        let ata_program = decode_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID)?;

        // Indices differ between the two shapes, so name them once and
        // build the instructions from the names.
        let (keys, i_owner, i_source, i_dest, i_mint, i_token, readonly_unsigned): (
            Vec<[u8; 32]>,
            u8,
            u8,
            u8,
            u8,
            u8,
            u8,
        ) = if self.create_destination {
            (
                vec![
                    self.owner,
                    self.source_ata,
                    self.destination_ata,
                    self.destination_owner,
                    self.mint,
                    token_program,
                    SYSTEM_PROGRAM_ID,
                    ata_program,
                ],
                0,
                1,
                2,
                4,
                5,
                5,
            )
        } else {
            (
                vec![
                    self.owner,
                    self.source_ata,
                    self.destination_ata,
                    self.mint,
                    token_program,
                ],
                0,
                1,
                2,
                3,
                4,
                2,
            )
        };

        let mut msg = Vec::with_capacity(3 + 1 + keys.len() * 32 + 32 + 64);
        msg.extend_from_slice(&[1, 0, readonly_unsigned]);
        msg.extend_from_slice(&shortvec(keys.len() as u16));
        for key in &keys {
            msg.extend_from_slice(key);
        }
        msg.extend_from_slice(&blockhash);

        let instruction_count = if self.create_destination { 2 } else { 1 };
        msg.extend_from_slice(&shortvec(instruction_count));

        if self.create_destination {
            // CreateIdempotent: payer, ata, owner, mint, system, token.
            let i_system = 6u8;
            let i_ata_program = 7u8;
            msg.push(i_ata_program);
            msg.extend_from_slice(&shortvec(6));
            msg.extend_from_slice(&[i_owner, i_dest, 3, i_mint, i_system, i_token]);
            msg.extend_from_slice(&shortvec(1));
            msg.push(IX_CREATE_IDEMPOTENT);
        }

        // TransferChecked: source, mint, destination, owner.
        msg.push(i_token);
        msg.extend_from_slice(&shortvec(4));
        msg.extend_from_slice(&[i_source, i_mint, i_dest, i_owner]);
        let mut data = Vec::with_capacity(10);
        data.push(IX_TRANSFER_CHECKED);
        data.extend_from_slice(&self.amount.to_le_bytes());
        data.push(self.decimals);
        msg.extend_from_slice(&shortvec(data.len() as u16));
        msg.extend_from_slice(&data);

        Ok(msg)
    }
}

/// Build a `getAccountInfo` request with parsed encoding.
pub fn account_info_request(address: &str) -> Result<String, String> {
    let addr = crate::address::validate_pubkey(address)?;
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAccountInfo",
        "params": [addr, { "encoding": "jsonParsed" }]
    })
    .to_string())
}

/// Read a mint's decimals from a parsed `getAccountInfo` response.
///
/// Decimals must come from the chain rather than a hardcoded table:
/// `TransferChecked` fails if they disagree with the mint, and that is
/// the guard that makes this transfer safe.
pub fn parse_mint_decimals(body: &str) -> Result<u8, String> {
    let value = parse_result_value(body)?;
    let info = value
        .pointer("/value/data/parsed/info")
        .ok_or_else(|| "address is not a parseable mint account".to_string())?;
    let kind = value
        .pointer("/value/data/parsed/type")
        .and_then(Value::as_str)
        .unwrap_or("");
    if kind != "mint" {
        return Err(format!(
            "address is a '{kind}' account, not a token mint"
        ));
    }
    info.get("decimals")
        .and_then(Value::as_u64)
        .map(|d| d as u8)
        .ok_or_else(|| "mint account has no decimals field".to_string())
}

/// Whether a `getAccountInfo` response describes an existing account.
pub fn parse_account_exists(body: &str) -> Result<bool, String> {
    let value = parse_result_value(body)?;
    Ok(!value
        .get("value")
        .map(|v| v.is_null())
        .unwrap_or(true))
}

/// Read the token balance out of a parsed token account response.
pub fn parse_token_account_amount(body: &str) -> Result<u64, String> {
    let value = parse_result_value(body)?;
    value
        .pointer("/value/data/parsed/info/tokenAmount/amount")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "token account has no readable amount".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const DEST: &str = "GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const BLOCKHASH: &str = "So11111111111111111111111111111111111111112";

    fn transfer(create: bool) -> TokenTransfer {
        let owner = decode_pubkey(OWNER).unwrap();
        TokenTransfer::resolve(&owner, DEST, USDC, 2_500_000, 6, create).unwrap()
    }

    #[test]
    fn resolves_both_token_accounts_to_mainnet_values() {
        let t = transfer(false);
        // Both are the mainnet-verified ATAs from the pda test vectors.
        assert_eq!(
            t.source_ata_base58(),
            "FGETo8T8wMcN2wCjav8VK6eh3dLk63evNDPxzLSJra8B"
        );
        assert_eq!(
            t.destination_ata_base58(),
            "6u6tm3d9Vf4QUDdbtMaV21qsmPHorJebdyDT6ZJ9h5JY"
        );
    }

    #[test]
    fn rejects_zero_and_self_transfer() {
        let owner = decode_pubkey(OWNER).unwrap();
        assert!(TokenTransfer::resolve(&owner, DEST, USDC, 0, 6, false).is_err());
        assert!(TokenTransfer::resolve(&owner, OWNER, USDC, 1, 6, false).is_err());
    }

    #[test]
    fn simple_message_layout_is_exact() {
        let t = transfer(false);
        let msg = t.build_message(BLOCKHASH).unwrap();

        // 1 signature, 0 readonly signed, 2 readonly unsigned.
        assert_eq!(&msg[0..3], &[1, 0, 2]);
        assert_eq!(msg[3], 5, "five account keys");
        assert_eq!(&msg[4..36], &t.owner);
        assert_eq!(&msg[36..68], &t.source_ata);
        assert_eq!(&msg[68..100], &t.destination_ata);
        assert_eq!(&msg[100..132], &t.mint);
        assert_eq!(&msg[132..164], decode_pubkey(TOKEN_PROGRAM_ID).unwrap());
        // blockhash
        assert_eq!(&msg[164..196], bs58::decode(BLOCKHASH).into_vec().unwrap().as_slice());
        // One instruction: count, program index 4, four accounts
        // [source, mint, dest, owner], then a 10 byte data blob.
        assert_eq!(&msg[196..203], &[1, 4, 4, 1, 3, 2, 0]);
        assert_eq!(msg[203], 10);
        assert_eq!(msg.len(), 214);
    }

    #[test]
    fn transfer_checked_data_encodes_amount_and_decimals() {
        let t = transfer(false);
        let msg = t.build_message(BLOCKHASH).unwrap();
        let data = &msg[msg.len() - 10..];
        assert_eq!(data[0], IX_TRANSFER_CHECKED);
        assert_eq!(&data[1..9], &2_500_000u64.to_le_bytes());
        assert_eq!(data[9], 6);
    }

    #[test]
    fn create_variant_adds_accounts_and_instruction() {
        let simple = transfer(false).build_message(BLOCKHASH).unwrap();
        let with_create = transfer(true).build_message(BLOCKHASH).unwrap();
        assert!(with_create.len() > simple.len());
        // 8 keys, 5 readonly unsigned.
        assert_eq!(&with_create[0..3], &[1, 0, 5]);
        assert_eq!(with_create[3], 8);
        // Two instructions now.
        let ix_start = 4 + 8 * 32 + 32;
        assert_eq!(with_create[ix_start], 2);
        // First is CreateIdempotent on the ATA program (index 7).
        assert_eq!(with_create[ix_start + 1], 7);
        assert_eq!(with_create[ix_start + 2], 6, "six accounts");
    }

    #[test]
    fn parses_mint_decimals() {
        let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{
            "data":{"parsed":{"info":{"decimals":6,"supply":"1","isInitialized":true},
            "type":"mint"},"program":"spl-token"},"owner":"Tokenkeg"}},"id":1}"#;
        assert_eq!(parse_mint_decimals(body).unwrap(), 6);
    }

    #[test]
    fn rejects_non_mint_account() {
        let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{
            "data":{"parsed":{"info":{"mint":"x"},"type":"account"},
            "program":"spl-token"},"owner":"Tokenkeg"}},"id":1}"#;
        let err = parse_mint_decimals(body).unwrap_err();
        assert!(err.contains("not a token mint"));
    }

    #[test]
    fn account_existence() {
        let missing = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":null},"id":1}"#;
        assert!(!parse_account_exists(missing).unwrap());
        let present = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{"lamports":1}},"id":1}"#;
        assert!(parse_account_exists(present).unwrap());
    }

    #[test]
    fn reads_token_balance() {
        let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{
            "data":{"parsed":{"info":{"tokenAmount":{"amount":"5000000","decimals":6}},
            "type":"account"}}}},"id":1}"#;
        assert_eq!(parse_token_account_amount(body).unwrap(), 5_000_000);
    }
}
