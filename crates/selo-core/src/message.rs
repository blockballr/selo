//! Generic legacy message compilation.
//!
//! `transfer` and `token` hand-index their accounts, which is fine at five
//! and a bug waiting to happen at ten. Callers here describe accounts by
//! meaning and this module derives the canonical ordering, merging
//! duplicates by the union of their flags.
//!
//! The regression test pins the output to the hand-built `token` layout,
//! which is itself confirmed against mainnet.

use crate::transfer::shortvec;

/// One account reference within an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountMeta {
    pub pubkey: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

impl AccountMeta {
    /// A writable, signing account.
    pub fn signer_writable(pubkey: [u8; 32]) -> Self {
        Self { pubkey, is_signer: true, is_writable: true }
    }

    /// A signing account that is only read.
    pub fn signer_readonly(pubkey: [u8; 32]) -> Self {
        Self { pubkey, is_signer: true, is_writable: false }
    }

    /// A writable account that does not sign, such as a PDA.
    pub fn writable(pubkey: [u8; 32]) -> Self {
        Self { pubkey, is_signer: false, is_writable: true }
    }

    /// An account that is only read, such as a program or a mint.
    pub fn readonly(pubkey: [u8; 32]) -> Self {
        Self { pubkey, is_signer: false, is_writable: false }
    }
}

/// One instruction: the program to invoke, the accounts it touches in
/// the order that program expects, and its opaque data payload.
#[derive(Debug, Clone)]
pub struct Instruction {
    pub program_id: [u8; 32],
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

/// Compile instructions into a serialized legacy message.
///
/// `fee_payer` is forced to index 0 as a writable signer, which the runtime
/// requires since it is debited for the fee. Program ids are appended as
/// readonly non-signers if not already referenced.
///
/// Returns the message bytes, which are exactly what gets signed.
pub fn compile_message(
    fee_payer: &[u8; 32],
    instructions: &[Instruction],
    blockhash_b58: &str,
) -> Result<Vec<u8>, String> {
    if instructions.is_empty() {
        return Err("a transaction needs at least one instruction".to_string());
    }

    let blockhash: [u8; 32] = bs58::decode(blockhash_b58.trim())
        .into_vec()
        .map_err(|_| format!("blockhash '{blockhash_b58}' is not valid base58"))?
        .try_into()
        .map_err(|_| format!("blockhash '{blockhash_b58}' does not decode to 32 bytes"))?;

    // Merge every reference to the same account, taking the union of
    // the flags. Insertion order is preserved so the sort below is
    // stable and the output is deterministic for a given input.
    let mut merged: Vec<AccountMeta> = Vec::new();
    let push = |meta: AccountMeta, merged: &mut Vec<AccountMeta>| {
        if let Some(existing) = merged.iter_mut().find(|m| m.pubkey == meta.pubkey) {
            existing.is_signer |= meta.is_signer;
            existing.is_writable |= meta.is_writable;
        } else {
            merged.push(meta);
        }
    };

    push(AccountMeta::signer_writable(*fee_payer), &mut merged);
    for ix in instructions {
        for meta in &ix.accounts {
            push(*meta, &mut merged);
        }
    }
    // Programs are read, never written, and never sign. If a program id
    // also appears as a regular account the union above already holds
    // the stronger flags, and this is a no-op.
    for ix in instructions {
        push(AccountMeta::readonly(ix.program_id), &mut merged);
    }

    // Canonical ordering. The fee payer is already first and sorts into
    // the writable-signer group, so a stable sort keeps it at index 0.
    fn rank(m: &AccountMeta) -> u8 {
        match (m.is_signer, m.is_writable) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 3,
        }
    }
    merged.sort_by_key(rank);

    if merged[0].pubkey != *fee_payer {
        // Unreachable given the stable sort, but a silent mismatch here
        // would mean the wrong account pays, so it is checked.
        return Err("fee payer did not land at account index 0".to_string());
    }

    let num_required_signatures = merged.iter().filter(|m| m.is_signer).count();
    let num_readonly_signed = merged.iter().filter(|m| m.is_signer && !m.is_writable).count();
    let num_readonly_unsigned = merged.iter().filter(|m| !m.is_signer && !m.is_writable).count();

    if num_required_signatures > u8::MAX as usize {
        return Err(format!("{num_required_signatures} signers exceeds the message limit"));
    }

    let index_of = |pubkey: &[u8; 32]| -> Result<u8, String> {
        merged
            .iter()
            .position(|m| m.pubkey == *pubkey)
            .map(|i| i as u8)
            .ok_or_else(|| "account missing from the compiled table".to_string())
    };

    let mut msg = Vec::with_capacity(3 + merged.len() * 32 + 32 + 128);
    msg.push(num_required_signatures as u8);
    msg.push(num_readonly_signed as u8);
    msg.push(num_readonly_unsigned as u8);

    msg.extend_from_slice(&shortvec(merged.len() as u16));
    for meta in &merged {
        msg.extend_from_slice(&meta.pubkey);
    }
    msg.extend_from_slice(&blockhash);

    msg.extend_from_slice(&shortvec(instructions.len() as u16));
    for ix in instructions {
        msg.push(index_of(&ix.program_id)?);
        msg.extend_from_slice(&shortvec(ix.accounts.len() as u16));
        for meta in &ix.accounts {
            msg.push(index_of(&meta.pubkey)?);
        }
        msg.extend_from_slice(&shortvec(ix.data.len() as u16));
        msg.extend_from_slice(&ix.data);
    }

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::decode_pubkey;

    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const BLOCKHASH: &str = "GXUnrX52iuQTFTqqCMDwoL6o8uMqfdFoodnXCsNGGoRr";

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// The hand-built `token` path is verified against mainnet, so
    /// reproducing its bytes exactly is the strongest available check
    /// that this generic compiler lays accounts out correctly.
    #[test]
    fn reproduces_the_hand_built_token_transfer() {
        use crate::token::TokenTransfer;

        let owner = decode_pubkey("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM").unwrap();
        let dest_owner = decode_pubkey("GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ").unwrap();
        let mint = decode_pubkey(USDC).unwrap();
        let token_program = decode_pubkey(TOKEN_PROGRAM).unwrap();

        let source_ata =
            crate::pda::associated_token_address(&owner, &mint, &token_program).unwrap();
        let destination_ata =
            crate::pda::associated_token_address(&dest_owner, &mint, &token_program).unwrap();

        let expected = TokenTransfer {
            owner,
            source_ata,
            destination_ata,
            destination_owner: dest_owner,
            mint,
            amount: 1_500_000,
            decimals: 6,
            create_destination: false,
        }
        .build_message(BLOCKHASH)
        .unwrap();

        // TransferChecked: source, mint, destination, owner.
        let mut data = Vec::new();
        data.push(12u8);
        data.extend_from_slice(&1_500_000u64.to_le_bytes());
        data.push(6u8);

        let actual = compile_message(
            &owner,
            &[Instruction {
                program_id: token_program,
                accounts: vec![
                    AccountMeta::writable(source_ata),
                    AccountMeta::readonly(mint),
                    AccountMeta::writable(destination_ata),
                    AccountMeta::signer_writable(owner),
                ],
                data,
            }],
            BLOCKHASH,
        )
        .unwrap();

        assert_eq!(
            actual, expected,
            "generic compilation must match the mainnet-verified hand-built layout"
        );
    }

    #[test]
    fn fee_payer_is_first_and_signs() {
        let payer = key(1);
        let msg = compile_message(
            &payer,
            &[Instruction {
                program_id: key(9),
                accounts: vec![AccountMeta::writable(key(2))],
                data: vec![0],
            }],
            BLOCKHASH,
        )
        .unwrap();
        assert_eq!(msg[0], 1, "one required signature");
        assert_eq!(msg[1], 0, "no readonly signers");
        // Header is 3 bytes, then a shortvec length, then the keys.
        assert_eq!(&msg[4..36], &payer, "fee payer occupies index 0");
    }

    #[test]
    fn duplicate_accounts_merge_to_the_strongest_flags() {
        let payer = key(1);
        let shared = key(2);
        let msg = compile_message(
            &payer,
            &[
                Instruction {
                    program_id: key(9),
                    accounts: vec![AccountMeta::readonly(shared)],
                    data: vec![0],
                },
                Instruction {
                    program_id: key(9),
                    accounts: vec![AccountMeta::writable(shared)],
                    data: vec![1],
                },
            ],
            BLOCKHASH,
        )
        .unwrap();
        // payer, shared (writable), program. The shared account must
        // appear once, and must be counted as writable.
        assert_eq!(msg[3], 3, "three distinct accounts");
        assert_eq!(msg[2], 1, "only the program is readonly unsigned");
    }

    #[test]
    fn program_id_is_added_to_the_account_table() {
        let payer = key(1);
        let program = key(9);
        let msg = compile_message(
            &payer,
            &[Instruction { program_id: program, accounts: vec![], data: vec![7] }],
            BLOCKHASH,
        )
        .unwrap();
        assert_eq!(msg[3], 2, "fee payer plus the program");
        assert_eq!(&msg[36..68], &program, "program follows the fee payer");
    }

    #[test]
    fn rejects_an_empty_instruction_list() {
        assert!(compile_message(&key(1), &[], BLOCKHASH).is_err());
    }

    #[test]
    fn rejects_a_malformed_blockhash() {
        let ix = Instruction { program_id: key(9), accounts: vec![], data: vec![0] };
        assert!(compile_message(&key(1), &[ix], "not-base58-!!!").is_err());
    }
}
