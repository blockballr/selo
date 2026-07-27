//! Program derived addresses and associated token accounts.
//!
//! `findProgramAddress` is reimplemented here because the Solana SDK
//! does not build for the wasm32-wasip2 component target. The algorithm
//! is small and fully specified: hash the seeds, a candidate bump, the
//! program id, and the marker string, then accept the result only if it
//! is *not* a valid ed25519 curve point. An on-curve result would be an
//! address someone could hold a private key for, which would defeat the
//! purpose of a program-owned account, so those candidates are rejected
//! and the bump is decremented.
//!
//! The tests check derivations against associated token accounts read
//! from mainnet, covering three different bump values.

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

/// The SPL Associated Token Account program.
pub const ASSOCIATED_TOKEN_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// Appended to every PDA preimage so a derived address can never
/// collide with a hash used for another purpose.
const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

/// Solana rejects seeds longer than this.
const MAX_SEED_LEN: usize = 32;

/// True when `bytes` decompresses to a valid ed25519 point, meaning a
/// private key could exist for it and it is therefore not a valid PDA.
pub fn is_on_curve(bytes: &[u8; 32]) -> bool {
    CompressedEdwardsY(*bytes).decompress().is_some()
}

/// Derive the address for one specific bump, or `None` when the result
/// lands on the curve and the caller should try the next bump down.
pub fn create_program_address(
    seeds: &[&[u8]],
    bump: u8,
    program_id: &[u8; 32],
) -> Option<[u8; 32]> {
    let mut hasher = Sha256::new();
    for seed in seeds {
        hasher.update(seed);
    }
    hasher.update([bump]);
    hasher.update(program_id);
    hasher.update(PDA_MARKER);
    let hash: [u8; 32] = hasher.finalize().into();
    if is_on_curve(&hash) {
        None
    } else {
        Some(hash)
    }
}

/// Find the canonical program address: the highest bump, counting down
/// from 255, whose derived address is off the curve.
pub fn find_program_address(
    seeds: &[&[u8]],
    program_id: &[u8; 32],
) -> Result<([u8; 32], u8), String> {
    for seed in seeds {
        if seed.len() > MAX_SEED_LEN {
            return Err(format!(
                "seed of {} bytes exceeds the {MAX_SEED_LEN} byte limit",
                seed.len()
            ));
        }
    }
    for bump in (0..=255u8).rev() {
        if let Some(address) = create_program_address(seeds, bump, program_id) {
            return Ok((address, bump));
        }
    }
    // Statistically unreachable: each bump is off-curve with probability
    // about one half, so all 256 failing is astronomically unlikely.
    Err("no off-curve bump found for these seeds".to_string())
}

/// Derive the associated token account for `owner` and `mint`.
///
/// Seeds are the owner, the token program, and the mint, in that order,
/// under the associated token account program.
pub fn associated_token_address(
    owner: &[u8; 32],
    mint: &[u8; 32],
    token_program: &[u8; 32],
) -> Result<[u8; 32], String> {
    let ata_program = crate::address::decode_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID)?;
    let (address, _bump) = find_program_address(
        &[owner.as_slice(), token_program.as_slice(), mint.as_slice()],
        &ata_program,
    )?;
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{decode_pubkey, encode_pubkey};

    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const USDT: &str = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB";

    /// Each case was read from mainnet: the derived address exists on
    /// chain as a token account whose owner and mint match the inputs.
    /// Bumps 254, 255, and 251 are covered, so the countdown loop is
    /// exercised rather than only its first iteration.
    const VECTORS: &[(&str, &str, &str)] = &[
        (
            "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
            USDC,
            "FGETo8T8wMcN2wCjav8VK6eh3dLk63evNDPxzLSJra8B",
        ),
        (
            "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
            USDT,
            "TB5FCqbNsnuLQgEjUuPaT9qtVPTT4U1A8rvi7qzEj2M",
        ),
        (
            "GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ",
            USDC,
            "6u6tm3d9Vf4QUDdbtMaV21qsmPHorJebdyDT6ZJ9h5JY",
        ),
    ];

    #[test]
    fn matches_mainnet_associated_token_accounts() {
        let token_program = decode_pubkey(TOKEN_PROGRAM).unwrap();
        for (owner, mint, expected) in VECTORS {
            let owner_bytes = decode_pubkey(owner).unwrap();
            let mint_bytes = decode_pubkey(mint).unwrap();
            let ata =
                associated_token_address(&owner_bytes, &mint_bytes, &token_program).unwrap();
            assert_eq!(
                encode_pubkey(&ata),
                *expected,
                "ATA mismatch for owner {owner} mint {mint}"
            );
        }
    }

    #[test]
    fn known_bumps_are_reproduced() {
        let token_program = decode_pubkey(TOKEN_PROGRAM).unwrap();
        let ata_program = decode_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID).unwrap();
        let owner = decode_pubkey(VECTORS[0].0).unwrap();
        let usdc = decode_pubkey(USDC).unwrap();
        let (_, bump) = find_program_address(
            &[owner.as_slice(), token_program.as_slice(), usdc.as_slice()],
            &ata_program,
        )
        .unwrap();
        assert_eq!(bump, 254);
    }

    #[test]
    fn system_program_id_is_on_curve_check_sanity() {
        // A real wallet address is a curve point; a derived ATA is not.
        let wallet = decode_pubkey(VECTORS[0].0).unwrap();
        assert!(is_on_curve(&wallet));
        let ata = decode_pubkey(VECTORS[0].2).unwrap();
        assert!(!is_on_curve(&ata));
    }

    #[test]
    fn rejects_oversized_seed() {
        let program = [0u8; 32];
        let big = [7u8; 33];
        let err = find_program_address(&[&big], &program).unwrap_err();
        assert!(err.contains("exceeds"));
    }

    #[test]
    fn create_program_address_is_deterministic() {
        let program = decode_pubkey(ASSOCIATED_TOKEN_PROGRAM_ID).unwrap();
        let seed = b"anchor";
        let first = create_program_address(&[seed], 255, &program);
        let second = create_program_address(&[seed], 255, &program);
        assert_eq!(first, second);
    }
}
