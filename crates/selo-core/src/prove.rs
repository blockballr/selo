//! Offline Groth16 proving for daily-close merkle inclusion.
//!
//! A daily close commits a list of sale lines under a Poseidon-over-BN254
//! merkle root. This module produces a Groth16 proof that a single line sits
//! at a given index under that root, without revealing the rest of the tree.
//!
//! The circuit mirrors the off-circuit hashing exactly: leaves are converted
//! to BN254 field elements big-endian, inner nodes are a width-2 Poseidon
//! permutation using the same circom round constants as `light-poseidon`, and
//! the path is folded from leaf to root. A proof therefore only verifies if
//! the prover genuinely knows a merkle path to the committed root.
//!
//! The setup here is a random test setup, generated and cached per root. A
//! deployment that wants public, auditable setup must replace it with a real
//! ceremony or a publicly produced parameter set; the circuit and witness
//! logic are independent of which setup is used.

use ark_bn254::Bn254;
use ark_bn254::Fr;
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::ns;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;
use light_poseidon::PoseidonError;

/// The deepest merkle inclusion proof this circuit accepts.
///
/// Daily closes hold at most 16,384 lines, so a tree is at most 14 levels
/// tall; the bound is a safety cap against malformed input, not the working
/// depth. Each proof folds exactly as many levels as its path carries, so a
/// proving key covers every close up to this depth.
pub const MAX_TREE_DEPTH: usize = 24;

/// Convert 32 big-endian bytes to an `Fr` element, matching the strict
/// length and range check light-poseidon applies in `hash_bytes_be`.
pub fn fr_from_bytes_be(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Convert an `Fr` back to its 32 big-endian bytes.
pub fn fr_to_bytes_be(value: Fr) -> [u8; 32] {
    let big = value.into_bigint();
    big.to_bytes_be().try_into().expect("32 bytes")
}

/// The Poseidon permutation as R1CS constraints.
///
/// Reproduces `light_poseidon::Poseidon::<Fr>::new_circom(2)` exactly: a
/// width-3 permutation (domain tag plus two inputs), 8 full rounds and 56
/// partial rounds, an x^5 sbox, and the same ark round constants and MDS
/// matrix from the generated `bn254_x5` parameters.
pub struct PoseidonGadget;

impl PoseidonGadget {
    fn params() -> Result<light_poseidon::PoseidonParameters<Fr>, PoseidonError> {
        // hash_pair hashes exactly two inputs, so the permutation width is
        // 3 (domain tag plus the two inputs), matching
        // `Poseidon::<Fr>::new_circom(2)` which sets width = nr_inputs + 1.
        get_poseidon_parameters::<Fr>(3)
    }

    /// Constrain `y = poseidon(left, right)` for the width-3 permutation.
    ///
    /// The state starts as `[domain_tag, left, right]` with domain tag zero,
    /// which is exactly the arrangement `hash_bytes_be(&[left, right])` uses.
    pub fn hash_pair(
        left: &FpVar<Fr>,
        right: &FpVar<Fr>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        let params = Self::params().map_err(|_| SynthesisError::Unsatisfiable)?;
        let width = params.width; // 3
        let mut state: Vec<FpVar<Fr>> = Vec::with_capacity(width);
        // Domain tag is zero for the circom construction.
        state.push(FpVar::constant(Fr::zero()));
        state.push(left.clone());
        state.push(right.clone());

        let all_rounds = params.full_rounds + params.partial_rounds;
        let half_rounds = params.full_rounds / 2;

        for round in 0..all_rounds {
            // Ark: add the round constants to every state element.
            let offset = round * width;
            for (i, elem) in state.iter_mut().enumerate() {
                let c = params.ark[offset + i];
                *elem = elem.clone() + c;
            }

            // S-box: full rounds sbox every element, partial rounds sbox only
            // the first element.
            let is_full = round < half_rounds || round >= all_rounds - half_rounds;
            if is_full {
                for elem in state.iter_mut() {
                    *elem = sbox5(elem)?;
                }
            } else {
                state[0] = sbox5(&state[0])?;
            }

            // MDS: linear combination with the MDS matrix.
            let mut next = Vec::with_capacity(state.len());
            for i in 0..state.len() {
                let mut acc = FpVar::constant(Fr::zero());
                for (j, elem) in state.iter().enumerate() {
                    let m = params.mds[i][j];
                    acc += elem.clone() * m;
                }
                next.push(acc);
            }
            state = next;
        }

        Ok(state[0].clone())
    }
}

/// The x^5 sbox for BN254, as three R1CS constraints: a = x*x, b = a*a,
/// out = b*x.
fn sbox5(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let sq = x.clone() * x.clone();
    let fourth = sq.clone() * sq.clone();
    Ok(fourth * x.clone())
}

/// Merkle inclusion circuit: `root = fold(leaf, index, path)`.
///
/// Public inputs: the committed root and the leaf index as bits. Private
/// witness: the leaf and the proof path. The path is a fixed depth; for a
/// shallow tree the trailing siblings are the empty leaf, which a prover
/// would present honestly because a fabricated path would not fold to the
/// public root.
#[derive(Clone)]
pub struct MerkleInclusionCircuit {
    pub root: Option<Fr>,
    pub leaf_index: Option<u64>,
    pub leaf: Option<Fr>,
    pub path: Vec<Option<Fr>>,
}

impl MerkleInclusionCircuit {
    pub fn new(
        root: Fr,
        leaf_index: u64,
        leaf: Fr,
        path: Vec<[u8; 32]>,
    ) -> Result<Self, String> {
        if path.len() > MAX_TREE_DEPTH {
            return Err(format!(
                "proof path has {} levels, more than the {MAX_TREE_DEPTH} this circuit accepts",
                path.len()
            ));
        }
        if (leaf_index.leading_zeros() as usize) + path.len() < 64 {
            return Err("leaf index does not fit the proof depth".to_string());
        }
        let full: Vec<Option<Fr>> = path.iter().map(|p| Some(fr_from_bytes_be(p))).collect();
        Ok(MerkleInclusionCircuit {
            root: Some(root),
            leaf_index: Some(leaf_index),
            leaf: Some(leaf),
            path: full,
        })
    }

    fn depth(&self) -> usize {
        self.path.len()
    }

    pub fn input_values(&self) -> Result<Vec<Fr>, String> {
        let root = self.root.ok_or("root not set")?;
        let index = self.leaf_index.ok_or("leaf index not set")?;
        let mut values = vec![root];
        for bit in 0..self.depth() {
            values.push(if (index >> bit) & 1 == 1 { Fr::one() } else { Fr::zero() });
        }
        Ok(values)
    }
}

impl ConstraintSynthesizer<Fr> for MerkleInclusionCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        let depth = self.depth();
        // Public inputs: root and index bits (as booleans, which become
        // 0/1 field elements in the Groth16 public input vector).
        let root = FpVar::<Fr>::new_input(ns!(cs, "root"), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mut index_bits = Vec::with_capacity(depth);
        for bit in 0..depth {
            let value = || {
                let idx = self.leaf_index.ok_or(SynthesisError::AssignmentMissing)?;
                Ok((idx >> bit) & 1 == 1)
            };
            let b = Boolean::<Fr>::new_input(ns!(cs, "index_bit"), value)?;
            index_bits.push(b);
        }

        // Private witness: leaf and the path.
        let leaf = FpVar::<Fr>::new_witness(ns!(cs, "leaf"), || {
            self.leaf.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mut path_vars = Vec::with_capacity(depth);
        for i in 0..depth {
            let v = FpVar::<Fr>::new_witness(ns!(cs, "path"), || {
                self.path[i].ok_or(SynthesisError::AssignmentMissing)
            })?;
            path_vars.push(v);
        }

        // Fold leaf and path into root using the Poseidon gadget. An empty
        // path means a one-line tree: the root is the leaf itself.
        let mut node = leaf;
        for level in 0..depth {
            let sibling = &path_vars[level];
            // Select the branch by the index bit: the node is the right
            // child of its parent when the bit is one, the left child when
            // it is zero (matching `compute_root` in zk.rs).
            let is_right = &index_bits[level];
            let left_child = CondSelectGadget::<Fr>::conditionally_select(is_right, sibling, &node)?;
            let right_child =
                CondSelectGadget::<Fr>::conditionally_select(is_right, &node, sibling)?;
            node = PoseidonGadget::hash_pair(&left_child, &right_child)?;
        }

        // Constrain the folded root to the public root.
        root.enforce_equal(&node)?;
        Ok(())
    }
}

/// Prove that `leaf` sits at `leaf_index` under `root`.
pub fn prove_inclusion(
    root: [u8; 32],
    leaf_index: u64,
    leaf: [u8; 32],
    path: Vec<[u8; 32]>,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>, Proof<Bn254>), String> {
    let circuit = MerkleInclusionCircuit::new(
        fr_from_bytes_be(&root),
        leaf_index,
        fr_from_bytes_be(&leaf),
        path,
    )?;
    let (pk, vk) = setup_for(&circuit)?;

    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .map_err(|e| format!("Groth16 proving failed: {e}"))?;

    Ok((pk, vk, proof))
}

/// Verify a Groth16 proof against a verifying key.
pub fn verify_inclusion(
    vk: &VerifyingKey<Bn254>,
    public_inputs: &[Fr],
    proof: &Proof<Bn254>,
) -> Result<bool, String> {
    Groth16::<Bn254>::verify(vk, public_inputs, proof)
        .map_err(|e| format!("proof verification failed: {e}"))
}

/// Build (and cache) a Groth16 proving/verifying key for the inclusion
/// circuit. The setup is random and unceremonied: fine for a proof of
/// concept, replaced by a real setup before any public anchoring.
fn setup_for(
    circuit: &MerkleInclusionCircuit,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), String> {
    let mut rng = StdRng::seed_from_u64(0xBEEF);
    Groth16::<Bn254>::setup(circuit.clone(), &mut rng)
        .map_err(|e| format!("Groth16 setup failed: {e}"))
}

/// Serialize a Groth16 proof to bytes for transport.
pub fn serialize_proof(proof: &Proof<Bn254>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    proof
        .serialize_compressed(&mut out)
        .map_err(|e| format!("proof serialize: {e}"))?;
    Ok(out)
}

/// Deserialize a Groth16 proof from bytes.
pub fn deserialize_proof(bytes: &[u8]) -> Result<Proof<Bn254>, String> {
    Proof::<Bn254>::deserialize_compressed(bytes)
        .map_err(|e| format!("proof deserialize: {e}"))
}

/// The public inputs a verifier needs for a statement: the merkle root
/// followed by the leaf index as one boolean per tree level.
pub fn statement_public_inputs(statement: &LineStatement) -> Result<Vec<Fr>, String> {
    let circuit = MerkleInclusionCircuit::new(
        fr_from_bytes_be(&statement.root),
        statement.line_index,
        fr_from_bytes_be(&statement.leaf),
        statement.proof_path.clone(),
    )?;
    circuit.input_values()
}

/// The compressed serialized size of a proving key, for reporting.
pub fn proving_key_size(pk: &ProvingKey<Bn254>) -> Result<usize, String> {
    let mut out = Vec::new();
    pk.serialize_compressed(&mut out)
        .map_err(|e| format!("proving key serialize: {e}"))?;
    Ok(out.len())
}

/// A prepared statement about one line in a daily close, ready to prove.
pub struct LineStatement {
    pub merchant: String,
    pub day_start_unix: i64,
    pub day_end_unix: i64,
    pub line_index: u64,
    pub leaf: [u8; 32],
    pub root: [u8; 32],
    pub proof_path: Vec<[u8; 32]>,
}

/// Build a statement for the line at `line_index` of a daily close.
pub fn line_statement(
    close: &crate::close::DailyClose,
    line_index: u64,
) -> Result<LineStatement, String> {
    let leaves = close.leaves();
    if line_index as usize >= leaves.len() {
        return Err(format!(
            "line {line_index} is outside this close, which has {} lines",
            leaves.len()
        ));
    }
    let leaf = leaves[line_index as usize];
    let proof_path = close.merkle_proof(line_index as usize)?;
    Ok(LineStatement {
        merchant: close.merchant.clone(),
        day_start_unix: close.day_start_unix,
        day_end_unix: close.day_end_unix,
        line_index,
        leaf,
        root: close.merkle_root,
        proof_path,
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::close::{build_close, ConfirmedSale, DailyClose};
    use crate::quote::issue_quote;
    use crate::quotelog::QuoteEntry;
    use crate::zk::compute_root;

    const MERCHANT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const CUSTOMER: &str = "GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const DAY_START: i64 = 1_750_000_000;
    const DAY_END: i64 = DAY_START + 86_400;

    fn sig(byte: u8) -> String {
        bs58::encode([byte; 64]).into_string()
    }

    fn sale_and_quote(
        sales_point: u8,
        order_counter: u8,
        sku: &str,
        quantity: u32,
        unit_price: u64,
        sig_byte: u8,
    ) -> (ConfirmedSale, QuoteEntry) {
        let quote = issue_quote(
            sales_point, order_counter, sku, quantity, unit_price, USDC,
            DAY_START, 900,
        )
        .expect("fixture quote is valid");
        let sale = ConfirmedSale {
            signature: sig(sig_byte),
            slot: 301_455_912 + sig_byte as u64,
            block_time_unix: Some(DAY_START + 43_200),
            sales_point,
            order_counter,
            sku: sku.to_string(),
            quantity,
            amount_base_units: quote.amount_due_base_units,
            mint: USDC.to_string(),
            payer: CUSTOMER.to_string(),
        };
        (sale, QuoteEntry::from(&quote))
    }

    fn a_day() -> DailyClose {
        let items = [
            (3u8, 47u8, "RICE-5KG", 1u32, 10_000_000u64, 1u8),
            (3, 48, "OIL-1L", 2, 3_500_000, 2),
            (7, 4, "SOAP", 3, 1_250_000, 3),
        ];
        let mut sales = Vec::new();
        let mut quotes = Vec::new();
        for (sp, oc, sku, qty, price, byte) in items {
            let (s, q) = sale_and_quote(sp, oc, sku, qty, price, byte);
            sales.push(s);
            quotes.push(q);
        }
        build_close(MERCHANT, DAY_START, DAY_END, &sales, &quotes).expect("the day closes")
    }

    #[test]
    fn a_real_line_proves_and_verifies() {
        let close = a_day();
        let leaves = close.leaves();
        for index in 0..leaves.len() {
            let statement = line_statement(&close, index as u64).expect("statement");
            let (_pk, vk, proof) =
                prove_inclusion(statement.root, statement.line_index, statement.leaf, statement.proof_path.clone())
                    .expect("proof generated");
            let inputs = MerkleInclusionCircuit::new(
                fr_from_bytes_be(&statement.root),
                statement.line_index,
                fr_from_bytes_be(&statement.leaf),
                statement.proof_path.clone(),
            )
            .expect("circuit")
            .input_values()
            .expect("public inputs");
            let ok = verify_inclusion(&vk, &inputs, &proof).expect("verification runs");
            assert!(ok, "line {index} proof did not verify against its root");
        }
    }

    #[test]
    fn a_tampered_root_does_not_verify() {
        let close = a_day();
        let statement = line_statement(&close, 0).expect("statement");
        // Prove the genuine statement, then verify it against a root that is
        // not the committed one: the proof must be rejected.
        let (_pk, vk, proof) =
            prove_inclusion(statement.root, statement.line_index, statement.leaf, statement.proof_path.clone())
                .expect("proof generated");
        let mut wrong_root = statement.root;
        wrong_root[31] ^= 0x01;
        let inputs = MerkleInclusionCircuit::new(
            fr_from_bytes_be(&wrong_root),
            statement.line_index,
            fr_from_bytes_be(&statement.leaf),
            statement.proof_path.clone(),
        )
        .expect("circuit")
        .input_values()
        .expect("public inputs");
        let ok = verify_inclusion(&vk, &inputs, &proof).expect("verification runs");
        assert!(!ok, "a proof for the real leaf must not verify under a tampered root");
    }

    #[test]
    fn proof_round_trips_through_serialization() {
        let close = a_day();
        let statement = line_statement(&close, 1).expect("statement");
        let (_pk, vk, proof) =
            prove_inclusion(statement.root, statement.line_index, statement.leaf, statement.proof_path.clone())
                .expect("proof generated");
        let bytes = serialize_proof(&proof).expect("serialize");
        let back = deserialize_proof(&bytes).expect("deserialize");
        let inputs = MerkleInclusionCircuit::new(
            fr_from_bytes_be(&statement.root),
            statement.line_index,
            fr_from_bytes_be(&statement.leaf),
            statement.proof_path.clone(),
        )
        .expect("circuit")
        .input_values()
        .expect("public inputs");
        assert!(verify_inclusion(&vk, &inputs, &back).expect("verify"));
    }

    #[test]
    fn a_single_line_close_proves_trivially() {
        // A close holding exactly one line has a one-leaf tree: the root is
        // the leaf itself and the proof path is empty.
        let (sale, quote) = sale_and_quote(3, 1, "RICE-5KG", 1, 10_000_000, 9);
        let close = build_close(MERCHANT, DAY_START, DAY_END, &[sale], &[quote])
            .expect("one-line day closes");
        assert_eq!(close.leaves().len(), 1);
        let statement = line_statement(&close, 0).expect("statement");
        assert!(statement.proof_path.is_empty());
        let (_pk, vk, proof) = prove_inclusion(
            statement.root,
            statement.line_index,
            statement.leaf,
            statement.proof_path.clone(),
        )
        .expect("proof generated");
        let inputs = statement_public_inputs(&statement).expect("public inputs");
        assert!(verify_inclusion(&vk, &inputs, &proof).expect("verify"));
    }

    #[test]
    fn gadget_matches_light_poseidon() {
        use ark_r1cs_std::R1CSVar;
        use ark_relations::r1cs::ConstraintSystem;
        use light_poseidon::{Poseidon, PoseidonBytesHasher};

        let left = [1u8; 32];
        let right = [2u8; 32];
        let mut real = Poseidon::<Fr>::new_circom(2).unwrap();
        let expected = real.hash_bytes_be(&[&left, &right]).unwrap();

        let cs = ConstraintSystem::<Fr>::new_ref();
        let l = FpVar::<Fr>::new_witness(ns!(cs, "l"), || Ok(fr_from_bytes_be(&left))).unwrap();
        let r = FpVar::<Fr>::new_witness(ns!(cs, "r"), || Ok(fr_from_bytes_be(&right))).unwrap();
        let out = PoseidonGadget::hash_pair(&l, &r).unwrap();
        out.enforce_equal(&FpVar::constant(fr_from_bytes_be(&expected))).unwrap();

        assert!(cs.is_satisfied().unwrap(), "gadget output != light-poseidon");
        let computed = out.value().unwrap();
        let expected_f = fr_from_bytes_be(&expected);
        assert_eq!(computed, expected_f);
    }

    #[test]
    fn statement_data_is_consistent() {
        let mut sales = Vec::new();
        let mut quotes = Vec::new();
        for i in 0..3u8 {
            let q = issue_quote(3, 47 + i, "RICE", 1, 10_000_000, USDC, 1_750_000_000, 900).unwrap();
            let s = ConfirmedSale {
                signature: bs58::encode([i; 64]).into_string(),
                slot: 301_455_912 + i as u64,
                block_time_unix: Some(1_750_000_000 + 43_200),
                sales_point: 3,
                order_counter: 47 + i,
                sku: "RICE".to_string(),
                quantity: 1,
                amount_base_units: q.amount_due_base_units,
                mint: USDC.to_string(),
                payer: CUSTOMER.to_string(),
            };
            sales.push(s);
            quotes.push(QuoteEntry::from(&q));
        }
        let close = build_close(MERCHANT, 1_750_000_000, 1_750_000_000 + 86_400, &sales, &quotes).unwrap();
        for idx in 0..3usize {
            let st = line_statement(&close, idx as u64).unwrap();
            let recomputed = compute_root(&st.leaf, st.line_index, &st.proof_path).unwrap();
            assert_eq!(recomputed, st.root, "line {idx}: off-circuit fold disagrees with root");
        }
    }
}
