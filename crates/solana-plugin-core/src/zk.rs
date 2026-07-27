//! ZK compression: compressed account proofs and their verification.
//!
//! ZK compression keeps account data off chain in a merkle tree and
//! stores only a small commitment on chain, which is how large airdrops
//! are distributed cheaply. Reading it requires a Photon indexer rather
//! than an ordinary RPC node.
//!
//! That indexer is the reason this module exists in the form it does.
//! Asking an indexer for a balance and printing the answer means
//! trusting a third party's claim about chain state. Instead the plugin
//! asks for the merkle proof alongside the balance and recomputes the
//! root itself, so a wrong or malicious answer is caught rather than
//! reported as fact. This is the same stance the swap plugin takes when
//! it refuses to sign a transaction it has not parsed.
//!
//! Two details had to match Light Protocol exactly, and both were read
//! from its source rather than guessed. The hasher is Poseidon over
//! BN254 with circom parameters (`program-libs/hasher/src/poseidon.rs`
//! uses `Poseidon::<Fr>::new_circom` with `hash_bytes_be`). The sibling
//! ordering is taken from `compute_parent_node` in
//! `program-libs/concurrent-merkle-tree/src/hash.rs`:
//!
//! ```text
//! let is_left = (node_index >> level) & 1 == 0;
//! if is_left { H(node, sibling) } else { H(sibling, node) }
//! ```

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use serde_json::{json, Value};

use crate::address::validate_pubkey;
use crate::rpc::parse_result_value;

/// A merkle tree taller than this is not something we expect from a
/// state tree, and refusing keeps a malformed proof from spinning.
const MAX_PROOF_DEPTH: usize = 40;

/// Build the Poseidon hasher once.
///
/// Constructing it is not cheap: it materialises the full circom round
/// constant and MDS matrix set. Doing that per hash meant building it
/// once per tree level, which overflowed the stack on a 32 level proof
/// in an unoptimised build and would be far worse inside a component,
/// where the stack is smaller than a native thread's. It is boxed so
/// those parameters live on the heap rather than in a stack frame.
fn hasher() -> Result<Box<Poseidon<Fr>>, String> {
    Poseidon::<Fr>::new_circom(2)
        .map(Box::new)
        .map_err(|e| format!("failed to construct Poseidon hasher: {e}"))
}

/// Poseidon hash of two 32 byte nodes, matching Light Protocol's hasher.
///
/// Convenience for single hashes. Anything hashing repeatedly should
/// build one hasher and call `hash_pair_with` instead.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], String> {
    hash_pair_with(&mut *hasher()?, left, right)
}

/// Poseidon hash using an already constructed hasher.
pub fn hash_pair_with(
    hasher: &mut Poseidon<Fr>,
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<[u8; 32], String> {
    hasher
        .hash_bytes_be(&[left, right])
        .map_err(|e| format!("Poseidon hashing failed: {e}"))
}

/// Fold a leaf and its proof path into a root.
///
/// Mirrors `compute_root` in Light Protocol: at each level the node is
/// the left child when the corresponding bit of the leaf index is zero.
pub fn compute_root(
    leaf: &[u8; 32],
    leaf_index: u64,
    proof: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    if proof.len() > MAX_PROOF_DEPTH {
        return Err(format!(
            "merkle proof has {} levels, more than the {MAX_PROOF_DEPTH} this plugin will process",
            proof.len()
        ));
    }
    // One hasher for the whole path, not one per level.
    let mut hasher = hasher()?;
    let mut node = *leaf;
    for (level, sibling) in proof.iter().enumerate() {
        let is_left = (leaf_index >> level) & 1 == 0;
        node = if is_left {
            hash_pair_with(&mut hasher, &node, sibling)?
        } else {
            hash_pair_with(&mut hasher, sibling, &node)?
        };
    }
    Ok(node)
}

/// Verify that `leaf` really sits at `leaf_index` under `expected_root`.
///
/// The error names both roots, because when this fails the useful
/// question is whether the indexer is lying or merely stale.
pub fn verify_proof(
    leaf: &[u8; 32],
    leaf_index: u64,
    proof: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), String> {
    let computed = compute_root(leaf, leaf_index, proof)?;
    if &computed == expected_root {
        Ok(())
    } else {
        Err(format!(
            "merkle proof does not verify: recomputing the root from the leaf gives {} but the indexer reported {}",
            bs58::encode(computed).into_string(),
            bs58::encode(expected_root).into_string()
        ))
    }
}

/// A compressed token balance as reported by the indexer, before any
/// proof has been checked.
#[derive(Debug, Clone, PartialEq)]
pub struct CompressedBalance {
    pub mint: String,
    pub amount: u64,
}

/// A compressed account's merkle proof.
#[derive(Debug, Clone)]
pub struct AccountProof {
    pub hash: [u8; 32],
    pub leaf_index: u64,
    pub merkle_tree: String,
    pub proof: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

/// A compressed account as listed by the indexer, before verification.
#[derive(Debug, Clone, PartialEq)]
pub struct CompressedAccount {
    pub hash: String,
    pub leaf_index: u64,
    pub tree: String,
    pub lamports: u64,
}

/// Build a `getCompressedAccountsByOwner` request.
pub fn accounts_by_owner_request(owner: &str) -> Result<String, String> {
    let addr = validate_pubkey(owner)?;
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getCompressedAccountsByOwner",
        "params": { "owner": addr }
    })
    .to_string())
}

/// Parse a `getCompressedAccountsByOwner` response.
///
/// Field names follow a live mainnet response: each item carries
/// `hash`, `leafIndex` and `tree`. Snake case variants are accepted
/// too, since the indexer has used both.
pub fn parse_accounts_by_owner(body: &str) -> Result<Vec<CompressedAccount>, String> {
    let result = parse_result_value(body)?;
    let items = result
        .pointer("/value/items")
        .and_then(Value::as_array)
        .ok_or_else(|| "compressed account response has no items list".to_string())?;

    let mut accounts = Vec::with_capacity(items.len());
    for item in items {
        let hash = item
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| "compressed account has no hash".to_string())?
            .to_string();
        let leaf_index = item
            .get("leafIndex")
            .or_else(|| item.get("leaf_index"))
            .and_then(Value::as_u64)
            .ok_or_else(|| "compressed account has no leafIndex".to_string())?;
        let tree = item
            .get("tree")
            .or_else(|| item.get("merkleTree"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        accounts.push(CompressedAccount {
            hash,
            leaf_index,
            tree,
            lamports: item.get("lamports").and_then(Value::as_u64).unwrap_or(0),
        });
    }
    Ok(accounts)
}

/// Build a `getCompressedTokenBalancesByOwnerV2` request.
pub fn token_balances_request(owner: &str) -> Result<String, String> {
    let addr = validate_pubkey(owner)?;
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getCompressedTokenBalancesByOwnerV2",
        "params": { "owner": addr }
    })
    .to_string())
}

/// Build a `getCompressedAccountProof` request for an account hash.
pub fn account_proof_request(hash_base58: &str) -> Result<String, String> {
    let hash = validate_pubkey(hash_base58)
        .map_err(|e| format!("account hash is not a 32 byte base58 value: {e}"))?;
    Ok(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getCompressedAccountProof",
        "params": { "hash": hash }
    })
    .to_string())
}

/// Decode a base58 32 byte value from a JSON field.
fn field_hash(value: &Value, field: &str) -> Result<[u8; 32], String> {
    let raw = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("proof response is missing '{field}'"))?;
    bs58::decode(raw)
        .into_vec()
        .map_err(|_| format!("'{field}' is not valid base58"))?
        .try_into()
        .map_err(|_| format!("'{field}' does not decode to 32 bytes"))
}

/// Parse a `getCompressedTokenBalancesByOwner` response.
///
/// The indexer has moved this shape around between versions, so both
/// the newer `items` list and the older `token_balances` list are
/// accepted rather than pinning to one and breaking on the other.
pub fn parse_token_balances(body: &str) -> Result<Vec<CompressedBalance>, String> {
    let result = parse_result_value(body)?;
    let list = result
        .pointer("/value/items")
        .or_else(|| result.pointer("/value/token_balances"))
        .or_else(|| result.pointer("/value/tokenBalances"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "compressed balance response has no items or token_balances list".to_string()
        })?;

    let mut balances = Vec::with_capacity(list.len());
    for entry in list {
        let mint = entry
            .get("mint")
            .and_then(Value::as_str)
            .ok_or_else(|| "compressed balance entry has no mint".to_string())?
            .to_string();
        // Amounts can arrive as a JSON number or a decimal string.
        let amount = entry
            .get("balance")
            .or_else(|| entry.get("amount"))
            .and_then(|b| {
                b.as_u64()
                    .or_else(|| b.as_str().and_then(|s| s.parse().ok()))
            })
            .ok_or_else(|| "compressed balance entry has no readable balance".to_string())?;
        balances.push(CompressedBalance { mint, amount });
    }
    Ok(balances)
}

/// Parse a `getCompressedAccountProof` response.
pub fn parse_account_proof(body: &str) -> Result<AccountProof, String> {
    let result = parse_result_value(body)?;
    let value = result.get("value").unwrap_or(&result);

    let proof_nodes = value
        .get("proof")
        .and_then(Value::as_array)
        .ok_or_else(|| "proof response has no proof array".to_string())?;
    let mut proof = Vec::with_capacity(proof_nodes.len());
    for node in proof_nodes {
        let raw = node
            .as_str()
            .ok_or_else(|| "proof node is not a string".to_string())?;
        let bytes: [u8; 32] = bs58::decode(raw)
            .into_vec()
            .map_err(|_| "proof node is not valid base58".to_string())?
            .try_into()
            .map_err(|_| "proof node does not decode to 32 bytes".to_string())?;
        proof.push(bytes);
    }

    Ok(AccountProof {
        hash: field_hash(value, "hash")?,
        leaf_index: value
            .get("leafIndex")
            .or_else(|| value.get("leaf_index"))
            .and_then(Value::as_u64)
            .ok_or_else(|| "proof response has no leafIndex".to_string())?,
        merkle_tree: value
            .get("merkleTree")
            .or_else(|| value.get("merkle_tree"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        proof,
        root: field_hash(value, "root")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a full binary tree of the given depth over `leaves`, then
    /// return its root plus the proof for `index`. This is an
    /// independent construction: the test builds the tree bottom up
    /// while `compute_root` folds a single path, so agreement between
    /// them is a real check rather than a restatement.
    fn tree_root_and_proof(
        leaves: &[[u8; 32]],
        index: usize,
    ) -> ([u8; 32], Vec<[u8; 32]>) {
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        let mut proof = Vec::new();
        let mut idx = index;
        while level.len() > 1 {
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            proof.push(level[sibling]);
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks(2) {
                next.push(hash_pair(&pair[0], &pair[1]).unwrap());
            }
            level = next;
            idx /= 2;
        }
        (level[0], proof)
    }

    fn leaf(n: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[31] = n;
        b
    }

    #[test]
    fn poseidon_matches_circomlib_vector() {
        // poseidon([1, 2]) is a widely published constant, so this
        // pins the parameters to circom's rather than some other set.
        let out = hash_pair(&leaf(1), &leaf(2)).unwrap();
        let as_int = out.iter().fold(String::new(), |mut acc, b| {
            acc.push_str(&format!("{b:02x}"));
            acc
        });
        assert_eq!(
            as_int,
            "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
        );
    }

    #[test]
    fn verifies_a_real_path_at_every_index() {
        let leaves: Vec<[u8; 32]> = (0..8).map(leaf).collect();
        for index in 0..8usize {
            let (root, proof) = tree_root_and_proof(&leaves, index);
            verify_proof(&leaves[index], index as u64, &proof, &root)
                .unwrap_or_else(|e| panic!("index {index} failed: {e}"));
        }
    }

    #[test]
    fn sibling_order_actually_matters() {
        // If left and right were interchangeable, a leaf would verify
        // at the wrong index. It must not.
        let leaves: Vec<[u8; 32]> = (0..8).map(leaf).collect();
        let (root, proof) = tree_root_and_proof(&leaves, 3);
        assert!(verify_proof(&leaves[3], 3, &proof, &root).is_ok());
        assert!(verify_proof(&leaves[3], 2, &proof, &root).is_err());
    }

    #[test]
    fn rejects_tampered_leaf_and_sibling() {
        let leaves: Vec<[u8; 32]> = (0..8).map(leaf).collect();
        let (root, proof) = tree_root_and_proof(&leaves, 5);

        let err = verify_proof(&leaf(99), 5, &proof, &root).unwrap_err();
        assert!(err.contains("does not verify"));

        let mut bad = proof.clone();
        bad[0][31] ^= 0xFF;
        assert!(verify_proof(&leaves[5], 5, &bad, &root).is_err());
    }

    #[test]
    fn empty_proof_means_the_leaf_is_the_root() {
        let l = leaf(7);
        assert_eq!(compute_root(&l, 0, &[]).unwrap(), l);
    }

    #[test]
    fn absurd_proof_depth_is_refused() {
        let proof = vec![[0u8; 32]; MAX_PROOF_DEPTH + 1];
        let err = compute_root(&leaf(1), 0, &proof).unwrap_err();
        assert!(err.contains("more than"));
    }

    #[test]
    fn requests_are_wellformed() {
        const OWNER: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
        let req = token_balances_request(OWNER).unwrap();
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "getCompressedTokenBalancesByOwnerV2");
        assert_eq!(v["params"]["owner"], OWNER);

        let req = account_proof_request(OWNER).unwrap();
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v["method"], "getCompressedAccountProof");
        assert!(token_balances_request("nope!").is_err());
    }

    #[test]
    fn parses_both_balance_shapes() {
        let items = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{
            "items":[{"mint":"Mint1","balance":1500}],"cursor":null}},"id":1}"#;
        let parsed = parse_token_balances(items).unwrap();
        assert_eq!(parsed[0], CompressedBalance { mint: "Mint1".into(), amount: 1500 });

        let legacy = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{
            "token_balances":[{"mint":"Mint2","balance":"42"}]}},"id":1}"#;
        let parsed = parse_token_balances(legacy).unwrap();
        assert_eq!(parsed[0], CompressedBalance { mint: "Mint2".into(), amount: 42 });
    }

    #[test]
    fn parses_proof_response() {
        let hash = bs58::encode(leaf(3)).into_string();
        let root = bs58::encode(leaf(9)).into_string();
        let sib = bs58::encode(leaf(4)).into_string();
        let body = format!(
            r#"{{"jsonrpc":"2.0","result":{{"value":{{"hash":"{hash}","leafIndex":5,
               "merkleTree":"Tree1","proof":["{sib}"],"root":"{root}"}}}},"id":1}}"#
        );
        let p = parse_account_proof(&body).unwrap();
        assert_eq!(p.leaf_index, 5);
        assert_eq!(p.merkle_tree, "Tree1");
        assert_eq!(p.proof.len(), 1);
        assert_eq!(p.hash, leaf(3));
        assert_eq!(p.root, leaf(9));
    }

    #[test]
    fn proof_response_missing_fields_errors() {
        assert!(parse_account_proof(r#"{"jsonrpc":"2.0","result":{"value":{}},"id":1}"#).is_err());
    }

    #[test]
    fn parses_accounts_by_owner_live_shape() {
        // Field names taken from a live mainnet Photon response.
        let body = r#"{"jsonrpc":"2.0","result":{"context":{"slot":1},"value":{"items":[
            {"hash":"5FPLN7N6M6E2NkqoGUVvvdghgJTMFAmrgYEJ5GbFf2A","leafIndex":4,
             "tree":"bmt4d3p1a4YQgk9PeZv5s4DBUmbF5NxqYpk9HGjQsd8","lamports":0}
        ],"cursor":null}},"id":1}"#;
        let a = parse_accounts_by_owner(body).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].leaf_index, 4);
        assert_eq!(a[0].hash, "5FPLN7N6M6E2NkqoGUVvvdghgJTMFAmrgYEJ5GbFf2A");
        assert_eq!(a[0].tree, "bmt4d3p1a4YQgk9PeZv5s4DBUmbF5NxqYpk9HGjQsd8");
    }

    #[test]
    fn accounts_by_owner_request_is_wellformed() {
        const OWNER: &str = "FmyBRAuM13MfPbDke5D4f5mmqUJ5EssFxe1YauT9Ntbz";
        let v: Value = serde_json::from_str(&accounts_by_owner_request(OWNER).unwrap()).unwrap();
        assert_eq!(v["method"], "getCompressedAccountsByOwner");
        assert_eq!(v["params"]["owner"], OWNER);
        assert!(accounts_by_owner_request("bad!").is_err());
    }

    #[test]
    fn accounts_missing_fields_error() {
        let body = r#"{"jsonrpc":"2.0","result":{"value":{"items":[{"leafIndex":1}]}},"id":1}"#;
        assert!(parse_accounts_by_owner(body).is_err());
    }
}
