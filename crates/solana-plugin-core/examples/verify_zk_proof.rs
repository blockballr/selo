// Dev helper: verify a real getCompressedAccountProof response.
use solana_plugin_core::zk;

fn main() {
    let body = std::fs::read_to_string(std::env::args().nth(1).unwrap()).unwrap();
    let p = zk::parse_account_proof(&body).unwrap();
    println!("leaf_index = {}", p.leaf_index);
    println!("proof depth = {}", p.proof.len());
    println!("tree        = {}", p.merkle_tree);
    let computed = zk::compute_root(&p.hash, p.leaf_index, &p.proof).unwrap();
    println!("indexer root = {}", bs58::encode(p.root).into_string());
    println!("computed root= {}", bs58::encode(computed).into_string());
    match zk::verify_proof(&p.hash, p.leaf_index, &p.proof, &p.root) {
        Ok(()) => println!("RESULT: proof VERIFIES against the indexer root"),
        Err(e) => { println!("RESULT: FAILED -> {e}"); std::process::exit(2); }
    }
}
