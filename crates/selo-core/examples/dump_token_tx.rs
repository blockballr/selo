// Dev helper: emit a base64 token transfer transaction for simulation.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use selo_core::address::decode_pubkey;
use selo_core::token::TokenTransfer;
use selo_core::transfer::shortvec;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let owner = decode_pubkey(&args[1]).unwrap();
    let dest = &args[2];
    let mint = &args[3];
    let amount: u64 = args[4].parse().unwrap();
    let blockhash = &args[5];
    let create: bool = args[6].parse().unwrap();

    let t = TokenTransfer::resolve(&owner, dest, mint, amount, 6, create).unwrap();
    let msg = t.build_message(blockhash).unwrap();
    let mut tx = Vec::new();
    tx.extend_from_slice(&shortvec(1));
    tx.extend_from_slice(&[0u8; 64]); // placeholder signature, sigVerify off
    tx.extend_from_slice(&msg);
    println!("{}", B64.encode(tx));
    eprintln!("source_ata={} dest_ata={}", t.source_ata_base58(), t.destination_ata_base58());
}
