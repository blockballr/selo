// Dev helper: emit a base64 SOL transfer with compute budget
// instructions, for simulating against a real cluster.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use solana_plugin_core::address::decode_pubkey;
use solana_plugin_core::transfer::{
    build_transfer_message_with_priority, shortvec, PriorityFee,
};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let from = decode_pubkey(&a[1]).unwrap();
    let to = &a[2];
    let lamports: u64 = a[3].parse().unwrap();
    let blockhash = &a[4];
    let priority = if a[5] == "none" {
        None
    } else {
        Some(PriorityFee {
            micro_lamports_per_cu: a[5].parse().unwrap(),
            compute_units: a[6].parse().unwrap(),
        })
    };

    let msg =
        build_transfer_message_with_priority(&from, to, lamports, blockhash, priority).unwrap();
    let mut tx = Vec::new();
    tx.extend_from_slice(&shortvec(1));
    tx.extend_from_slice(&[0u8; 64]);
    tx.extend_from_slice(&msg);
    println!("{}", B64.encode(tx));
    eprintln!("message bytes={}", msg.len());
}
