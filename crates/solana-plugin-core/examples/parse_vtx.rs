// Dev helper: parse a base64 transaction and report its structure.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use solana_plugin_core::address::encode_pubkey;
use solana_plugin_core::vtx::parse_transaction;

fn main() {
    let b64 = std::env::args().nth(1).unwrap();
    let tx = B64.decode(b64.trim()).unwrap();
    let p = parse_transaction(&tx).unwrap();
    println!("version={:?}", p.version);
    println!("required_signatures={}", p.required_signatures);
    println!("message_offset={}", p.message_offset);
    println!("static_keys={}", p.static_account_keys.len());
    println!("instructions={}", p.instruction_count);
    println!("lookup_tables={}", p.address_table_lookup_count);
    println!("fee_payer={}", encode_pubkey(&p.fee_payer().unwrap()));
}
