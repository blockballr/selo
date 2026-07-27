// Dev helper for verifying the swap signing path end to end.
//
// Modes:
//   keygen                  prints a throwaway pubkey and secret
//   sign <secret> <tx_b64>  verifies and signs, prints signed base64
//
// The signed output is meant to be handed to simulateTransaction with
// sigVerify enabled: a bad signature fails verification, while a
// correct signature on an unfunded wallet fails on funds instead.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use solana_plugin_core::address::encode_pubkey;
use solana_plugin_core::transfer::Keypair;
use solana_plugin_core::vtx;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args[1].as_str() {
        "keygen" => {
            // Deterministic from a caller-supplied seed byte so runs are
            // reproducible; this is a test helper, never a wallet.
            let seed: u8 = args[2].parse().unwrap();
            let mut bytes = [0u8; 32];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = seed.wrapping_add(i as u8);
            }
            let signing = ed25519_dalek::SigningKey::from_bytes(&bytes);
            let full = signing.to_keypair_bytes();
            println!("pubkey={}", encode_pubkey(&signing.verifying_key().to_bytes()));
            println!("secret={}", bs58::encode(full).into_string());
        }
        "sign" => {
            let kp = Keypair::from_config_value(&args[2]).unwrap();
            let mut tx = B64.decode(args[3].trim()).unwrap();
            let owner = kp.public_key_bytes();
            match vtx::verify_and_sign(&mut tx, &owner, |m| kp.sign_message(m)) {
                Ok(p) => {
                    eprintln!(
                        "verified version={:?} sigs={} keys={} lookups={}",
                        p.version,
                        p.required_signatures,
                        p.static_account_keys.len(),
                        p.address_table_lookup_count
                    );
                    println!("{}", B64.encode(&tx));
                }
                Err(e) => {
                    eprintln!("REFUSED: {e}");
                    std::process::exit(2);
                }
            }
        }
        other => panic!("unknown mode {other}"),
    }
}
