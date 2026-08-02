mod rpc;
mod store_io;

use rpc::ToolRpc;
use selo_core::{brain, store::QuoteRecord, store::QuoteStatus, AccountingEngine, RpcSeam};
use std::env;

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Selo Accounting Engine CLI");
        println!("Usage: selo-tool <command> [args]");
        println!("\nCommands:");
        println!("  issue <sku> [qty]       Issue a quote intent and save to local store");
        println!("  check [quote_id]        Check payment/reconciliation status of quotes");
        println!("  balance <pubkey>        Query account balance from Solana network");
        println!("  blockhash               Fetch latest blockhash");
        return Ok(());
    }

    let rpc_url = env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());

    let rpc = ToolRpc::new(&rpc_url);
    let engine = AccountingEngine::new(rpc);

    match args[1].as_str() {
        "issue" => {
            let sku = args
                .get(2)
                .cloned()
                .unwrap_or_else(|| "SKU-SOL-100".to_string());
            let quantity: u32 = args.get(3).and_then(|q| q.parse().ok()).unwrap_or(1);

            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs() as i64;

            let quote_args = brain::QuoteArgs {
                sku: sku.clone(),
                quantity,
                now_unix,
            };

            // Call core brain engine
            let _quote_response = brain::action_quote(&engine.rpc, &quote_args)?;

            // Generate deterministic record entry
            let quote_id = format!("Q-{}", now_unix % 100000);
            let dummy_ref_pubkey = format!("RefPDA{}", now_unix % 1000);
            let record = QuoteRecord {
                id: quote_id.clone(),
                sku,
                quantity,
                amount_lamports: (quantity as u64) * 100_000_000, // standard lamport amount
                reference_pubkey: dummy_ref_pubkey,
                created_at: now_unix,
                status: QuoteStatus::Pending,
            };

            // Persist to local store
            let mut store = store_io::load_store();
            store.add_quote(record);
            store_io::save_store(&store)?;

            println!("✅ Quote Issued and Saved to Store!");
            println!("   ID: {}", quote_id);
            println!("   Status: Pending");
        }

        "check" => {
            let store = store_io::load_store();
            let target_id = args.get(2);

            match target_id {
                Some(id) => match store.find_quote(id) {
                    Some(q) => {
                        println!("Quote Details for [{}]", q.id);
                        println!("  SKU: {}", q.sku);
                        println!("  Quantity: {}", q.quantity);
                        println!("  Lamports: {}", q.amount_lamports);
                        println!("  Status: {:?}", q.status);
                    }
                    None => println!("❌ Quote ID [{}] not found in local store.", id),
                },
                None => {
                    println!("Stored Quotes (Total: {}):", store.list_quotes().len());
                    for q in store.list_quotes() {
                        println!(
                            "  - [{}] SKU: {} | Qty: {} | Status: {:?}",
                            q.id, q.sku, q.quantity, q.status
                        );
                    }
                }
            }
        }

        "balance" => {
            let address = args.get(2).ok_or("Missing public key address")?;
            let balance = engine.rpc.get_balance(address)?;
            println!("Balance for {}: {} lamports", address, balance);
        }

        "blockhash" => {
            let hash = engine.rpc.get_latest_blockhash()?;
            println!("Latest blockhash: {}", hash);
        }

        _ => println!("Unknown command: {}", args[1]),
    }

    Ok(())
}
