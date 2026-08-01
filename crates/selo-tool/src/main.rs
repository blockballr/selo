mod rpc;

use rpc::ToolRpc;
use selo_core::{brain, AccountingEngine, RpcSeam};
use std::env;

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Selo Accounting Engine CLI");
        println!("Usage: selo-tool <command> [args]");
        println!("\nCommands:");
        println!("  balance <pubkey>       Query account balance from Solana network");
        println!("  quote <sku> [qty]      Generate quote using selo-core Brain logic");
        println!("  blockhash              Fetch latest blockhash");
        return Ok(());
    }

    let rpc_url = env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string());

    let rpc = ToolRpc::new(&rpc_url);
    let engine = AccountingEngine::new(rpc);

    match args[1].as_str() {
        "balance" => {
            let address = args.get(2).ok_or("Missing public key address")?;
            let balance = engine.rpc.get_balance(address)?;
            println!("Balance for {}: {} lamports", address, balance);
        }
        "quote" => {
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
                sku,
                quantity,
                now_unix,
            };

            let response = brain::action_quote(&engine.rpc, &quote_args)?;
            println!("{}", response);
        }
        "blockhash" => {
            let hash = engine.rpc.get_latest_blockhash()?;
            println!("Latest blockhash: {}", hash);
        }
        _ => {
            println!("Unknown command: {}", args[1]);
        }
    }

    Ok(())
}
