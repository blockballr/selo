mod rpc;

use rpc::ToolRpc;
use selo_core::ledger::CounterpartyRegistry;
use selo_core::solana_pay::{build_solana_pay_url, SolanaPayParams};
use selo_core::store::{QuoteRecord, QuoteStatus, SeloStore};
use selo_core::{brain, AccountingEngine, RpcSeam};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const STORE_PATH: &str = ".selo_store.json";
const RULES_PATH: &str = ".selo_rules.json";
/// loads local state store or initializes a new one.
fn load_store() -> SeloStore {
    if Path::new(STORE_PATH).exists() {
        if let Ok(content) = fs::read_to_string(STORE_PATH) {
            if let Ok(store) = serde_json::from_str(&content) {
                return store;
            }
        }
    }
    SeloStore::new()
}

/// saves state store to disk.
fn save_store(store: &SeloStore) -> Result<(), String> {
    let content = serde_json::to_string_pretty(store).map_err(|e| e.to_string())?;
    fs::write(STORE_PATH, content).map_err(|e| e.to_string())
}

fn load_rules() -> CounterpartyRegistry {
    if Path::new(RULES_PATH).exists() {
        if let Ok(content) = fs::read_to_string(RULES_PATH) {
            if let Ok(registry) = serde_json::from_str(&content) {
                return registry;
            }
        }
    }
    CounterpartyRegistry::new()
}

fn save_rules(registry: &CounterpartyRegistry) -> Result<(), String> {
    let content = serde_json::to_string_pretty(registry).map_err(|e| e.to_string())?;
    fs::write(RULES_PATH, content).map_err(|e| e.to_string())
}

// deterministically derives or generates a single-use reference key string
fn generate_reference_key(now_unix: u64, amount: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(now_unix.to_le_bytes());
    hasher.update(amount.to_le_bytes());
    hasher.update(b"selo_reference_seed");
    let result = hasher.finalize();
    bs58::encode(result).into_string()
}

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Selo Accounting Engine CLI");
        println!("Usage: selo-tool <command> [args]");
        println!("\nCommands:");
        println!("  balance <pubkey>                                 Query account balance");
        println!(
            "  quote <sku> [qty]                                Generate legacy catalog quote"
        );
        println!("  issue --amount <lamports> --recipient <pubkey>   Issue a Solana Pay quote with reference key");
        println!("  check                                            Inspect store status and pending quotes");
        println!("  confirm                                          Reconcile pending quotes with on-chain transactions");
        println!("  expire                                           Sweep expired pending quotes in store");
        println!("  rules [--add <pubkey> --name <label>]            Manage counterparty entity mapping rules");
        println!("  backfill <pubkey>                                Paginate and list historical transactions");
        println!("  blockhash                                        Fetch latest blockhash");
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
            let now_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
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
        "issue" => {
            let mut amount: u64 = 500_000_000;
            let mut recipient: String = String::new();
            let mut label: Option<String> = None;
            let mut message: Option<String> = None;

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--amount" => {
                        if let Some(val) = args.get(i + 1) {
                            amount = val.parse().unwrap_or(amount);
                        }
                        i += 2;
                    }
                    "--recipient" => {
                        if let Some(val) = args.get(i + 1) {
                            recipient = val.clone();
                        }
                        i += 2;
                    }
                    "--label" => {
                        if let Some(val) = args.get(i + 1) {
                            label = Some(val.clone());
                        }
                        i += 2;
                    }
                    "--message" => {
                        if let Some(val) = args.get(i + 1) {
                            message = Some(val.clone());
                        }
                        i += 2;
                    }
                    _ => i += 1,
                }
            }

            if recipient.is_empty() {
                return Err("Missing required argument: --recipient <pubkey>".to_string());
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();

            let expires_at = now + 900;
            let ref_key = generate_reference_key(now, amount);
            let quote_id = format!("q_{:.8}", ref_key);

            let record = QuoteRecord {
                id: quote_id.clone(),
                recipient: recipient.clone(),
                amount_lamports: amount,
                reference_pubkey: ref_key.clone(),
                created_at: now,
                expires_at,
                status: QuoteStatus::Pending,
                label: label.clone(),
                message: message.clone(),
            };

            let pay_params = SolanaPayParams {
                recipient: &recipient,
                amount_lamports: amount,
                reference_pubkey: &ref_key,
                label: label.as_deref(),
                message: message.as_deref(),
            };

            let pay_url = build_solana_pay_url(&pay_params);

            let mut store = load_store();
            store.add_quote(record);
            store.updated_at = now;
            save_store(&store)?;

            println!("✓ Quote Issued Successfully [{}]", quote_id);
            println!("  Reference Key : {}", ref_key);
            println!("  Solana Pay URI: {}", pay_url);
            println!("  Expires At    : {}", expires_at);
        }
        "check" => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();

            let mut store = load_store();
            let expired_count = store.prune_expired(now);
            if expired_count > 0 {
                store.updated_at = now;
                save_store(&store)?;
            }

            let summary = store.get_summary();
            let pending = store.get_pending_quotes();

            println!("Selo Accounting Store Status");
            println!("Total Quotes Stored : {}", summary.total);
            println!("Pending Quotes      : {}", summary.pending);
            println!("Settled Quotes      : {}", summary.settled);
            println!("Expired Quotes      : {}", summary.expired);
            if expired_count > 0 {
                println!("! Auto-expired {} quote(s) during check.", expired_count);
            }
            println!("{:-<60}", "");

            for q in pending {
                let sol_amount = q.amount_lamports as f64 / 1_000_000_000.0;
                let remaining_secs = q.expires_at.saturating_sub(now);
                println!(
                    "ID: {} | Amount: {} SOL | Ref: {:.12}... | TTL: {}s | Label: {}",
                    q.id,
                    sol_amount,
                    q.reference_pubkey,
                    remaining_secs,
                    q.label.as_deref().unwrap_or("N/A")
                );
            }
        }
        "confirm" => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();

            let mut store = load_store();
            let expired_count = store.prune_expired(now);

            let pending_items: Vec<(String, String)> = store
                .quotes
                .iter()
                .filter_map(|q| {
                    if matches!(q.status, QuoteStatus::Pending) {
                        Some((q.id.clone(), q.reference_pubkey.clone()))
                    } else {
                        None
                    }
                })
                .collect();

            if pending_items.is_empty() {
                if expired_count > 0 {
                    store.updated_at = now;
                    save_store(&store)?;
                    println!(
                        "Auto-expired {} quote(s). No active pending quotes to reconcile.",
                        expired_count
                    );
                } else {
                    println!("No pending quotes to reconcile.");
                }
                return Ok(());
            }

            println!(
                "Scanning on-chain signatures for {} pending quote(s)...",
                pending_items.len()
            );

            let mut settled_count = 0;

            for (quote_id, ref_key) in pending_items {
                match engine.rpc.get_signatures(&ref_key) {
                    Ok(sigs) if !sigs.is_empty() => {
                        let tx_sig = sigs[0].clone();
                        if store.settle_quote(&quote_id, tx_sig.clone(), now) {
                            println!("✓ Quote [{}] SETTLED via Tx: {}", quote_id, tx_sig);
                            settled_count += 1;
                        }
                    }
                    Ok(_) => {
                        println!("  Quote [{}] - Pending (no transactions found)", quote_id);
                    }
                    Err(e) => {
                        eprintln!(
                            "  Quote [{}] - Warning fetching RPC signatures: {}",
                            quote_id, e
                        );
                    }
                }
            }

            if settled_count > 0 || expired_count > 0 {
                store.updated_at = now;
                save_store(&store)?;
                println!("------------------------------------------------------------");
                println!(
                    "Reconciliation complete. Settled {} quote(s), expired {} quote(s).",
                    settled_count, expired_count
                );
            } else {
                println!("------------------------------------------------------------");
                println!("Reconciliation complete. No new settlements detected.");
            }
        }
        "expire" => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();

            let mut store = load_store();
            let expired_count = store.prune_expired(now);

            if expired_count > 0 {
                store.updated_at = now;
                save_store(&store)?;
                println!("✓ Expired {} quote(s) past TTL validity.", expired_count);
            } else {
                println!("No quotes required expiry.");
            }

            let summary = store.get_summary();
            println!(
                "Store Status -> Pending: {} | Settled: {} | Expired: {}",
                summary.pending, summary.settled, summary.expired
            );
        }
        "rules" => {
            let mut rules = load_rules();

            if args.len() >= 5 && args[2] == "--add" {
                let pubkey = args[3].clone();
                let name = if args.len() >= 6 && args[4] == "--name" {
                    args[5].clone()
                } else {
                    "Custom Entity".to_string()
                };

                rules.add_rule(pubkey.clone(), name.clone());
                save_rules(&rules)?;
                println!("✓ Added counterparty rule: {} -> {}", pubkey, name);
                return Ok(());
            }

            println!("Selo Counterparty Rules ({})", rules.count());
            println!("{:-<60}", "");
            for (pubkey, name) in &rules.rules {
                println!("  {} => {}", pubkey, name);
            }
        }
        "backfill" => {
            let address = args
                .get(2)
                .ok_or("Missing public key address for backfill")?;
            let rules = load_rules();
            let entity_label = rules.get_name(address);
            println!(
                "Backfilling transaction signatures for: {} [{}]",
                address, entity_label
            );

            let backfiller = selo_core::ledger::Backfiller::new(&engine.rpc);
            let signatures = backfiller.backfill(address)?;

            println!("Found {} signature(s):", signatures.len());
            for (idx, sig) in signatures.iter().enumerate() {
                println!("  {:02}. {}", idx + 1, sig);
            }
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
