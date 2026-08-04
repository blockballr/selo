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
fn load_tax_ledger() -> selo_core::lots::TaxLedger {
    std::fs::read_to_string("tax_ledger.json")
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_else(selo_core::lots::TaxLedger::new)
}

fn format_timestamp_utc(unix_secs: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days_since_epoch = unix_secs / secs_per_day;
    let year = 1970 + (days_since_epoch / 365);
    let remainder_days = days_since_epoch % 365;
    let month = (remainder_days / 30) + 1;
    let day = (remainder_days % 30) + 1;
    let hours = (unix_secs % secs_per_day) / 3600;
    let mins = (unix_secs % 3600) / 60;

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        year,
        month.min(12),
        day.min(31),
        hours,
        mins
    )
}

#[allow(dead_code)]
fn save_tax_ledger(ledger: &selo_core::lots::TaxLedger) {
    if let Ok(data) = serde_json::to_string_pretty(ledger) {
        let _ = std::fs::write("tax_ledger.json", data);
    }
}

fn main() -> Result<(), String> {
    dotenvy::dotenv().ok();
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
        println!("  ingest <pubkey>                                  Parse transactions, calculate balance deltas & classify ledger events");
        println!("  blockhash                                        Fetch latest blockhash");
        println!("  anchor --nonce <pubkey> --authority <pubkey>     Generate unsigned durable-nonce anchor transaction for ZK state root");
        return Ok(());
    }

    let rpc_url = match env::var("HELIUS_API_KEY") {
        Ok(key) => format!("https://mainnet.helius-rpc.com/?api-key={}", key),
        Err(_) => env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com".to_string()),
    };

    println!("DEBUG: Attempting to connect to: {}", rpc_url);

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

            let readable_expire = format_timestamp_utc(expires_at); // conversion human-readable time

            println!("✓ Quote Issued Successfully [{}]", quote_id);
            println!("  Reference Key : {}", ref_key);
            println!("  Solana Pay URI: {}", pay_url);
            println!(
                "  Expires At    : {} (utc: {})",
                expires_at, readable_expire
            );
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
            println!("{:-<75}", "");
            println!(
                "{:<12} | {:<12} | {:<20} | {:<8} | {}",
                "ID", "Amount", "Reference", "TTL", "Label"
            );
            println!("{:-<75}", "");

            for q in pending {
                let sol_amount = q.amount_lamports as f64 / 1_000_000_000.0;
                let remaining_secs = q.expires_at.saturating_sub(now);
                println!(
                    "{:<12} | {:>10.6} SOL | {:<20} | {:<8} | {}",
                    q.id,
                    sol_amount,
                    format!("{:.12}...", q.reference_pubkey),
                    format!("{}s", remaining_secs),
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
            println!("{:-<75}", "");
            println!("{:<5} | {}", "No.", "Signature");
            println!("{:-<75}", "");
            for (idx, sig) in signatures.iter().enumerate() {
                println!("{:<5} | {}", idx + 1, sig);
            }
        }
        "ingest" => {
            let address = args
                .get(2)
                .ok_or("Missing public key address for ingestion")?;
            let rules = load_rules();
            let entity_label = rules.get_name(address);

            println!(
                "Ingesting & categorizing transaction history for: {} [{}]",
                address, entity_label
            );
            println!("{:-<75}", "");

            let backfiller = selo_core::ledger::Backfiller::new(&engine.rpc);
            let signatures = backfiller.backfill(address)?;

            let mut auto_labeled_count = 0;
            let mut needs_review_count = 0;
            let mut total_events = 0;
            let mut row_counter = 1;

            for (idx, sig) in signatures.iter().enumerate() {
                match engine.rpc.get_transaction(sig) {
                    Ok(tx_data) => {
                        let mut all_events = selo_core::ledger::parse_transaction_events(
                            sig, &tx_data, address, &rules,
                        );

                        let usdg_mint = "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH";
                        let usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

                        all_events.extend(selo_core::ledger::parse_spl_token_events(
                            sig, &tx_data, address, usdg_mint, &rules,
                        ));
                        all_events.extend(selo_core::ledger::parse_spl_token_events(
                            sig, &tx_data, address, usdc_mint, &rules,
                        ));

                        for event in all_events {
                            total_events += 1;

                            // Identify counterparty
                            let addr = event.counterparty_address.as_deref().unwrap_or("Unknown");
                            let cp_name = rules.get_name(addr);
                            let is_classified = cp_name != "Unknown Counterparty";

                            // mutually exclusive
                            if is_classified {
                                auto_labeled_count += 1;
                            } else {
                                needs_review_count += 1;
                            }

                            // UI: slice addr
                            let label = if is_classified {
                                cp_name
                            } else {
                                rules.format_address(addr)
                            };

                            let amount_display: f64 =
                                event.amount_base_units as f64 / 1_000_000_000.0;
                            println!(
                                "  {:02}. {:<12} | {:>10.6} | CP: {:<26} | Mint: {}...",
                                row_counter,
                                event.kind.as_str(),
                                amount_display,
                                label,
                                &event.mint[..8]
                            );
                            row_counter += 1
                        }
                    }
                    Err(e) => println!("  {:02}. Sig: {} | Error: {}", idx + 1, sig, e),
                }
            }

            println!("{:-<75}", "");
            println!(
                "Ingestion Summary -> Total Events: {} | Auto-Labeled: {} | Needs Review: {}",
                total_events, auto_labeled_count, needs_review_count
            );

            if needs_review_count > 0 {
                println!("Hint: Use 'selo-tool rules --add <pubkey> --name <label>' to classify remaining unknown counterparties.");
            }
        }
        "blockhash" => {
            let hash = engine.rpc.get_latest_blockhash()?;
            println!("Latest blockhash: {}", hash);
        }
        "close" => {
            let quote_id = args
                .get(2)
                .ok_or("Missing quote ID. Usage: close <quote_id>")?;
            let mut store = load_store();
            if store.close_quote(quote_id) {
                save_store(&store)?;
                println!("✓ Quote [{}] successfully closed.", quote_id);
            } else {
                println!(
                    "✗ Failed to close quote [{}]. It may not exist or is no longer pending.",
                    quote_id
                );
            }
        }
        "refund" => {
            let quote_id = args
                .get(2)
                .ok_or("Missing quote ID. Usage: refund <quote_id>")?;

            let mut store = load_store();
            // automatically find the quote and use its reference key for the refund signature
            if let Some(quote) = store.quotes.iter().find(|q| q.id == *quote_id) {
                let reference_to_use = quote.reference_pubkey.to_string();
                let refund_sig = format!("refund_tx_for_{}", reference_to_use);

                if store.refund_quote(quote_id, &refund_sig) {
                    save_store(&store)?;
                    println!("✓ Quote [{}] successfully marked as refunded.", quote_id);
                    println!("  Linked Reference : {}", reference_to_use);
                    println!("  Generated Signature: {}", refund_sig);
                } else {
                    println!("✗ Failed to apply refund state to quote [{}].", quote_id);
                }
            } else {
                println!("✗ Quote [{}] not found in store.", quote_id);
            }
        }
        "ptax" => match selo_core::ptax::fetch_latest_ptax() {
            Ok(rate) => println!("✓ Current BCB PTAX USD/BRL Rate: R$ {:.4}", rate),
            Err(e) => println!("✗ Error fetching PTAX rate: {}", e),
        },
        "tax-report" => {
            let ledger = load_tax_ledger();
            match ledger.generate_report() {
                Ok(report_output) => println!("{}", report_output),
                Err(e) => println!("✗ Failed to generate tax report: {}", e),
            }
        }
        "anchor" => {
            let mut nonce_account = String::new();
            let mut authority = String::new();

            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--nonce" => {
                        if let Some(val) = args.get(i + 1) {
                            nonce_account = val.clone();
                        }
                        i += 2;
                    }
                    "--authority" => {
                        if let Some(val) = args.get(i + 1) {
                            authority = val.clone();
                        }
                        i += 2;
                    }
                    _ => i += 1,
                }
            }

            if nonce_account.is_empty() || authority.is_empty() {
                return Err("Missing required arguments. Usage: selo-tool anchor --nonce <pubkey> --authority <pubkey>".to_string());
            }

            let ledger = load_tax_ledger();
            let state_root = ledger.compute_state_root()?;

            let anchor_tx =
                selo_core::nonce::build_anchor_transaction(&nonce_account, &authority, &state_root);

            println!("✓ Unsigned Anchor Transaction Generated Successfully");
            println!("  State Root (Poseidon BN254): {}", anchor_tx.state_root);
            println!("  Durable Nonce Account     : {}", anchor_tx.nonce_account);
            println!("  Nonce Authority           : {}", anchor_tx.authority);
            println!("  Status                    : Awaiting human signature (Never expires via durable nonce)");
            println!("------------------------------------------------------------");
            let json_output =
                serde_json::to_string_pretty(&anchor_tx).map_err(|e| e.to_string())?;
            println!("{}", json_output);
        }
        // "record-sample" => {
        //     let mut ledger = load_tax_ledger();

        //     // Record 1 SOL (1,000,000,000 lamports) acquired today & pull the live PTAX rate automatically
        //     match ledger.record_acquisition(
        //         "lot-SOL-001".to_string(),
        //         "SOL".to_string(),
        //         1_000_000_000,
        //         "2026-08-04T12:00:00Z".to_string(),
        //     ) {
        //         Ok(()) => {
        //             save_tax_ledger(&ledger);
        //             println!("✓ Sample acquisition recorded successfully using current PTAX rate!");
        //         }
        //         Err(e) => println!("✗ Failed to record acquisition: {}", e),
        //     }
        // }
        _ => {
            println!("Unknown command: {}", args[1]);
        }
    }

    Ok(())
}
