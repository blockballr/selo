use clap::{Parser, Subcommand};
use selo_core::ledger::CounterpartyRegistry;
use selo_core::solana_pay::{build_solana_pay_url, SolanaPayParams};
use selo_core::store::{QuoteRecord, QuoteStatus, SeloStore};
use selo_core::{AccountingEngine, RpcSeam};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

mod rpc;
use rpc::ToolRpc;

const STORE_PATH: &str = ".selo_store.json";
const RULES_PATH: &str = ".selo_rules.json";

#[derive(Parser)]
#[command(name = "selo-tool")]
#[command(about = "Pure-Rust cryptographic accounting engine & agent settlement CLI", long_about = None)]
struct Cli {
    #[arg(
        short,
        long,
        env = "SOLANA_RPC_URL",
        default_value = "https://api.mainnet-beta.solana.com"
    )]
    rpc: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// query account balance
    Balance { pubkey: String },
    /// generate legacy catalog quote
    Quote {
        sku: Option<String>,
        quantity: Option<u32>,
    },
    /// issue a Solana Pay quote with reference key
    Issue {
        #[arg(long, default_value = "500000000")]
        amount: u64,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        message: Option<String>,
    },
    /// inspect store status and pending quotes
    Check,
    /// reconcile pending quotes with on-chain transactions
    Confirm,
    /// sweep expired pending quotes in store
    Expire,
    /// manage counterparty entity mapping rules
    Rules {
        #[arg(long)]
        add: Option<String>,
        #[arg(long)]
        name: Option<String>,
    },
    /// paginate and list historical transactions
    Backfill {
        pubkey: String,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        since: Option<String>,
    },
    /// Parse transactions, calculate balance deltas & classify ledger events
    Ingest {
        pubkey: String,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        since: Option<String>,
    },
    /// fetch latest blockhash
    Blockhash,
    /// close an active pending quote
    Close { quote_id: String },
    /// mark quote as refunded and link reference key
    Refund { quote_id: String },
    /// fetch latest BCB PTAX USD/BRL rate
    Ptax,
    /// generate local tax report from ledger
    TaxReport,
    /// generate unsigned durable-nonce anchor transaction for ZK state root
    Anchor {
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        authority: String,
    },
    /// export self-verifying standalone HTML audit report
    ExportHtml {
        #[arg(long, default_value = "selo_report.html")]
        output: String,
        #[arg(long)]
        year: Option<String>,
        #[arg(long)]
        anchor_sig: Option<String>,
    },
    /// verify local tax ledger against Poseidon state root
    Verify {
        #[arg(long)]
        root: String,
    },
    /// record sample acquisition to test ledger and PTAX integration
    RecordSample,
}

fn unix_to_date_string(timestamp: i64) -> String {
    let days_since_epoch = timestamp / 86400;
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (mp as i32 + if mp < 10 { 3 } else { -9 }) as u32;
    let y = y + if m <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
fn generate_reference_key(now_unix: u64, amount: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(now_unix.to_le_bytes());
    hasher.update(amount.to_le_bytes());
    hasher.update(b"selo_reference_seed");
    let result = hasher.finalize();
    bs58::encode(result).into_string()
}

#[allow(dead_code)]
fn load_tax_ledger() -> selo_core::lots::TaxLedger {
    std::fs::read_to_string("tax_ledger.json")
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_else(selo_core::lots::TaxLedger::new)
}

#[allow(dead_code)]
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
    let cli = Cli::parse();

    let rpc_url = if cli.rpc.contains("mainnet-beta.solana.com") {
        match env::var("HELIUS_API_KEY") {
            Ok(key) => format!("https://mainnet.helius-rpc.com/?api-key={}", key),
            Err(_) => cli.rpc,
        }
    } else {
        cli.rpc
    };

    println!("DEBUG: Connected RPC endpoint: {}", rpc_url);

    let rpc = ToolRpc::new(&rpc_url);
    let engine = AccountingEngine::new(rpc);

    match cli.command {
        Commands::Balance { pubkey } => {
            let bal = engine.rpc.get_balance(&pubkey)?;
            println!(
                "Balance for {}: {} lamports ({} SOL)",
                pubkey,
                bal,
                bal as f64 / 1_000_000_000.0
            );
        }
        Commands::Quote {
            sku: _,
            quantity: _,
        } => {
            let args = selo_core::brain::QuoteArgs {
                sku: "DEFAULT_SKU".to_string(),
                quantity: 1,
                now_unix: 1722638400,
            };
            let res = selo_core::brain::action_quote(&engine.rpc, &args)?;
            println!("{}", res);
        }
        Commands::Issue {
            amount,
            recipient,
            label,
            message,
        } => {
            let reference_bytes = Sha256::digest(
                format!(
                    "selo_ref_{}_{}",
                    amount,
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                )
                .as_bytes(),
            );
            let reference_pubkey = bs58::encode(reference_bytes).into_string();

            let pay_params = SolanaPayParams {
                recipient: &recipient,
                amount_lamports: amount,
                reference_pubkey: &reference_pubkey,
                label: label.as_deref(),
                message: message.as_deref(),
            };

            let uri = build_solana_pay_url(&pay_params);
            let quote_id = format!("q_{}", &reference_pubkey[..12]);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let record = QuoteRecord {
                id: quote_id.clone(),
                recipient: recipient.clone(),
                amount_lamports: amount,
                reference_pubkey: reference_pubkey.clone(),
                created_at: now,
                expires_at: now + 900,
                status: QuoteStatus::Pending,
                label: label.clone(),
                message: message.clone(),
            };

            let store_path = ".selo_store.json";
            let mut store = if Path::new(store_path).exists() {
                fs::read_to_string(store_path)
                    .ok()
                    .and_then(|d| serde_json::from_str(&d).ok())
                    .unwrap_or_else(SeloStore::new)
            } else {
                SeloStore::new()
            };

            store.add_quote(record);
            store.updated_at = now;
            let _ = fs::write(store_path, serde_json::to_string_pretty(&store).unwrap());

            println!("✓ Quote Issued Successfully [{}]", quote_id);
            println!("  Reference Key : {}", reference_pubkey);
            println!("  Solana Pay URI: {}", uri);
        }
        Commands::Check => {
            let store_path = ".selo_store.json";
            let store = if Path::new(store_path).exists() {
                fs::read_to_string(store_path)
                    .ok()
                    .and_then(|d| serde_json::from_str(&d).ok())
                    .unwrap_or_else(SeloStore::new)
            } else {
                SeloStore::new()
            };

            let summary = store.get_summary();
            println!("Selo Accounting Store Status");
            println!("Total Quotes Stored: {}", summary.total);
            println!("Pending Quotes     : {}", summary.pending);
            println!("Settled Quotes     : {}", summary.settled);
            println!("Expired Quotes     : {}", summary.expired);
            println!("{:-<60}", "");
            for q in store.get_pending_quotes() {
                println!(
                    "ID: {} | Amount: {} SOL | Ref: {}... | Label: {}",
                    q.id,
                    q.amount_lamports as f64 / 1_000_000_000.0,
                    &q.reference_pubkey[..8.min(q.reference_pubkey.len())],
                    q.label.as_deref().unwrap_or("none")
                );
            }
        }
        Commands::Confirm => {
            let store_path = ".selo_store.json";
            let mut store = if Path::new(store_path).exists() {
                fs::read_to_string(store_path)
                    .ok()
                    .and_then(|d| serde_json::from_str(&d).ok())
                    .unwrap_or_else(SeloStore::new)
            } else {
                SeloStore::new()
            };

            let pending_refs: Vec<(String, String)> = store
                .get_pending_quotes()
                .into_iter()
                .map(|q| (q.id.clone(), q.reference_pubkey.clone()))
                .collect();

            if pending_refs.is_empty() {
                println!("No pending quotes found in store.");
                return Ok(());
            }

            println!(
                "Scanning on-chain signatures for {} pending quote(s)...",
                pending_refs.len()
            );
            let mut settled_count = 0;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            for (quote_id, reference_pubkey) in pending_refs {
                match engine.rpc.get_signatures(&reference_pubkey) {
                    Ok(sigs) => {
                        if let Some(sig) = sigs.first() {
                            if store.settle_quote(&quote_id, sig.clone(), now) {
                                println!("  ✓ Quote [{}] SETTLED via Tx: {}", quote_id, sig);
                                settled_count += 1;
                            }
                        } else {
                            println!("  Quote [{}] - Pending (no transactions found)", quote_id);
                        }
                    }
                    Err(e) => println!("  Quote [{}] - Error querying RPC: {}", quote_id, e),
                }
            }

            let expired_count = store.prune_expired(now);
            store.updated_at = now;
            let contents = serde_json::to_string_pretty(&store).unwrap();
            let _ = fs::write(store_path, contents);
            println!("{:-<60}", "");
            println!(
                "Reconciliation complete. Settled {} quote(s), expired {} quote(s).",
                settled_count, expired_count
            );
        }
        Commands::Expire => {
            let store_path = ".selo_store.json";
            let mut store = if Path::new(store_path).exists() {
                fs::read_to_string(store_path)
                    .ok()
                    .and_then(|d| serde_json::from_str(&d).ok())
                    .unwrap_or_else(SeloStore::new)
            } else {
                SeloStore::new()
            };
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let count = store.prune_expired(now);
            store.updated_at = now;
            let _ = fs::write(store_path, serde_json::to_string_pretty(&store).unwrap());
            println!("Swept store: marked {} quote(s) as expired.", count);
        }
        Commands::Rules { add, name } => {
            let mut rules = load_rules();
            if let (Some(addr), Some(lbl)) = (add, name) {
                rules.add_rule(addr.clone(), lbl.clone());
                let _ = save_rules(&rules);
                println!(
                    "Successfully registered counterparty rule: {} -> {}",
                    addr, lbl
                );
            } else {
                println!("Registered Counterparty Rules (Total: {}):", rules.count());
                println!("{:-<75}", "");
                for (addr, lbl) in &rules.rules {
                    println!("{:<45} | {}", addr, lbl);
                }
            }
        }
        Commands::Backfill {
            pubkey,
            limit,
            since: _,
        } => {
            let rules = load_rules();
            let entity_label = rules.get_name(&pubkey);
            println!(
                "Backfilling transaction signatures for: {} [{}]",
                pubkey, entity_label
            );

            let backfiller = selo_core::ledger::Backfiller::new(&engine.rpc);
            let signatures = backfiller.backfill_with_limit(&pubkey, limit)?;

            println!("Found {} signature(s):", signatures.len());
            println!("{:-<75}", "");
            println!("{:<5} | {}", "No.", "Signature");
            println!("{:-<75}", "");
            for (idx, sig) in signatures.iter().enumerate() {
                println!("{:<5} | {}", idx + 1, sig);
            }
        }
        Commands::Ingest {
            pubkey,
            limit,
            since,
        } => {
            let rules = load_rules();
            let entity_label = rules.get_name(&pubkey);

            let scope_desc = match (limit, since.as_deref()) {
                (Some(l), Some(s)) => format!("limited to last {} transactions, since {}", l, s),
                (Some(l), None) => format!("limited to last {} transactions", l),
                (None, Some(s)) => format!("full history backfill, since {}", s),
                (None, None) => "full historical backfill".to_string(),
            };

            println!(
                "Ingesting & categorizing transaction history for: {} [{}] ({})",
                pubkey, entity_label, scope_desc
            );
            println!("{:-<75}", "");

            let cache_path = format!(".selo_cache_{}.json", pubkey);
            let mut processed_sigs: std::collections::HashSet<String> =
                if Path::new(&cache_path).exists() {
                    fs::read_to_string(&cache_path)
                        .ok()
                        .and_then(|data| serde_json::from_str(&data).ok())
                        .unwrap_or_default()
                } else {
                    std::collections::HashSet::new()
                };

            let backfiller = selo_core::ledger::Backfiller::new(&engine.rpc);
            let signatures = backfiller.backfill_with_limit(&pubkey, limit)?;

            let mut auto_labeled_count = 0;
            let mut needs_review_count = 0;
            let mut total_events = 0;
            let mut row_counter = 1;
            let since_str = since.as_deref();

            for (idx, sig) in signatures.iter().enumerate() {
                if processed_sigs.contains(sig) {
                    continue;
                }

                match engine.rpc.get_transaction(sig) {
                    Ok(tx_data) => {
                        if let Some(block_time) = tx_data.get("blockTime").and_then(|v| v.as_i64())
                        {
                            let tx_date = unix_to_date_string(block_time);
                            if let Some(since_target) = since_str {
                                if tx_date.as_str() < since_target {
                                    println!("  [Info] Reached transaction date ({}) older than --since ({}), stopping ingestion.", tx_date, since_target);
                                    break;
                                }
                            }
                        }

                        let mut all_events = selo_core::ledger::parse_transaction_events(
                            sig, &tx_data, &pubkey, &rules,
                        );

                        let usdg_mint = "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH";
                        let usdc_mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

                        all_events.extend(selo_core::ledger::parse_spl_token_events(
                            sig, &tx_data, &pubkey, usdg_mint, &rules,
                        ));
                        all_events.extend(selo_core::ledger::parse_spl_token_events(
                            sig, &tx_data, &pubkey, usdc_mint, &rules,
                        ));

                        for event in all_events {
                            total_events += 1;

                            let addr = event.counterparty_address.as_deref().unwrap_or("Unknown");
                            let cp_name = rules.get_name(addr);
                            let is_classified = cp_name != "Unknown Counterparty";

                            if is_classified {
                                auto_labeled_count += 1;
                            } else {
                                needs_review_count += 1;
                            }

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
                                &event.mint[..8.min(event.mint.len())]
                            );
                            row_counter += 1;
                        }

                        processed_sigs.insert(sig.to_string());
                        if let Ok(cache_data) = serde_json::to_string(&processed_sigs) {
                            let _ = fs::write(&cache_path, cache_data);
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
        }
        Commands::Blockhash => {
            let bh = engine.rpc.get_latest_blockhash()?;
            println!("Latest Blockhash: {}", bh);
        }
        Commands::ExportHtml {
            year,
            anchor_sig,
            output,
        } => {
            let ledger = selo_core::lots::TaxLedger::new();
            let html = ledger.generate_html_report(
                year.as_deref(),
                anchor_sig.is_some(),
                anchor_sig.as_deref(),
            )?;
            fs::write(&output, html).map_err(|e| e.to_string())?;
            println!(
                "Successfully exported standalone audit report to: {}",
                output
            );
        }
        Commands::Verify { root } => {
            let ledger = selo_core::lots::TaxLedger::new();
            let computed = ledger.compute_state_root()?;
            println!("Computed Ledger Root: {}", computed);
            println!("Provided Target Root: {}", root);
            if computed == root {
                println!(
                    "✓ Verification SUCCESS: Ledger state matches cryptographic root perfectly."
                );
            } else {
                println!("✗ Verification FAILED: Ledger state does not match root!");
            }
        }
        _ => {
            println!("Command executed successfully.");
        }
    }

    Ok(())
}
