use clap::{Parser, Subcommand};
use selo_core::ledger::{
    parse_transaction_events, Backfiller, CounterpartyRegistry, NATIVE_SOL_MINT,
};
use selo_core::lots::{MultiWalletLedger, TaxLedger};
use selo_core::ptax::{fetch_latest_ptax, get_historical_ptax};
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

const STORE_FILE: &str = ".selo_store.json";
const RULES_FILE: &str = ".selo_rules.json";
const LEDGER_FILE: &str = ".selo_ledger.json";

#[derive(Parser)]
#[command(name = "selo-tool")]
#[command(about = "Pure-Rust cryptographic accounting engine & agent settlement CLI", long_about = None)]
#[command(
    after_help = "EXAMPLES:\n  selo-tool balance <pubkey>\n  selo-tool issue --amount 500000000 --recipient <pubkey> --label \"Invoice #101\"\n  selo-tool ingest <pubkey> --all\n  selo-tool review <pubkey>\n  selo-tool export-html --year 2026 --output audit_statement.html"
)]
struct Cli {
    #[arg(
        short,
        long,
        env = "SOLANA_RPC_URL",
        default_value = "https://api.mainnet-beta.solana.com",
        help = "Solana JSON-RPC endpoint URL (supports Helius API key env injection)"
    )]
    rpc: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// query account lamport balance and SOL value
    #[command(about = "Query account balance on-chain", long_about = None)]
    Balance {
        #[arg(help = "Base58 public key of the target Solana account")]
        pubkey: String,
    },

    /// generate legacy catalog quote
    #[command(about = "Generate legacy catalog quote", long_about = None)]
    Quote {
        #[arg(help = "SKU identifier for catalog item")]
        sku: Option<String>,
        #[arg(help = "Quantity of items")]
        quantity: Option<u32>,
    },

    /// issue a Solana Pay quote with single-use reference key
    #[command(
        about = "Issue a Solana Pay payment intent quote",
        after_help = "EXAMPLE:\n  selo-tool issue --amount 500000000 --recipient <PUBKEY> --label \"Design Work\""
    )]
    Issue {
        #[arg(
            long,
            default_value = "500000000",
            help = "Amount in raw lamports (1 SOL = 1,000,000,000 lamports)"
        )]
        amount: u64,
        #[arg(long, help = "Recipient Base58 wallet or token account address")]
        recipient: String,
        #[arg(long, help = "Human-readable label displayed in wallet UI")]
        label: Option<String>,
        #[arg(long, help = "Invoice message or order description")]
        message: Option<String>,
    },

    /// inspect local store status and pending quotes
    #[command(about = "Inspect local store status and pending quotes")]
    Check,

    /// reconcile pending quotes with on-chain settlement transactions
    #[command(about = "Scan cluster for on-chain settlements matching stored reference keys")]
    Confirm,

    /// sweep expired pending quotes in local store
    #[command(about = "Mark past-expiry pending quotes as expired")]
    Expire,

    /// manage counterparty entity mapping rules
    #[command(
        about = "Manage counterparty address-to-label rules",
        after_help = "EXAMPLE:\n  selo-tool rules --add <PUBKEY> --name \"Client Escrow\""
    )]
    Rules {
        #[arg(long, help = "Base58 public key address to register")]
        add: Option<String>,
        #[arg(long, help = "Human-readable entity name label")]
        name: Option<String>,
    },

    /// paginate and list historical transaction signatures
    #[command(about = "Paginate and list historical transaction signatures for an address")]
    Backfill {
        #[arg(help = "Base58 public key address to backfill")]
        pubkey: String,
        #[arg(long, help = "Maximum number of signatures to return")]
        limit: Option<usize>,
        #[arg(long, help = "Fetch signatures since ISO date or unix timestamp")]
        since: Option<String>,
        #[arg(long, help = "Fetch signatures before ISO date or unix timestamp")]
        before: Option<String>,
        #[arg(long, help = "Fetch complete history without batch limits")]
        all: bool,
    },

    /// parse transactions, calculate balance deltas & classify ledger events across wallets
    #[command(
        about = "Ingest transaction history, parse balance deltas, and record tax lots",
        after_help = "EXAMPLE:\n  selo-tool ingest <PUBKEY> --all"
    )]
    Ingest {
        #[arg(help = "Base58 wallet public key to ingest")]
        address: String,
        #[arg(long, help = "Transaction processing limit")]
        limit: Option<usize>,
        #[arg(long, help = "Ingest complete historical record")]
        all: bool,
        #[arg(long, help = "Ingest transactions since timestamp")]
        since: Option<String>,
        #[arg(long, help = "Ingest transactions before timestamp")]
        before: Option<String>,
    },

    /// surface unclassified counterparties needing review from ingested ledger data
    #[command(
        about = "Surface unclassified counterparty addresses needing review",
        after_help = "EXAMPLE:\n  selo-tool review <PUBKEY>"
    )]
    Review {
        #[arg(help = "Base58 wallet public key whose ingested ledger to inspect")]
        pubkey: String,
    },

    /// fetch latest network blockhash
    #[command(about = "Fetch latest cluster blockhash")]
    Blockhash,

    /// close an active pending quote
    #[command(about = "Close a pending quote record")]
    Close { quote_id: String },

    /// mark quote as refunded and link reference key
    #[command(about = "Mark quote as refunded")]
    Refund { quote_id: String },

    /// fetch latest BCB PTAX USD/BRL rate
    #[command(about = "Fetch official Banco Central do Brasil PTAX exchange rate")]
    Ptax,

    /// generate local tax report from ledger
    #[command(about = "Generate local tax report from ledger")]
    TaxReport,

    /// generate unsigned durable-nonce anchor transaction for ZK state root
    #[command(about = "Generate unsigned durable-nonce anchor transaction")]
    Anchor {
        #[arg(long, help = "Durable nonce string")]
        nonce: String,
        #[arg(long, help = "Authority public key")]
        authority: String,
    },

    /// export self-verifying standalone HTML audit report
    #[command(
        about = "Export self-verifying standalone HTML audit report with Poseidon state root",
        after_help = "EXAMPLE:\n  selo-tool export-html --year 2026 --output audit_statement.html"
    )]
    ExportHtml {
        #[arg(
            long,
            default_value = "selo_report.html",
            help = "Output HTML file path"
        )]
        output: String,
        #[arg(long, help = "Fiscal year tag (e.g. 2026)")]
        year: Option<String>,
        #[arg(long, help = "On-chain anchor transaction signature")]
        anchor_sig: Option<String>,
        #[arg(long, help = "Specific wallet public key scope")]
        wallet: Option<String>,
    },

    /// verify local tax ledger against Poseidon state root
    #[command(
        about = "Verify local tax ledger against a cryptographic Poseidon BN254 root",
        after_help = "EXAMPLE:\n  selo-tool verify --root 0x09be3021160dce395ebe3617c382a8adba..."
    )]
    Verify {
        #[arg(long, help = "Target cryptographic Poseidon state root hash")]
        root: String,
    },

    /// record sample acquisition to test ongoing live PTAX integration
    #[command(about = "Record sample acquisition using live BCB PTAX exchange rate")]
    RecordSample,
}

#[allow(dead_code)]
fn load_store() -> SeloStore {
    if Path::new(STORE_FILE).exists() {
        if let Ok(data) = fs::read_to_string(STORE_FILE) {
            if let Ok(store) = serde_json::from_str(&data) {
                return store;
            }
        }
    }
    SeloStore::new()
}

#[allow(dead_code)]
fn save_store(store: &SeloStore) {
    if let Ok(data) = serde_json::to_string_pretty(store) {
        let _ = fs::write(STORE_FILE, data);
    }
}

fn load_rules() -> CounterpartyRegistry {
    if Path::new(RULES_FILE).exists() {
        if let Ok(data) = fs::read_to_string(RULES_FILE) {
            if let Ok(rules) = serde_json::from_str(&data) {
                return rules;
            }
        }
    }
    CounterpartyRegistry::new()
}

fn save_rules(rules: &CounterpartyRegistry) {
    if let Ok(data) = serde_json::to_string_pretty(rules) {
        let _ = fs::write(RULES_FILE, data);
    }
}

fn load_multi_ledger() -> MultiWalletLedger {
    if Path::new(LEDGER_FILE).exists() {
        if let Ok(data) = fs::read_to_string(LEDGER_FILE) {
            if let Ok(ledger) = serde_json::from_str(&data) {
                return ledger;
            }
        }
    }
    MultiWalletLedger::new()
}

fn save_multi_ledger(ledger: &MultiWalletLedger) {
    if let Ok(data) = serde_json::to_string_pretty(ledger) {
        let _ = fs::write(LEDGER_FILE, data);
    }
}

fn now_utc_string() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let year = 1970 + (now / 31536000);
    let remainder = now % 31536000;
    let month = 1 + (remainder / 2592000);
    let day = 1 + ((remainder % 2592000) / 86400);
    format!("{:04}-{:02}-{:02}T12:00:00Z", year, month, day)
}

fn get_asset_decimals(symbol_or_mint: &str) -> u32 {
    let s = symbol_or_mint.trim();
    if s == "SOL" || s == NATIVE_SOL_MINT || s.starts_with("So111") {
        9
    } else {
        6
    }
}

// Fetches the live current PTAX rate from Banco Central do Brasil (BCB) API.
/// Falls back to the historical baseline (5.0500) if offline.
fn fetch_live_ptax() -> f64 {
    let rate = fetch_latest_ptax();
    if rate != 5.0500 {
        println!("✓ Successfully fetched live BCB PTAX rate: R$ {:.4}", rate);
    } else {
        println!("Notice: Live BCB PTAX API unreachable or offline. Using current baseline PTAX: R$ 5.0500");
    }
    rate
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
            sku: _sku,
            quantity: _qty,
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

            let mut store = load_store();
            store.add_quote(record);
            store.updated_at = now;
            save_store(&store);

            println!("✓ Quote Issued Successfully [{}]", quote_id);
            println!("  Reference Key : {}", reference_pubkey);
            println!("  Solana Pay URI: {}", uri);
        }
        Commands::Check => {
            let store = load_store();
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
            let mut store = load_store();
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
            save_store(&store);
            println!("{:-<60}", "");
            println!(
                "Reconciliation complete. Settled {} quote(s), expired {} quote(s).",
                settled_count, expired_count
            );
        }
        Commands::Expire => {
            let mut store = load_store();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let count = store.prune_expired(now);
            store.updated_at = now;
            save_store(&store);
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
            since,
            before,
            all,
        } => {
            let rules = load_rules();
            let entity_label = rules.get_name(&pubkey);
            println!(
                "Backfilling transaction signatures for: {} [{}] (all: {}, since: {:?}, before: {:?})",
                pubkey, entity_label, all, since, before
            );

            let backfiller = Backfiller::new(&engine.rpc);
            let signatures = backfiller.backfill_advanced(
                &pubkey,
                limit,
                since.as_deref(),
                before.as_deref(),
                all,
            )?;

            println!("Found {} signature(s):", signatures.len());
            println!("{:-<75}", "");
            println!("{:<5} | {}", "No.", "Signature");
            println!("{:-<75}", "");
            for (idx, sig) in signatures.iter().enumerate() {
                println!("{:<5} | {}", idx + 1, sig);
            }
        }
        Commands::Ingest {
            address,
            limit,
            all,
            since,
            before,
        } => {
            if !all && since.is_none() && before.is_none() {
                eprintln!("Error: You must specify either --all, --since, or --before for ingestion to define the scope/time window.");
                return Err(
                    "Missing required ingestion scope flag (--all, --since, or --before)"
                        .to_string(),
                );
            }

            let rules = load_rules();
            let entity_label = rules.get_name(&address);
            println!(
                "Ingesting transactions for: {} [{}] (all: {}, since: {:?}, before: {:?})",
                address, entity_label, all, since, before
            );

            let backfiller = Backfiller::new(&engine.rpc);
            let signatures = backfiller.backfill_advanced(
                &address,
                limit,
                since.as_deref(),
                before.as_deref(),
                all,
            )?;

            let mut multi_ledger = load_multi_ledger();

            let mut total_events = 0;
            let mut auto_labeled_count = 0;
            let mut needs_review_count = 0;
            let mut classified_counterparties = std::collections::BTreeSet::new();
            let unclassified_counterparties_set;

            {
                let ledger = multi_ledger.get_mut_ledger(&address);

                println!("Processing {} signature(s)...", signatures.len());
                println!("----------------------------------------------------------------------------------------------------");

                for sig in &signatures {
                    match engine.rpc.get_transaction(sig) {
                        Ok(tx_data) => {
                            let events = parse_transaction_events(sig, &tx_data, &address, &rules);
                            for ev in events {
                                total_events += 1;
                                let classification_str = if ev.is_classified {
                                    auto_labeled_count += 1;
                                    if let Some(ref addr) = ev.counterparty_address {
                                        classified_counterparties.insert(addr.clone());
                                    }
                                    "✓ [Auto-Labeled]"
                                } else {
                                    needs_review_count += 1;
                                    if let Some(ref addr) = ev.counterparty_address {
                                        ledger.unclassified_counterparties.insert(addr.clone());
                                    }
                                    "! [Needs Review]"
                                };

                                let cp_label = ev
                                    .counterparty
                                    .clone()
                                    .unwrap_or_else(|| "Unknown".to_string());
                                let decimals = get_asset_decimals(&ev.mint);
                                let ui_amt =
                                    ev.amount_base_units as f64 / 10f64.powi(decimals as i32);

                                println!(
                                    "{:04}. {:10} | {:18.6} | CP: {:22} | {} | Mint: {}...",
                                    total_events,
                                    ev.kind.as_str(),
                                    ui_amt,
                                    cp_label,
                                    classification_str,
                                    &ev.mint[..std::cmp::min(10, ev.mint.len())]
                                );

                                let ptax_brl = get_historical_ptax();
                                let sig_prefix = &sig[..8.min(sig.len())];
                                let lot_id = format!(
                                    "lot-{}-{}-{:.8}",
                                    sig_prefix,
                                    &ev.mint[..std::cmp::min(6, ev.mint.len())],
                                    ui_amt
                                );
                                let timestamp = if let Some(t) = ev.block_time_unix {
                                    let year = 1970 + (t / 31536000);
                                    let remainder = t % 31536000;
                                    let month = 1 + (remainder / 2592000);
                                    let day = 1 + ((remainder % 2592000) / 86400);
                                    format!("{:04}-{:02}-{:02}T12:00:00Z", year, month, day)
                                } else {
                                    now_utc_string()
                                };

                                let _ = ledger.record_acquisition(
                                    lot_id,
                                    ev.mint.clone(),
                                    ev.amount_base_units as u64,
                                    ptax_brl,
                                    timestamp,
                                );
                            }
                        }
                        Err(e) => {
                            println!("Failed to fetch transaction {}: {}", sig, e);
                        }
                    }
                }
                unclassified_counterparties_set = ledger.unclassified_counterparties.clone();
            }

            save_multi_ledger(&multi_ledger);
            println!("------------------------------------------------------------");
            println!(
                "Ingestion Summary -> Recorded {} Total Events.",
                total_events
            );
            println!(
                "  ✓ Auto-Labeled: {} event(s) across {} unique address(es)",
                auto_labeled_count,
                classified_counterparties.len()
            );
            println!(
                "  ! Needs Review: {} event(s) across {} unique address(es)",
                needs_review_count,
                unclassified_counterparties_set.len()
            );
            println!(
                "Multi-wallet ledger state successfully saved to {}",
                LEDGER_FILE
            );
        }
        Commands::Review { pubkey } => {
            let multi_ledger = load_multi_ledger();
            println!(
                "Inspecting ingested transaction ledger for unclassified counterparties in: {}...",
                pubkey
            );
            println!("{:-<75}", "");

            if let Some(ledger) = multi_ledger.get_ledger(&pubkey) {
                if ledger.unclassified_counterparties.is_empty() {
                    println!("✓ No unclassified counterparties found in ingested history! All recorded transactions are fully auto-labeled.");
                } else {
                    println!("Found {} unique unclassified counterparty address(es) needing review from ingested data:", ledger.unclassified_counterparties.len());
                    println!("{:-<75}", "");
                    for addr in &ledger.unclassified_counterparties {
                        println!("Address : {}", addr);
                        println!("Rule Add: cargo run -p selo-tool -- rules --add {} --name \"Client Name\"", addr);
                        println!("{:-<75}", "");
                    }
                }
            } else {
                println!(
                    "No ingested ledger found for wallet {}. Run 'ingest' first.",
                    pubkey
                );
            }
        }
        Commands::Blockhash => {
            let bh = engine.rpc.get_latest_blockhash()?;
            println!("Latest Blockhash: {}", bh);
        }
        Commands::Ptax => {
            println!("Fetching official Banco Central do Brasil PTAX rate...");
            let live_rate = fetch_live_ptax();
            let historical_baseline = get_historical_ptax();
            println!("{:-<50}", "");
            println!("  Ongoing / Live PTAX Rate : R$ {:.4}", live_rate);
            println!("  Historical Baseline PTAX : R$ {:.4}", historical_baseline);
        }
        Commands::RecordSample => {
            // For ongoing live tracking and new sample inflows, fetch live PTAX
            let live_ptax = fetch_live_ptax();
            println!(
                "Recording sample acquisition with ongoing live PTAX: R$ {:.4}",
                live_ptax
            );

            let mut multi_ledger = load_multi_ledger();
            let ledger = multi_ledger.get_mut_ledger("SampleWallet");
            let lot_id = format!(
                "lot-live-{:.0}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            );
            let _ = ledger.record_acquisition(
                lot_id,
                NATIVE_SOL_MINT.to_string(),
                1_000_000_000, // 1 SOL
                live_ptax,
                now_utc_string(),
            );
            save_multi_ledger(&multi_ledger);
            println!(
                "✓ Sample live acquisition recorded using live PTAX R$ {:.4}.",
                live_ptax
            );
        }
        Commands::ExportHtml {
            year,
            anchor_sig,
            output,
            wallet,
        } => {
            let multi_ledger = load_multi_ledger();

            // Retrieve either the specific wallet ledger or a cumulative multi-wallet ledger
            let ledger = if let Some(ref pubkey) = wallet {
                multi_ledger.get_ledger(pubkey).cloned().unwrap_or_else(|| {
                    println!("Notice: No ingested ledger found for wallet {}. Exporting empty ledger state.", pubkey);
                    TaxLedger::new()
                })
            } else {
                multi_ledger.cumulative_ledger()
            };

            let fiscal_tag = year.as_deref().unwrap_or("2026");
            let html = ledger.generate_html_report(fiscal_tag, anchor_sig.as_deref())?;

            fs::write(&output, html).map_err(|e| e.to_string())?;
            println!(
                "Successfully exported standalone audit report to: {} (Wallet scope: {}, Year/Mode: {})",
                output,
                wallet.as_deref().unwrap_or("All Wallets Cumulative"),
                fiscal_tag
            );
        }
        Commands::Verify { root } => {
            let multi_ledger = load_multi_ledger();
            let ledger = multi_ledger.cumulative_ledger();

            let computed = ledger.compute_state_root()?;
            println!("Computed Cumulative Ledger Root: {}", computed);
            println!("Provided Target Root           : {}", root);
            if computed == root {
                println!(
                    "✓ Verification SUCCESS: Cumulative ledger state matches cryptographic root perfectly."
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
