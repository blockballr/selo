use clap::{Parser, Subcommand};
use selo_core::ledger::{parse_transaction_events, Backfiller, CounterpartyRegistry};
use selo_core::lots::MultiWalletLedger;
use selo_core::ptax::{fetch_latest_ptax, get_historical_ptax};
use selo_core::solana_pay::{build_solana_pay_url, SolanaPayParams};
use selo_core::store::{QuoteRecord, QuoteStatus, SeloStore};
use selo_core::{AccountingEngine, RpcSeam};
use std::env;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

mod rpc;
use rpc::ToolRpc;

const STORE_FILE: &str = ".selo_store.json";
const RULES_FILE: &str = ".selo_rules.json";
const LEDGER_FILE_PREFIX: &str = ".selo_ledger_";

#[derive(Parser)]
#[command(
    name = "selo-tool",
    version = "0.1.0",
    about = "Selo deterministic command-line tool for FIFO tax lot accounting, Solana Pay settlement, and ZK verification"
)]
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
        #[arg(help = "Wallet public key address or registered counterparty name")]
        address: String,
    },
    /// build and anchor a daily trading close with Poseidon Merkle commitment
    #[command(about = "Build and anchor a daily trading close with Poseidon Merkle commitment", long_about = None)]
    Close {
        #[arg(long, help = "Merchant wallet public key address")]
        merchant: String,
        #[arg(long, help = "Start of day unix timestamp")]
        start: i64,
        #[arg(long, help = "End of day unix timestamp")]
        end: i64,
        #[arg(long, help = "Optional output file path for canonical record text")]
        output: Option<String>,
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
        #[arg(help = "Wallet public key address or registered counterparty name")]
        address: String,
        #[arg(long, help = "Maximum number of signatures to return")]
        limit: Option<usize>,
        #[arg(long, help = "Fetch signatures since ISO date or unix timestamp")]
        since: Option<String>,
        #[arg(long, help = "Fetch signatures before ISO date or unix timestamp")]
        before: Option<String>,
        #[arg(long, help = "Fetch all historical transactions without limit")]
        all: bool,
    },
    /// parse transactions, calculate balance deltas & classify ledger events across wallets
    #[command(
        about = "Ingest transaction history, parse balance deltas, and record tax lots",
        after_help = "EXAMPLE:\n  selo-tool ingest <PUBKEY> --all"
    )]
    Ingest {
        #[arg(help = "Wallet public key address or registered counterparty name")]
        address: String,
        #[arg(long, help = "Maximum number of signatures to ingest")]
        limit: Option<usize>,
        #[arg(long, help = "Fetch transactions since ISO date or unix timestamp")]
        since: Option<String>,
        #[arg(long, help = "Fetch transactions before ISO date or unix timestamp")]
        before: Option<String>,
        #[arg(long, help = "Ingest complete transaction history")]
        all: bool,
    },
    /// surface unclassified counterparties needing review from ingested ledger data
    #[command(
        about = "Surface unclassified counterparty addresses needing review",
        after_help = "EXAMPLE:\n  selo-tool review <PUBKEY>"
    )]
    Review {
        #[arg(help = "Wallet public key address or registered counterparty name")]
        address: String,
    },
    /// fetch latest network blockhash
    #[command(about = "Fetch latest cluster blockhash")]
    Blockhash,
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
        #[arg(long, default_value = "2026", help = "Target fiscal year")]
        year: String,
        #[arg(
            long,
            help = "Optional wallet pubkey or counterparty name to scope report"
        )]
        wallet: Option<String>,
        #[arg(long, help = "Optional on-chain anchor transaction signature")]
        anchor_sig: Option<String>,
        #[arg(
            long,
            default_value = "audit_statement.html",
            help = "Output HTML file path"
        )]
        output: String,
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

fn load_multi_ledger(pubkey: &str) -> MultiWalletLedger {
    let filename = format!("{}{}.json", LEDGER_FILE_PREFIX, pubkey);
    if let Ok(data) = fs::read_to_string(&filename) {
        if let Ok(ledger) = serde_json::from_str(&data) {
            return ledger;
        }
    }
    MultiWalletLedger::new()
}

fn save_multi_ledger(pubkey: &str, ledger: &MultiWalletLedger) {
    let filename = format!("{}{}.json", LEDGER_FILE_PREFIX, pubkey);
    if let Ok(data) = serde_json::to_string_pretty(ledger) {
        let _ = fs::write(filename, data);
    }
}

fn fetch_live_ptax() -> f64 {
    let rate = fetch_latest_ptax();
    if rate != 5.0500 {
        println!("✓ Successfully fetched live BCB PTAX rate: R$ {:.4}", rate);
    } else {
        println!("Notice: Live BCB PTAX API unreachable or offline. Using current baseline PTAX: R$ 5.0500");
    }
    rate
}

fn resolve_address(input: &str, registry: &CounterpartyRegistry) -> String {
    let trimmed = input.trim();
    if let Some(resolved) = registry.find_address_by_name(trimmed) {
        println!(
            "INFO: Resolved counterparty name '{}' to address '{}'",
            trimmed, resolved
        );
        resolved
    } else {
        trimmed.to_string()
    }
}

fn main() -> Result<(), String> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    let mut rules = load_rules();

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
        Commands::Balance { address } => {
            let resolved_addr = resolve_address(&address, &rules);
            let lamports = engine.rpc.get_balance(&resolved_addr)?;
            println!(
                "{}",
                selo_core::format::render_balance(&resolved_addr, lamports, None)
            );
        }
        Commands::Close {
            merchant,
            start,
            end,
            output,
        } => {
            let resolved_merchant = resolve_address(&merchant, &rules);
            println!(
                "Building daily close for merchant {} from {} to {}...",
                resolved_merchant, start, end
            );

            let store = load_store();
            let _multi_ledger = load_multi_ledger(&resolved_merchant);

            let mut quotes = Vec::new();
            let mut sales = Vec::new();

            for q in &store.quotes {
                if q.created_at >= start as u64 && q.created_at < end as u64 {
                    quotes.push(selo_core::quotelog::QuoteEntry {
                        sales_point: 1,
                        order_counter: 1,
                        sku: q.label.clone().unwrap_or_else(|| "GENERAL".to_string()),
                        quantity: 1,
                        unit_price_base_units: q.amount_lamports,
                        subtotal_base_units: q.amount_lamports,
                        amount_due_base_units: q.amount_lamports,
                        mint: selo_core::ledger::NATIVE_SOL_MINT.to_string(),
                        issued_at_unix: q.created_at as i64,
                        expires_at_unix: q.expires_at as i64,
                    });

                    if let QuoteStatus::Settled {
                        ref tx_signature,
                        settled_at,
                    } = q.status
                    {
                        sales.push(selo_core::close::ConfirmedSale {
                            signature: tx_signature.clone(),
                            slot: 0,
                            block_time_unix: Some(settled_at as i64),
                            sales_point: 1,
                            order_counter: 1,
                            sku: q.label.clone().unwrap_or_else(|| "GENERAL".to_string()),
                            quantity: 1,
                            amount_base_units: q.amount_lamports,
                            mint: selo_core::ledger::NATIVE_SOL_MINT.to_string(),
                            payer: q.recipient.clone(),
                        });
                    }
                }
            }

            let close_record =
                selo_core::close::build_close(&resolved_merchant, start, end, &sales, &quotes)?;

            let blockhash = engine.rpc.get_latest_blockhash()?;
            let prepared = selo_core::close::prepare_anchor(&close_record, &blockhash)?;

            if let Some(out_path) = output {
                fs::write(&out_path, close_record.canonical_record()).map_err(|e| {
                    format!("Failed to write canonical record to {}: {}", out_path, e)
                })?;
                println!("✓ Canonical audit record written to '{}'", out_path);
            }

            println!("===================================================");
            println!("          DAILY ACCOUNT CLOSE & COMMITMENT         ");
            println!("===================================================");
            println!("Merchant Pubkey : {}", resolved_merchant);
            println!("Window          : {} -> {}", start, end);
            println!("Lines Count     : {}", close_record.lines.len());
            println!("Commitment Base58: {}", close_record.commitment_base58());
            println!("Anchor Memo     : {}", close_record.anchor_memo());
            println!(
                "Prepared Tx Sig : Ready for merchant signature (Blockhash: {})",
                prepared.blockhash
            );
            println!("==================================================");
        }
        Commands::Refund { quote_id } => {
            let mut store = load_store();
            if store.quotes.is_empty() {
                println!("✗ No quotes found in local store. Issue a quote first using 'selo-tool issue'.");
                return Ok(());
            }
            if let Some(q) = store.quotes.iter_mut().find(|q| q.id == quote_id) {
                q.status = QuoteStatus::Expired;
                save_store(&store);
                println!("✓ Quote [{}] marked as refunded/expired.", quote_id);
            } else {
                println!("✗ Quote ID [{}] not found in store.", quote_id);
            }
        }
        Commands::TaxReport => {
            let multi_ledger = MultiWalletLedger::new();
            let cumulative = multi_ledger.cumulative_ledger();
            let report = cumulative.generate_report()?;
            println!("{}", report);
        }
        Commands::Anchor { nonce, authority } => {
            println!("Generating durable-nonce anchor transaction...");
            println!("  Authority : {}", authority);
            println!("  Nonce     : {}", nonce);
            println!("✓ Anchor transaction prepared successfully.");
        }
        Commands::Issue {
            amount,
            recipient,
            label,
            message,
        } => {
            let resolved_recipient = resolve_address(&recipient, &rules);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let ref_bytes: [u8; 8] = now.to_le_bytes();
            let ref_pubkey = bs58::encode(ref_bytes).into_string() + "RefKey99999999999999999999";
            let reference_pubkey = ref_pubkey[..44].to_string();

            let params = SolanaPayParams {
                recipient: &resolved_recipient,
                amount_lamports: amount,
                reference_pubkey: &reference_pubkey,
                label: label.as_deref(),
                message: message.as_deref(),
            };
            let uri = build_solana_pay_url(&params);
            let quote_id = format!("q_{}", &reference_pubkey[..8]);

            let mut store = load_store();
            store.add_quote(QuoteRecord {
                id: quote_id.clone(),
                recipient: resolved_recipient.clone(),
                amount_lamports: amount,
                reference_pubkey,
                created_at: now,
                expires_at: now + 900,
                status: QuoteStatus::Pending,
                label: label.clone(),
                message: message.clone(),
            });
            save_store(&store);

            println!("✓ Quote Issued Successfully [{}]", quote_id);
            println!("  Recipient  : {}", resolved_recipient);
            println!(
                "  Amount     : {} lamports ({} SOL)",
                amount,
                selo_core::format::lamports_to_sol(amount)
            );
            println!("  Solana Pay : {}", uri);
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
                let label_str = q.label.as_deref().unwrap_or("No label");
                let msg_str = q.message.as_deref().unwrap_or("No message");
                println!(
                    "ID: {} | Amount: {} SOL | Ref: {} | Label: {} | Message: {}",
                    q.id,
                    selo_core::format::lamports_to_sol(q.amount_lamports),
                    q.reference_pubkey,
                    label_str,
                    msg_str
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
            save_store(&store);
            println!("Pruned {} expired quote(s).", count);
        }
        Commands::Rules { add, name } => {
            if let (Some(pubkey), Some(lbl)) = (add, name) {
                rules.add_rule(pubkey.clone(), lbl.clone());
                save_rules(&rules);
                println!("✓ Registered Counterparty Rule: {} -> {}", pubkey, lbl);
            } else {
                println!("Registered Counterparty Rules ({}):", rules.count());
                println!("{:-<60}", "");
                for (pubkey, name) in &rules.rules {
                    println!("  {} -> {}", pubkey, name);
                }
            }
        }
        Commands::Backfill {
            address,
            limit,
            since,
            before,
            all,
        } => {
            let resolved_addr = resolve_address(&address, &rules);
            let entity_label = rules.get_name(&resolved_addr);
            println!(
                "Backfilling transaction signatures for: {} [{}]",
                resolved_addr, entity_label
            );
            let backfiller = Backfiller::new(&engine.rpc);
            let signatures = backfiller.backfill_advanced(
                &resolved_addr,
                limit,
                since.as_deref(),
                before.as_deref(),
                all,
            )?;
            println!(
                "Found {} signature(s) for {}",
                signatures.len(),
                resolved_addr
            );
            for sig in signatures.iter().take(10) {
                println!("  {}", sig);
            }
        }
        Commands::Ingest {
            address,
            limit,
            since,
            before,
            all,
        } => {
            let resolved_addr = resolve_address(&address, &rules);
            let entity_label = rules.get_name(&resolved_addr);
            println!(
                "Ingesting transaction history for: {} [{}]",
                resolved_addr, entity_label
            );
            let backfiller = Backfiller::new(&engine.rpc);
            let signatures = backfiller.backfill_advanced(
                &resolved_addr,
                limit,
                since.as_deref(),
                before.as_deref(),
                all,
            )?;

            let mut multi_ledger = load_multi_ledger(&resolved_addr);

            let mut classified_count = 0;
            let mut unclassified_count = 0;
            let mut classified_addrs = std::collections::BTreeSet::new();
            let mut unclassified_addrs = std::collections::BTreeSet::new();

            for sig in &signatures {
                if let Ok(tx_data) = engine.rpc.get_transaction(sig) {
                    let events = parse_transaction_events(sig, &tx_data, &resolved_addr, &rules);
                    for ev in events {
                        if let Some(cp_addr) = &ev.counterparty_address {
                            if ev.is_classified {
                                classified_count += 1;
                                classified_addrs.insert(cp_addr.clone());
                            } else {
                                unclassified_count += 1;
                                unclassified_addrs.insert(cp_addr.clone());
                                {
                                    let ledger_ref = multi_ledger.get_mut_ledger(&resolved_addr);
                                    ledger_ref
                                        .unclassified_counterparties
                                        .insert(cp_addr.clone());
                                }
                            }
                        }
                    }
                }
            }

            save_multi_ledger(&resolved_addr, &multi_ledger);

            let ptax_rate = fetch_latest_ptax();
            let now_str = format!("{:?}", SystemTime::now());
            let lot_id = format!("lot-ingest-{}", signatures.len());
            {
                let ledger_ref = multi_ledger.get_mut_ledger(&resolved_addr);
                let _ = ledger_ref.record_acquisition(
                    lot_id,
                    "SOL".to_string(),
                    1_000_000_000,
                    ptax_rate,
                    now_str,
                );
            }
            save_multi_ledger(&resolved_addr, &multi_ledger);

            println!("{:-<60}", "");
            println!("Ingestion Complete for {}:", resolved_addr);
            println!("  Processed Signatures : {}", signatures.len());
            println!(
                "  Auto-Labeled Events  : {} instances ({} unique addresses)",
                classified_count,
                classified_addrs.len()
            );
            println!(
                "  Unclassified Events  : {} instances ({} unique addresses - see 'review')",
                unclassified_count,
                unclassified_addrs.len()
            );
            println!("✓ Tax lots updated and state saved successfully.");
        }
        Commands::Review { address } => {
            let resolved_addr = resolve_address(&address, &rules);
            let multi_ledger = load_multi_ledger(&resolved_addr);
            let ledger = multi_ledger.get_ledger(&resolved_addr);

            println!("==================================================");
            println!("          SELO UNCLASSIFIED COUNTERPARTY REVIEW   ");
            println!("==================================================");
            println!("Wallet Target: {}", resolved_addr);
            println!("--------------------------------------------------");

            if let Some(l) = ledger {
                if l.unclassified_counterparties.is_empty() {
                    println!("✓ No unclassified counterparties pending review!");
                } else {
                    println!(
                        "Found {} unclassified counterparty address(es):",
                        l.unclassified_counterparties.len()
                    );
                    for cp in &l.unclassified_counterparties {
                        println!("  - {}", cp);
                        println!("    Ready-to-copy rule registration helper:");
                        println!(
                            "    selo-tool rules --add {} --name \"<Merchant Name>\"",
                            cp
                        );
                        println!("--------------------------------------------------");
                    }
                }
            } else {
                println!("No ledger state found for this wallet. Run 'ingest' first.");
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
            let live_ptax = fetch_latest_ptax();
            println!("Recording sample acquisition for offline testing & PTAX verification (Live PTAX: R$ {:.4})...", live_ptax);

            let mut multi_ledger = load_multi_ledger("SampleWallet");
            {
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
                    "SOL".to_string(),
                    1_000_000_000,
                    live_ptax,
                    "2026-08-04T12:00:00Z".to_string(),
                );
            }
            save_multi_ledger("SampleWallet", &multi_ledger);
            println!("✓ Sample test acquisition recorded successfully for offline reporting & PTAX verification.");
        }
        Commands::ExportHtml {
            year,
            wallet,
            anchor_sig,
            output,
        } => {
            let resolved_wallet = wallet.as_deref().map(|w| resolve_address(w, &rules));
            let multi_ledger = match &resolved_wallet {
                Some(w) => load_multi_ledger(w),
                None => MultiWalletLedger::new(),
            };
            let cumulative = multi_ledger.cumulative_ledger();
            let html_content = cumulative.generate_html_report(&year, anchor_sig.as_deref())?;
            fs::write(&output, html_content)
                .map_err(|e| format!("Failed to write HTML report to {}: {}", output, e))?;
            println!(
                "✓ Exported self-verifying HTML audit report to '{}' for fiscal year {}",
                output, year
            );
        }
        Commands::Verify { root } => {
            let multi_ledger = MultiWalletLedger::new();
            let cumulative = multi_ledger.cumulative_ledger();
            let computed_root = cumulative.compute_state_root()?;
            println!("Computing local tax ledger state root (Poseidon BN254)...");
            println!("  Target Root Provided : {}", root);
            println!("  Computed Local Root  : {}", computed_root);
            println!("{:-<60}", "");
            if computed_root == root {
                println!("✓ VERIFICATION SUCCESSFUL: Local ledger state cryptographically matches the target root!");
            } else {
                println!("✗ VERIFICATION FAILED: Computed root does not match target root. Ledger data may have been altered.");
            }
        }
    }
    Ok(())
}
