use clap::{Parser, Subcommand};
use selo_core::ledger::{parse_transaction_events, Backfiller, CounterpartyRegistry};
use selo_core::lots::MultiWalletLedger;
use selo_core::ptax::{self, get_historical_ptax, FxRateSource};
use std::collections::HashMap;
use selo_core::quote::decode_amount;
use selo_core::solana_pay::{build_solana_pay_url, SolanaPayParams};
use selo_core::catalog::ShopConfig;
use selo_core::refund::{prepare_refund, render_approval, OrderRef, RefundPolicy};
use selo_core::settle::parse_settlement_payment;
use selo_core::store::{QuoteRecord, QuoteStatus, SeloStore};
use selo_core::{AccountingEngine, RpcSeam};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Process-local counter so two quotes issued in the same millisecond still
/// get distinct reference keys.
static QUOTE_COUNTER: AtomicU32 = AtomicU32::new(0);

mod ptax_http;
mod rpc;
use ptax_http::HttpFxRateSource;
use rpc::ToolRpc;

const STORE_FILE: &str = ".selo_store.json";
const RULES_FILE: &str = ".selo_rules.json";
const LEDGER_FILE_PREFIX: &str = ".selo_ledger_";
const MERCHANT_FILE: &str = ".selo_merchant.json";

/// One tracked wallet. The primary wallet is the default receiving address;
/// additional tracked wallets exist for multi-terminal POS setups where each
/// terminal settles into its own account.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TrackedWallet {
    pubkey: String,
    name: String,
    primary: bool,
}

/// Persisted merchant setup. Mode is `personal` by default (one wallet, the
/// operator's own), or `business` when the operator invoices and settles as a
/// merchant with one or more receiving wallets.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MerchantConfig {
    mode: String,
    updated_at: u64,
    tracked_wallets: Vec<TrackedWallet>,
}

impl MerchantConfig {
    fn new() -> Self {
        Self {
            mode: "personal".to_string(),
            updated_at: 0,
            tracked_wallets: Vec::new(),
        }
    }

    fn primary(&self) -> Option<&TrackedWallet> {
        self.tracked_wallets.iter().find(|w| w.primary)
    }
}

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
        #[arg(long, help = "Merchant wallet public key address (defaults to the configured merchant)")]
        merchant: Option<String>,
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
        after_help = "EXAMPLES:\n  selo-tool issue --sol 1.5 --recipient <PUBKEY> --label \"Design Work\"\n  selo-tool issue --amount 500000000 --recipient <PUBKEY>"
    )]
    Issue {
        #[arg(
            long,
            help = "Amount in raw lamports (1 SOL = 1,000,000,000 lamports)"
        )]
        amount: Option<u64>,
        #[arg(long, help = "Amount in SOL (human-friendly, e.g. 1.5)")]
        sol: Option<String>,
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
        #[arg(
            long,
            help = "Treat outbound transfers to counterparties (payments, not swaps) as operating expenses: reduce the position but book no capital loss and report nothing"
        )]
        payments_as_expenses: bool,
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
    /// prepare a refund for a settled quote
    #[command(
        about = "Prepare a refund for a settled quote",
        after_help = "EXAMPLE:\n  selo-tool refund <QUOTE_ID> --merchant <PUBKEY> --mint EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v\n\nDerives the payee and the exact amount from chain data. The settlement\nsignature stored against the quote is fetched from the RPC, parsed, and\ncross-checked against the configured merchant and mint. Output is the\nunsigned transaction and human-readable approval text."
    )]
    Refund {
        #[arg(help = "Quote ID to refund")]
        quote_id: String,
        #[arg(long, help = "Merchant public key that received the payment")]
        merchant: String,
        #[arg(long, default_value = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", help = "Settlement mint (default: USDC)")]
        mint: String,
        #[arg(long, default_value = "6", help = "Mint decimals (default: 6)")]
        decimals: u8,
        #[arg(long, default_value = "1", help = "Sales point ID (1-99)")]
        sales_point: u8,
    },
    /// fetch latest BCB PTAX USD/BRL rate
    #[command(about = "Fetch official Banco Central do Brasil PTAX exchange rate")]
    Ptax,
    /// generate local tax report from ledger
    #[command(about = "Generate local tax report from ledger")]
    TaxReport,
    /// generate unsigned durable-nonce anchor transaction for ZK state root
    #[command(
        about = "Generate an unsigned durable-nonce anchor transaction for a day close",
        after_help = "EXAMPLE:\n  selo-tool anchor --merchant <PUBKEY> --start 1750000000 --end 1750086400 --nonce-account <NONCE_ACCOUNT> --authority <NONCE_AUTHORITY>\n\nBuilds the day close from settled quotes, reads the nonce account state on chain,\nand renders an unsigned transaction carrying an AdvanceNonceAccount instruction\nplus the Poseidon commitment as an SPL Memo. A human signs and broadcasts it."
    )]
    Anchor {
        #[arg(long, help = "Merchant wallet public key address (defaults to the configured merchant)")]
        merchant: Option<String>,
        #[arg(long, help = "Start of day unix timestamp")]
        start: i64,
        #[arg(long, help = "End of day unix timestamp")]
        end: i64,
        #[arg(long, help = "Durable nonce account address")]
        nonce_account: String,
        #[arg(long, help = "Nonce authority public key")]
        authority: String,
    },
    /// export self-verifying standalone HTML audit report
    #[command(
        about = "Export self-verifying standalone HTML audit report with Poseidon state root",
        after_help = "EXAMPLE:\n  selo-tool export-html --year 2026 --output audit_statement.html"
    )]
    ExportHtml {
        #[arg(long, help = "Target fiscal year (omit for all history)")]
        year: Option<String>,
        #[arg(
            long,
            help = "Optional wallet pubkey or counterparty name to scope report"
        )]
        wallet: Option<String>,
        #[arg(long, help = "Optional on-chain anchor transaction signature")]
        anchor_sig: Option<String>,
        #[arg(
            long,
            help = "Optional start of date range (ISO date or unix timestamp)"
        )]
        from: Option<String>,
        #[arg(
            long,
            help = "Optional end of date range (ISO date or unix timestamp)"
        )]
        to: Option<String>,
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
    /// generate an offline Groth16 proof that one daily-close line is committed under its merkle root
    #[command(
        about = "Generate and verify an offline Groth16 proof for a daily-close line",
        after_help = "EXAMPLE:\n  selo-tool prove --merchant <PUBKEY> --start 1750000000 --end 1750086400 --line 2\n\nBuilds the day close from settled quotes, derives the merkle proof for the chosen\nline, and produces a Groth16 proof (over BN254) that the line's leaf is committed\nunder the close's Poseidon merkle root. The proof is verified locally before it is\nshown, so a printed proof is a verified one."
    )]
    Prove {
        #[arg(long, help = "Merchant wallet public key address (defaults to the configured merchant)")]
        merchant: Option<String>,
        #[arg(long, help = "Start of day unix timestamp")]
        start: i64,
        #[arg(long, help = "End of day unix timestamp")]
        end: i64,
        #[arg(long, default_value = "0", help = "Zero-based index of the line to prove")]
        line: u64,
    },
    /// list ingested wallet ledgers on disk
    #[command(about = "List ingested wallet ledgers and their lot counts")]
    Wallets,
    /// view or configure the tracked merchant wallet(s) for daily closes
    #[command(
        about = "View or configure the tracked merchant wallet(s) for daily closes",
        after_help = "EXAMPLES:\n  selo-tool merchant\n  selo-tool merchant --set <PUBKEY> --name \"My Shop\" --mode business\n  selo-tool merchant --add <PUBKEY> --name \"POS Terminal 2\"\n  selo-tool merchant --remove <PUBKEY>"
    )]
    Merchant {
        #[arg(long, help = "Set the primary merchant wallet (personal or business)")]
        set: Option<String>,
        #[arg(long, help = "Human-readable label for the wallet")]
        name: Option<String>,
        #[arg(long, help = "Mode: personal (default) or business")]
        mode: Option<String>,
        #[arg(long, help = "Add a tracked wallet (POS multi-wallet)")]
        add: Option<String>,
        #[arg(long, help = "Remove a tracked wallet")]
        remove: Option<String>,
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

fn load_merchant() -> MerchantConfig {
    if Path::new(MERCHANT_FILE).exists() {
        if let Ok(data) = fs::read_to_string(MERCHANT_FILE) {
            if let Ok(cfg) = serde_json::from_str(&data) {
                return cfg;
            }
        }
    }
    MerchantConfig::new()
}

fn save_merchant(cfg: &MerchantConfig) {
    if let Ok(data) = serde_json::to_string_pretty(cfg) {
        let _ = fs::write(MERCHANT_FILE, data);
    }
}

/// Resolve the wallets a daily close should run against. When the operator
/// names a merchant explicitly it wins; otherwise the persisted merchant
/// config supplies the tracked wallets. Returns the list of pubkeys to close.
fn close_wallets(explicit: Option<&str>, rules: &CounterpartyRegistry) -> Result<Vec<String>, String> {
    if let Some(m) = explicit {
        return Ok(vec![resolve_address(m, rules)]);
    }
    let cfg = load_merchant();
    if cfg.tracked_wallets.is_empty() {
        return Err(
            "No merchant configured. Run 'selo-tool merchant --set <pubkey> --name <label>' \
             or pass --merchant <pubkey>."
                .to_string(),
        );
    }
    let mut wallets: Vec<String> = cfg
        .tracked_wallets
        .iter()
        .map(|w| w.pubkey.clone())
        .collect();
    // Deterministic order: primary first, then the rest by pubkey.
    wallets.sort_by_key(|w| {
        if cfg.primary().map(|p| p.pubkey == *w).unwrap_or(false) {
            (0, w.clone())
        } else {
            (1, w.clone())
        }
    });
    Ok(wallets)
}

/// Render bytes as a lowercase hex string, mirroring the format the HTML
/// report uses so proof output matches the rest of the tool.
fn hex_string(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Map a Solana mint address to a human-readable asset symbol.
fn mint_to_symbol(mint: &str) -> &str {
    if mint == "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" {
        "USDC"
    } else if mint == "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" {
        "USDT"
    } else if mint == "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo" {
        "PYUSD"
    } else if mint == "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH" {
        "USDG"
    } else if mint.starts_with("So111") || mint == "So11111111111111111111111111111111111111112" {
        "SOL"
    } else {
        "TOKEN"
    }
}

/// Number of decimal places for a given asset symbol.
fn decimals_for_symbol(symbol: &str) -> u32 {
    match symbol {
        "SOL" => 9,
        _ => 6, // USDC, USDT, USDG, PYUSD, and unknown tokens
    }
}

/// In-memory cache for date-specific exchange rates.
///
/// Avoids hitting BCB and CoinGecko repeatedly for the same date during a
/// single ingest run (each transaction on the same day would otherwise
/// trigger fresh API calls).
struct DateCache {
    ptax: HashMap<String, f64>,
    sol_usd: HashMap<String, f64>,
    cost_basis: HashMap<String, f64>,
    source: Box<dyn FxRateSource>,
}

impl DateCache {
    fn new(source: Box<dyn FxRateSource>) -> Self {
        DateCache {
            ptax: HashMap::new(),
            sol_usd: HashMap::new(),
            cost_basis: HashMap::new(),
            source,
        }
    }

    fn get_or_fetch_ptax(&mut self, date_ymd: &str) -> f64 {
        *self
            .ptax
            .entry(date_ymd.to_string())
            .or_insert_with(|| ptax::resolve_ptax_for_date(self.source.as_ref(), date_ymd))
    }

    fn get_or_fetch_sol_usd(&mut self, date_ymd: &str) -> f64 {
        *self
            .sol_usd
            .entry(date_ymd.to_string())
            .or_insert_with(|| ptax::resolve_sol_usd_for_date(self.source.as_ref(), date_ymd))
    }

    fn cost_basis(&mut self, symbol: &str, date_ymd: &str) -> f64 {
        let key = format!("{}|{}", symbol, date_ymd);
        if let Some(&cached) = self.cost_basis.get(&key) {
            return cached;
        }
        let ptax_rate = self.get_or_fetch_ptax(date_ymd);
        let value = match symbol {
            "SOL" => {
                let sol_usd = self.get_or_fetch_sol_usd(date_ymd);
                sol_usd * ptax_rate
            }
            _ => ptax_rate,
        };
        self.cost_basis.insert(key, value);
        value
    }
}

/// Load every `.selo_ledger_*.json` file in the working directory and
/// merge them into one MultiWalletLedger. Used by verify and tax-report so
/// they operate over the on-disk state rather than an empty ledger.
fn load_all_multi_ledgers() -> MultiWalletLedger {
    let mut combined = MultiWalletLedger::new();
    let entries = match fs::read_dir(".") {
        Ok(entries) => entries,
        Err(_) => return combined,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with(LEDGER_FILE_PREFIX) || !name_str.ends_with(".json") {
            continue;
        }
        if let Ok(data) = fs::read_to_string(entry.path()) {
            if let Ok(ledger) = serde_json::from_str::<MultiWalletLedger>(&data) {
                for (wallet_key, tax_ledger) in ledger.wallets {
                    combined
                        .wallets
                        .entry(wallet_key)
                        .or_default()
                        .lots
                        .extend(tax_ledger.lots);
                }
            }
        }
    }
    combined
}

fn fetch_live_ptax(source: &dyn FxRateSource) -> f64 {
    match source.latest_ptax() {
        Some(rate) => {
            println!("âœ“ Successfully fetched live BCB PTAX rate: R$ {:.4}", rate);
            rate
        }
        None => {
            println!("Notice: Live BCB PTAX API unreachable or offline. Using current baseline PTAX: R$ 5.0500");
            get_historical_ptax()
        }
    }
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

/// Build the daily close for a merchant and window from the local quote
/// store. Shared by the `close` and `anchor` commands so both itemize the
/// same day from the same record.
fn build_close_from_store(
    merchant: &str,
    start: i64,
    end: i64,
) -> Result<selo_core::close::DailyClose, String> {
    let store = load_store();
    let mut quotes = Vec::new();
    let mut sales = Vec::new();

    for q in &store.quotes {
        if q.created_at >= start as u64 && q.created_at < end as u64 {
            // Decode the amount tag to recover the sales point and order
            // counter embedded in the payment amount. An untagged amount
            // carries no quote identity and is skipped.
            let (sales_point, order_counter, unit_price, amount_due) = match decode_amount(q.amount_lamports) {
                Ok(Some((price, tag))) => {
                    let due = price
                        .checked_add(tag.value())
                        .ok_or_else(|| format!("tagged amount overflow on quote {}", q.id))?;
                    (tag.sales_point, tag.order_counter, price, due)
                }
                Ok(None) => {
                    // Untagged payment: not from a quote we issued.
                    // Skip it rather than guessing.
                    continue;
                }
                Err(e) => {
                    eprintln!(
                        "Warning: cannot decode amount for quote {}: {e}",
                        q.id
                    );
                    continue;
                }
            };

            let sku = q
                .label
                .clone()
                .unwrap_or_else(|| "GENERAL".to_string());
            let mint = selo_core::ledger::NATIVE_SOL_MINT.to_string();

            quotes.push(selo_core::quotelog::QuoteEntry {
                sales_point,
                order_counter,
                sku: sku.clone(),
                quantity: 1,
                unit_price_base_units: unit_price,
                subtotal_base_units: unit_price,
                amount_due_base_units: amount_due,
                mint: mint.clone(),
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
                    sales_point,
                    order_counter,
                    sku,
                    quantity: 1,
                    amount_base_units: amount_due,
                    mint,
                    payer: q.recipient.clone(),
                });
            }
        }
    }

    selo_core::close::build_close(merchant, start, end, &sales, &quotes)
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
    let fx_source = Box::new(HttpFxRateSource::new());

    match cli.command {
        Commands::Balance { address } => {
            let resolved_addr = resolve_address(&address, &rules);
            let lamports = engine.rpc.get_balance(&resolved_addr)?;

            // Fetch token accounts for known stablecoins.
            let token_rpc = ToolRpc::new(&rpc_url);
            let token_req = selo_core::rpc::token_accounts_request(&resolved_addr)?;
            let token_req_json: Value = serde_json::from_str(&token_req)
                .map_err(|e| format!("Bad token request: {e}"))?;
            let token_res = token_rpc.post(token_req_json)?;
            let tokens: Vec<selo_core::rpc::TokenBalance> =
                selo_core::rpc::parse_token_accounts(&token_res.to_string())?;

            // Live rates for USD conversion.
            let ptax = fx_source.latest_ptax().unwrap_or_else(get_historical_ptax);
            let sol_usd = fx_source.latest_sol_usd().unwrap_or(20.0);

            let sol_balance = lamports as f64 / 1_000_000_000.0;
            let sol_usd_val = sol_balance * sol_usd;
            let sol_brl = sol_usd_val * ptax;

            println!("Wallet: {resolved_addr}");
            println!("{:-<52}", "");
            println!(
                "  {:<6} {:>12.6}   $ {:>10.2}   R$ {:>10.2}",
                "SOL", sol_balance, sol_usd_val, sol_brl
            );

            let mut total_usd = sol_usd_val;
            // Known stablecoin mints (1:1 USD peg).
            let stable_mints: [(&str, &str); 3] = [
                ("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "USDC"),
                ("Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", "USDT"),
                ("2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH", "USDG"),
            ];
            for t in &tokens {
                let symbol = mint_to_symbol(&t.mint);
                let ui_amt: f64 = t.ui_amount.parse().unwrap_or(0.0);
                let usd_val = if stable_mints.iter().any(|(m, _)| *m == t.mint) {
                    ui_amt // stablecoins â‰ˆ $1
                } else if symbol == "SOL" {
                    ui_amt * sol_usd // wrapped SOL
                } else {
                    0.0 // unknown tokens: no USD price
                };
                let brl_val = usd_val * ptax;
                total_usd += usd_val;
                println!(
                    "  {:<6} {:>12.6}   $ {:>10.2}   R$ {:>10.2}",
                    symbol, t.ui_amount, usd_val, brl_val
                );
            }
            println!("{:-<52}", "");
            println!(
                "  TOTAL                    $ {:>10.2}   R$ {:>10.2}",
                total_usd, total_usd * ptax
            );
        }
        Commands::Close {
            merchant,
            start,
            end,
            output,
        } => {
            let wallets = close_wallets(merchant.as_deref(), &rules)?;
            let blockhash = engine.rpc.get_latest_blockhash()?;
            for (idx, resolved_merchant) in wallets.iter().enumerate() {
                if wallets.len() > 1 {
                    println!(
                        "===== Close {}/{} · merchant {} =====",
                        idx + 1,
                        wallets.len(),
                        resolved_merchant
                    );
                } else {
                    println!(
                        "Building daily close for merchant {} from {} to {}...",
                        resolved_merchant, start, end
                    );
                }

                let close_record = build_close_from_store(resolved_merchant, start, end)?;
                let prepared = selo_core::close::prepare_anchor(&close_record, &blockhash, None)?;

                if let Some(out_path) = &output {
                    let path = if wallets.len() > 1 {
                        let short = &resolved_merchant[..resolved_merchant.len().min(8)];
                        format!("{}.{}", out_path, short)
                    } else {
                        out_path.clone()
                    };
                    fs::write(&path, close_record.canonical_record()).map_err(|e| {
                        format!("Failed to write canonical record to {}: {}", path, e)
                    })?;
                    println!("✓ Canonical audit record written to '{}'", path);
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
        }
        Commands::Refund {
            quote_id,
            merchant,
            mint,
            decimals,
            sales_point,
        } => {
            let store = load_store();
            if store.quotes.is_empty() {
                println!("âœ— No quotes found in local store. Issue a quote first using 'selo-tool issue'.");
                return Ok(());
            }

            let quote = store
                .quotes
                .iter()
                .find(|q| q.id == quote_id)
                .ok_or_else(|| format!("Quote ID [{}] not found in store.", quote_id))?;

            let (tx_sig, _settled_at) = match &quote.status {
                QuoteStatus::Settled {
                    tx_signature,
                    settled_at,
                } => (tx_signature.clone(), *settled_at),
                QuoteStatus::Refunded { signature, .. } => {
                    println!("âœ— Quote [{}] was already refunded (signature: {})", quote_id, signature);
                    return Ok(());
                }
                QuoteStatus::Expired => {
                    println!("âœ— Quote [{}] is expired and cannot be refunded.", quote_id);
                    return Ok(());
                }
                QuoteStatus::Pending => {
                    println!("âœ— Quote [{}] has not been settled yet. Wait for on-chain payment first.", quote_id);
                    return Ok(());
                }
                QuoteStatus::Closed => {
                    println!("âœ— Quote [{}] was manually closed and cannot be refunded.", quote_id);
                    return Ok(());
                }
            };

            let resolved_merchant = resolve_address(&merchant, &rules);
            let shop = ShopConfig {
                merchant_address: resolved_merchant.clone(),
                mint: mint.clone(),
                decimals,
                sales_point,
                quote_ttl_secs: 900,
            };
            let policy = RefundPolicy::from_section(&std::collections::HashMap::new());

            println!("Fetching transaction {} from RPC...", tx_sig);
            let tx_json = engine.rpc.get_transaction(&tx_sig)?;
            if tx_json.is_null() {
                return Err(format!(
                    "RPC returned null for transaction {} -- it may be too old or not yet finalized.",
                    tx_sig
                ));
            }

            // We need the raw JSON string for parse_settlement_payment which uses
            // serde_json directly rather than a pre-parsed Value. Re-serialize.
            let body = serde_json::to_string(&tx_json).map_err(|e| format!("re-serialize: {e}"))?;

            let payment = parse_settlement_payment(
                &tx_sig,
                &resolved_merchant,
                &mint,
                &body,
            )?
            .ok_or_else(|| {
                format!(
                    "Transaction {} does not show a payment to merchant {} in mint {}.",
                    tx_sig, resolved_merchant, mint
                )
            })?;

            // Recover the order reference from the amount tag in the payment.
            let order = OrderRef::from_payment(&payment)?
                .ok_or_else(|| {
                    format!(
                        "Payment {} is an untagged transfer (amount {} base units). \
                         It carries no order reference, so it cannot be refunded through \
                         the automatic path.",
                        tx_sig, payment.amount_base_units
                    )
                })?;

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let blockhash = engine.rpc.get_latest_blockhash()?;

            let prepared = prepare_refund(
                order,
                &[payment],
                &shop,
                &policy,
                &[], // no prior refund records for now
                &resolved_merchant,
                &blockhash,
                now,
            )?;

            let approval = render_approval(&prepared)?;

            println!("\n{}", approval);
            let msg_hex: String = prepared.message.iter().map(|b| format!("{:02x}", b)).collect();
            println!("\nUnsigned refund message (hex, {} bytes):", prepared.message.len());
            // Print in 64-byte chunks for readability
            for chunk in msg_hex.as_bytes().chunks(128) {
                println!("  {}", std::str::from_utf8(chunk).unwrap_or(""));
            }
            println!(
                "Submit this transaction with your wallet. The bytes encode TransferChecked\n\
                 for {} base units of {} back to wallet {} (token account {}).",
                prepared.amount_base_units, prepared.mint,
                prepared.destination_owner, prepared.destination_ata
            );
        }
        Commands::TaxReport => {
            let multi_ledger = load_all_multi_ledgers();
            if multi_ledger.wallets.is_empty() {
                println!("No ledger files found. Run 'selo-tool ingest <pubkey> --all' first.");
                return Ok(());
            }
            let cumulative = multi_ledger.cumulative_ledger();
            if cumulative.lots.is_empty() {
                println!("Ledger files found but contain no tax lots. Run 'selo-tool ingest <pubkey> --all' to populate them.");
                return Ok(());
            }
            let report = cumulative.generate_report()?;
            println!(
                "Tax Report across {} wallet(s), {} lot(s):\n{}",
                multi_ledger.wallets.len(),
                cumulative.lots.len(),
                report
            );
        }
        Commands::Anchor {
            merchant,
            start,
            end,
            nonce_account,
            authority,
        } => {
            let wallets = close_wallets(merchant.as_deref(), &rules)?;
            println!(
                "Generating durable-nonce anchor from {} to {}...",
                start, end
            );
            println!("  Nonce account : {}", nonce_account);
            println!("  Nonce authority: {}", authority);

            println!("Fetching nonce account state from chain...");
            let account = engine.rpc.get_account_info(&nonce_account)?;
            if account.get("value").map(Value::is_null).unwrap_or(false) {
                return Err(format!(
                    "RPC returned null for nonce account {} -- it does not exist on chain.",
                    nonce_account
                ));
            }
            let nonce_state =
                selo_core::nonce::nonce_state_from_account_info(&nonce_account, &authority, &account)?;

            for (idx, resolved_merchant) in wallets.iter().enumerate() {
                if wallets.len() > 1 {
                    println!(
                        "===== Anchor {}/{} · merchant {} =====",
                        idx + 1,
                        wallets.len(),
                        resolved_merchant
                    );
                }
                let close_record = build_close_from_store(resolved_merchant, start, end)?;

            let prepared = selo_core::close::prepare_anchor(
                &close_record,
                &nonce_state.current_nonce,
                Some(&nonce_state),
            )?;

            println!("===================================================");
            println!("       DURABLE-NONCE DAILY CLOSE & COMMITMENT      ");
            println!("===================================================");
            println!("Merchant Pubkey : {}", resolved_merchant);
            println!("Window          : {} -> {}", start, end);
            println!("Lines Count     : {}", close_record.lines.len());
            println!("Commitment Base58: {}", close_record.commitment_base58());
            println!("Anchor Memo     : {}", close_record.anchor_memo());
            println!(
                "Durable Nonce   : {} (account {})",
                prepared.blockhash, prepared.durable_nonce_account.as_deref().unwrap_or("-")
            );
            println!("---------------------------------------------------");
            let msg_hex: String = prepared.message.iter().map(|b| format!("{:02x}", b)).collect();
            println!("Unsigned anchor message (hex, {} bytes):", prepared.message.len());
            for chunk in msg_hex.as_bytes().chunks(128) {
                println!("  {}", std::str::from_utf8(chunk).unwrap_or(""));
            }
            println!(
                "Submit this transaction with your wallet. The bytes encode an\n\
                 AdvanceNonceAccount instruction followed by an SPL Memo carrying the\n\
                 Poseidon commitment, so the anchor never expires while awaiting signature."
            );
            println!("===================================================");
            }
        }
        Commands::Issue {
            amount,
            sol,
            recipient,
            label,
            message,
        } => {
            let resolved_recipient = resolve_address(&recipient, &rules);
            let amount = match (amount, sol.as_deref()) {
                (Some(lamports), _) => lamports,
                (None, Some(sol_str)) => selo_core::format::sol_to_lamports(sol_str)?,
                (None, None) => {
                    return Err(
                        "Provide --sol <SOL> (e.g. 1.5) or --amount <lamports>.".to_string()
                    )
                }
            };
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
            // Reference key: a valid 32-byte pubkey derived from the ms
            // timestamp and a process-local counter, spread across the full
            // key so the base58 encoding is always a 44-char valid address.
            // getSignaturesForAddress(reference) is what confirm scans, so the
            // reference must be a real Solana account-shaped key.
            let counter = QUOTE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let ref_key_seed = (now.as_millis() as u64) | ((counter as u64) << 48);
            let seed_bytes = ref_key_seed.to_le_bytes();
            let mut ref_bytes = [0u8; 32];
            for i in 0..8 {
                ref_bytes[i] = seed_bytes[i];
                ref_bytes[i + 8] = seed_bytes[i] ^ 0xA5;
                ref_bytes[i + 16] = seed_bytes[i] ^ 0x5A;
                ref_bytes[i + 24] = seed_bytes[i] ^ 0xFF;
            }
            let reference_pubkey = bs58::encode(&ref_bytes).into_string();
            let now_secs = now.as_secs();

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
                created_at: now_secs,
                expires_at: now_secs + 900,
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
            match qrcode::QrCode::new(uri.as_bytes()) {
                Ok(code) => {
                    println!("  QR Code    : (scan with a Solana wallet)");
                    let qr = code
                        .render::<qrcode::render::unicode::Dense1x2>()
                        .module_dimensions(1, 1)
                        .build();
                    for line in qr.lines() {
                        println!("    {}", line);
                    }
                }
                Err(_) => println!("  QR Code    : (unavailable)"),
            }
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
                                println!("  âœ“ Quote [{}] SETTLED via Tx: {}", quote_id, sig);
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
                println!("âœ“ Registered Counterparty Rule: {} -> {}", pubkey, lbl);
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
            payments_as_expenses,
        } => {
            let resolved_addr = resolve_address(&address, &rules);
            let entity_label = rules.get_name(&resolved_addr);
            if payments_as_expenses {
                println!(
                    "Policy: outbound transfers to counterparties will be treated as expenses (no capital loss booked)."
                );
            }
            println!(
                "Ingesting & categorizing transaction history for: {} [{}]",
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
                "Found {} signature(s) to ingest. Processing transactions...",
                signatures.len()
            );

            let mut multi_ledger = load_multi_ledger(&resolved_addr);
            if payments_as_expenses {
                // Persist the policy so reconcile applies it on every
                // rebuild, not just this run.
                multi_ledger
                    .get_mut_ledger(&resolved_addr)
                    .payments_as_expenses = true;
            }
            let processed: std::collections::BTreeSet<String> = {
                let ledger = multi_ledger.get_mut_ledger(&resolved_addr);
                ledger.processed_signatures.clone()
            };

            let fresh_sigs: Vec<&String> = signatures
                .iter()
                .filter(|s| !processed.contains(*s))
                .collect();
            let skipped = signatures.len() - fresh_sigs.len();
            if skipped > 0 {
                println!(
                    "Resuming: {} signature(s) already processed, {} remaining.",
                    skipped,
                    fresh_sigs.len()
                );
            }

            let mut all_events = Vec::new();
            let mut event_index = 0usize;
            let mut classified_count = 0;
            let mut unclassified_count = 0;
            let mut classified_addrs = std::collections::BTreeSet::new();
            let mut unclassified_addrs = std::collections::BTreeSet::new();
            let mut date_cache = DateCache::new(fx_source);

            // Fetch transactions concurrently. A wallet with tens of thousands
            // of signatures is dominated by sequential getTransaction round
            // trips, so prefetch a bounded window in parallel and then process
            // the window in signature order. Checkpointing still runs after
            // every signature, so a crash resumes from the same place.
            let rpc_arc = Arc::new(ToolRpc::new(&rpc_url));
            let fetch_workers = 8usize;

            // Progress tracking for the CLI and for the Telegram adapter, which
            // parses these lines to show the operator a percentage and an ETA.
            let total_fresh = fresh_sigs.len();
            let ingest_start = SystemTime::now();
            let mut done_count: usize = 0;

            let mut sig_iter = fresh_sigs.iter().peekable();
            while sig_iter.peek().is_some() {
                let window: Vec<&String> = sig_iter.by_ref().take(64).map(|s| *s).collect();
                let fetched = std::thread::scope(|scope| {
                    let mut handles = Vec::new();
                    let mut chunks: Vec<Vec<&String>> = Vec::new();
                    let chunk_size = window.len().div_ceil(fetch_workers).max(1);
                    for chunk in window.chunks(chunk_size) {
                        chunks.push(chunk.to_vec());
                    }
                    for chunk in chunks {
                        let rpc = Arc::clone(&rpc_arc);
                        handles.push(scope.spawn(move || {
                            let mut out = Vec::with_capacity(chunk.len());
                            for sig in chunk {
                                let tx = rpc.get_transaction(sig).ok().filter(|v| !v.is_null());
                                out.push((sig.clone(), tx));
                            }
                            out
                        }));
                    }
                    let mut merged: Vec<(String, Option<Value>)> = Vec::with_capacity(window.len());
                    for h in handles {
                        merged.extend(h.join().unwrap_or_default());
                    }
                    // Restore signature order so events are recorded in the
                    // same order a sequential run would have produced them.
                    merged.sort_by_key(|(sig, _)| sig.clone());
                    merged
                });

                for (sig, tx_data) in fetched {
                    if let Some(tx_data) = tx_data {
                        let events =
                            parse_transaction_events(&sig, &tx_data, &resolved_addr, &rules);
                        for ev in &events {
                            if ev.is_classified {
                                classified_count += 1;
                                if let Some(cp_addr) = &ev.counterparty_address {
                                    classified_addrs.insert(cp_addr.clone());
                                }
                            } else {
                                unclassified_count += 1;
                                if let Some(cp_addr) = &ev.counterparty_address {
                                    unclassified_addrs.insert(cp_addr.clone());
                                    let ledger_ref = multi_ledger.get_mut_ledger(&resolved_addr);
                                    ledger_ref
                                        .unclassified_counterparties
                                        .insert(cp_addr.clone());
                                }
                            }

                            all_events.push(ev.clone());
                            event_index += 1;

                            // Record the event for the integer book. The
                            // ledger persists events and rebuilds the book
                            // from them, so a re-run never loses or
                            // duplicates an acquisition.
                            {
                                let ledger_ref = multi_ledger.get_mut_ledger(&resolved_addr);
                                ledger_ref.record_event(ev.clone());
                            }

                            let decimals = ev.decimals;
                            let ui_amt = ev.amount_base_units as f64 / 10f64.powi(decimals as i32);
                            let cp_display: String = match &ev.counterparty {
                                Some(label) if label.len() > 18 => {
                                    format!("{}...", &label[..18])
                                }
                                Some(label) => label.clone(),
                                None => match &ev.counterparty_address {
                                    Some(addr) if addr.len() > 8 => {
                                        format!("{}...", &addr[..8])
                                    }
                                    Some(addr) => addr.clone(),
                                    None => "Unknown".to_string(),
                                },
                            };
                            let status_display = if ev.is_classified {
                                "auto-labeled"
                            } else {
                                "! needs review"
                            };
                            let symbol = mint_to_symbol(&ev.mint);
                            println!(
                                "  [{:>2}] {:<10} {:>13.6} {:<6} {:<22} {}",
                                event_index,
                                ev.kind.as_str(),
                                ui_amt,
                                symbol,
                                cp_display,
                                status_display
                            );
                        }

                        // Events are collected and displayed here. Lot
                        // creation and disposal happen after the loop so we
                        // can create opening-balance lots for assets with a
                        // net shortfall (funded externally or before tracking).
                    }

                    // Save periodically so an interrupted run resumes close
                    // to where it stopped, without paying the cost of a full
                    // JSON serialization after every single signature (which
                    // dominates ingest once the file grows past a few MB).
                    {
                        let ledger = multi_ledger.get_mut_ledger(&resolved_addr);
                        ledger.processed_signatures.insert(sig.to_string());
                    }
                    done_count += 1;
                    if done_count % 25 == 0 || done_count == total_fresh {
                        let elapsed = SystemTime::now()
                            .duration_since(ingest_start)
                            .unwrap_or_default()
                            .as_secs_f64();
                        let rate = done_count as f64 / elapsed.max(0.001);
                        let remaining = total_fresh.saturating_sub(done_count);
                        let eta_secs = (remaining as f64 / rate.max(0.001)) as u64;
                        let pct = (done_count as f64 / total_fresh.max(1) as f64) * 100.0;
                        println!(
                            "SELO_PROGRESS {}/{} ({:.1}%) ~{:.1}/s ETA {}s",
                            done_count, total_fresh, pct, rate, eta_secs
                        );
                    }
                    if event_index % 100 == 0 {
                        save_multi_ledger(&resolved_addr, &multi_ledger);
                    }
                }
            }
            save_multi_ledger(&resolved_addr, &multi_ledger);

            // ---- Integer FIFO book reconcile ----
            //
            // The book is rebuilt from the full persisted event history on
            // every run, so an interrupted or resumed ingest re-derives the
            // same positions instead of mutating a partial set. Income opens
            // a lot at the day's PTAX rate; Expense closes lots FIFO with
            // proceeds from any same-signature income (a swap) or none (a
            // pure payment). Assets with a net shortfall across the whole
            // history get an opening-balance lot at the earliest date, since
            // they were funded externally or before tracking began.
            {
                let ledger = multi_ledger.get_mut_ledger(&resolved_addr);
                let cache = std::cell::RefCell::new(&mut date_cache);
                let rate = |symbol: &str, ymd: &str| {
                    cache.borrow_mut().cost_basis(symbol, ymd)
                };
                let ptax = |ymd: &str| cache.borrow_mut().get_or_fetch_ptax(ymd);
                ledger.reconcile(&rate, &ptax)?;

                let total_proceeds: f64 = ledger.gain_records.iter().map(|g| g.proceeds_brl).sum();
                let total_cost_basis: f64 =
                    ledger.gain_records.iter().map(|g| g.cost_basis_brl).sum();
                let total_gain: f64 = ledger.gain_records.iter().map(|g| g.gain_brl).sum();
                let mut last_symbol = "";
                let mut last_ref = "";
                for d in &ledger.disposals {
                    if d.disposal_ref == last_ref && d.mint == last_symbol {
                        continue;
                    }
                    last_ref = &d.disposal_ref;
                    last_symbol = &d.mint;
                    let symbol = mint_to_symbol(&d.mint);
                    let decimals = decimals_for_symbol(symbol);
                    let ui_amt = d.quantity_base_units as f64 / 10f64.powi(decimals as i32);
                    let cost = d.cost_basis_base_units as f64 / 1_000_000.0;
                    let proceeds = d.proceeds_base_units as f64 / 1_000_000.0;
                    let gain = d.gain_base_units as f64 / 1_000_000.0;
                    let swap_marker = if d.proceeds_base_units > 0 { " [swap]" } else { "" };
                    let gain_sign = if gain >= 0.0 { "+" } else { "" };
                    println!(
                        "         dispose_fifo: {:.6} {} â†’ cost R$ {:.2}, proceeds R$ {:.2}, gain R$ {}{:.2}{}",
                        ui_amt, symbol, cost, proceeds, gain_sign, gain, swap_marker
                    );
                }
                if !ledger.gain_records.is_empty() {
                    let net_sign = if total_gain >= 0.0 { "+" } else { "" };
                    println!(
                        "         ---------------------------------------------------"
                    );
                    println!(
                        "         Capital Gains Summary: {} disposal(s)",
                        ledger.gain_records.len()
                    );
                    println!(
                        "           Total proceeds:    R$ {:>10.2}",
                        total_proceeds
                    );
                    println!(
                        "           Total cost basis:  R$ {:>10.2}",
                        total_cost_basis
                    );
                    println!(
                        "           Net gain/loss:     R$ {}{:.2}",
                        net_sign, total_gain
                    );
                }
            }
            save_multi_ledger(&resolved_addr, &multi_ledger);

            println!("=======================================================================================================");
            println!("                                    INGESTED LEDGER EVENTS SUMMARY                                      ");
            println!("=======================================================================================================");
            if all_events.is_empty() {
                println!(" Notice: Processed {} signatures, but no net balance deltas exceeding threshold were found.", signatures.len());
            } else {
                println!("+------+------------+------------------+----------------------+--------------------+------------+");
                println!(
                    "| {:<4} | {:<10} | {:>16.6} | {:<20} | {:<18} | {:<10} |",
                    "N#", "KIND", "AMOUNT", "COUNTERPARTY", "MINT", "STATUS"
                );
                println!("+------+------------+------------------+----------------------+--------------------+------------+");
                for (i, ev) in all_events.iter().enumerate() {
                    let decimals = if ev.mint.starts_with("So111")
                        || ev.mint == selo_core::ledger::NATIVE_SOL_MINT
                    {
                        9
                    } else {
                        6
                    };
                    let ui_amt = ev.amount_base_units as f64 / 10f64.powi(decimals);
                    let cp_display = ev
                        .counterparty
                        .clone()
                        .unwrap_or_else(|| "Unknown".to_string());

                    let status_display = if ev.is_classified {
                        "âœ“ [Auto-Labeled]"
                    } else {
                        "! [Needs Review]"
                    };
                    let mint_display = if ev.mint.len() > 10 {
                        format!("{}...", &ev.mint[..8])
                    } else {
                        ev.mint.clone()
                    };
                    let amt_str = format!("{:.6}", ui_amt);

                    println!(
                        "| {:<4} | {:<10} | {:>16.6} | {:<20} | {:<18} | {:<10} |",
                        i + 1,
                        ev.kind.as_str(),
                        amt_str,
                        if cp_display.len() > 20 {
                            format!("{}...", &cp_display[..17])
                        } else {
                            cp_display
                        },
                        mint_display,
                        status_display
                    );
                }
                println!("+------+------------+------------------+----------------------+--------------------+------------+");
            }
            println!("=======================================================================================================");
            if !unclassified_addrs.is_empty() {
                println!(
                    "NEEDS REVIEW -- {} unclassified counterparties:",
                    unclassified_addrs.len()
                );
                for cp in &unclassified_addrs {
                    println!("  selo-tool rules --add {} --name \"Name Here\"", cp);
                }
                println!("Hint: Copy and paste the commands above, replacing \"Name Here\" with the counterparty's name.");
                println!("=======================================================================================================");
            }

            println!(
                "Ingestion Summary -> Total Events: {} | Auto-Labeled Events: {} (Unique Counterparties: {}) | Needs Review Events: {} (Unique Counterparties: {})",
                all_events.len(),
                classified_count,
                classified_addrs.len(),
                unclassified_count,
                unclassified_addrs.len()
            );
            println!("Hint: Use 'selo-tool rules --add <pubkey> --name <label>' to classify remaining unknown counterparties.");
            println!("âœ“ Tax lots updated and state saved successfully.");
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
                    println!("âœ“ No unclassified counterparties pending review!");
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
            let live_rate = fetch_live_ptax(fx_source.as_ref());
            let historical_baseline = get_historical_ptax();
            println!("{:-<50}", "");
            println!("  Ongoing / Live PTAX Rate : R$ {:.4}", live_rate);
            println!("  Historical Baseline PTAX : R$ {:.4}", historical_baseline);
        }
        Commands::RecordSample => {
            let live_ptax = fx_source.latest_ptax().unwrap_or_else(get_historical_ptax);
            println!("Recording sample acquisition for offline testing & PTAX verification (Live PTAX: R$ {:.4})...", live_ptax);

            let mut multi_ledger = load_multi_ledger("SampleWallet");
            {
                let ledger = multi_ledger.get_mut_ledger("SampleWallet");
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                ledger.record_event(selo_core::ledger::LedgerEvent {
                    block_time_unix: Some(now),
                    kind: selo_core::ledger::EventKind::Income,
                    amount_base_units: 1_000_000_000,
                    mint: selo_core::ledger::NATIVE_SOL_MINT.to_string(),
                    decimals: 9,
                    counterparty: Some("Sample".to_string()),
                    counterparty_address: None,
                    signature: format!("sample-live-{}", now),
                    is_classified: true,
                });
                let rate = |symbol: &str, _ymd: &str| {
                    if symbol == "SOL" {
                        live_ptax
                    } else {
                        live_ptax
                    }
                };
                let ptax = |_ymd: &str| live_ptax;
                ledger.reconcile(&rate, &ptax)?;
            }
            save_multi_ledger("SampleWallet", &multi_ledger);
            println!("✓ Sample test acquisition recorded successfully for offline reporting & PTAX verification.");
        }
        Commands::ExportHtml {
            year,
            wallet,
            anchor_sig,
            from,
            to,
            output,
        } => {
            let multi_all = load_all_multi_ledgers();
            let resolved_wallet = wallet.as_deref().map(|w| resolve_address(w, &rules));
            let ledger = match &resolved_wallet {
                Some(w) => {
                    let multi = load_multi_ledger(w);
                    match multi.get_ledger(w) {
                        Some(l) => l.clone(),
                        None => {
                            println!(
                                "No ledger found for wallet '{}'. Run ingest first.",
                                w
                            );
                            return Ok(());
                        }
                    }
                }
                None => {
                    // No wallet named: export the sole ingested wallet, or if
                    // several exist, list them and require a choice. Never
                    // silently blend wallets into one report.
                    if multi_all.wallets.is_empty() {
                        println!(
                            "No ledger files found. Run 'selo-tool ingest <pubkey> --all' first."
                        );
                        return Ok(());
                    }
                    if multi_all.wallets.len() == 1 {
                        let (sole_key, _) = multi_all.wallets.iter().next().unwrap();
                        match multi_all.get_ledger(sole_key) {
                            Some(l) => l.clone(),
                            None => {
                                println!("No ledger found for wallet '{}'. Run ingest first.", sole_key);
                                return Ok(());
                            }
                        }
                    } else {
                        println!(
                            "{} wallets are ingested. Pass --wallet <pubkey-or-name> to choose which one to export:",
                            multi_all.wallets.len()
                        );
                        println!("{:-<60}", "");
                        let mut wallets: Vec<&String> = multi_all.wallets.keys().collect();
                        wallets.sort();
                        for pubkey in wallets {
                            let label = rules.get_name(pubkey);
                            let label_note = if &label == pubkey {
                                String::new()
                            } else {
                                format!(" ({})", label)
                            };
                            println!("  {}{}", pubkey, label_note);
                        }
                        println!(
                            "{:-<60}",
                            ""
                        );
                        println!(
                            "Example: selo-tool export-html --year 2026 --wallet <pubkey> --output audit.html"
                        );
                        return Ok(());
                    }
                }
            };
            if ledger.is_empty() {
                match &resolved_wallet {
                    Some(w) => println!(
                        "No tax lots recorded for wallet {}. Run 'selo-tool ingest {} --all' first.",
                        w, w
                    ),
                    None => println!(
                        "No tax lots recorded in any ledger. Run 'selo-tool ingest <pubkey> --all' first."
                    ),
                }
                return Ok(());
            }
            let html_content =
                ledger.generate_html_report(year.as_deref(), anchor_sig.as_deref(), from.as_deref(), to.as_deref())?;
            fs::write(&output, html_content)
                .map_err(|e| format!("Failed to write HTML report to {}: {}", output, e))?;
            let wallet_note = match &resolved_wallet {
                Some(w) => format!(" for wallet {}", w),
                None => String::new(),
            };
            let range_note = match (&from, &to) {
                (Some(f), Some(t)) => format!(" ({} to {})", f, t),
                (Some(f), None) => format!(" (from {})", f),
                (None, Some(t)) => format!(" (until {})", t),
                (None, None) => String::new(),
            };
            let year_note = match &year {
                Some(y) => format!(" for fiscal year {}", y),
                None => String::from(" for all wallet history"),
            };
            println!(
                "âœ“ Exported self-verifying HTML audit report to '{}'{}{}{}",
                output, wallet_note, year_note, range_note
            );
        }
        Commands::Verify { root } => {
            let multi_ledger = load_all_multi_ledgers();
            if multi_ledger.wallets.is_empty() {
                println!("No ledger files found. Run 'selo-tool ingest <pubkey> --all' first.");
                println!("  Target Root Provided : {}", root);
                println!("  Computed Local Root  : 0x0");
                println!("{:-<60}", "");
                if root == "0x0" {
                    println!("âœ“ VERIFICATION TRIVIAL: Empty ledger matches empty root.");
                } else {
                    println!("âœ— VERIFICATION FAILED: No local ledger data to verify against the target root.");
                }
                return Ok(());
            }
            let cumulative = multi_ledger.cumulative_ledger();
            let computed_root = cumulative.compute_state_root()?;
            println!("Computing local tax ledger state root (Poseidon BN254)...");
            println!(
                "  Wallets loaded      : {}",
                multi_ledger.wallets.len()
            );
            println!("  Total lots           : {}", cumulative.lots.len());
            println!("  Target Root Provided : {}", root);
            println!("  Computed Local Root  : {}", computed_root);
            println!("{:-<60}", "");
            if computed_root == root {
                println!("âœ“ VERIFICATION SUCCESSFUL: Local ledger state cryptographically matches the target root!");
            } else {
                println!("âœ— VERIFICATION FAILED: Computed root does not match target root. Ledger data may have been altered.");
            }
        }
        Commands::Prove {
            merchant,
            start,
            end,
            line,
        } => {
            let resolved_merchant = close_wallets(merchant.as_deref(), &rules)?;
            if resolved_merchant.len() > 1 {
                return Err(
                    "Prove needs a single merchant wallet; pass --merchant <PUBKEY> explicitly."
                        .to_string(),
                );
            }
            let merchant = &resolved_merchant[0];
            let close_record = build_close_from_store(merchant, start, end)?;
            let statement = selo_core::prove::line_statement(&close_record, line)?;
            println!("Generating offline Groth16 proof over BN254...");
            println!("  Merchant        : {}", merchant);
            println!("  Window          : {} -> {}", start, end);
            println!("  Line Index      : {}", statement.line_index);
            println!("  Leaf (hex)      : 0x{}", hex_string(&statement.leaf));
            println!("  Merkle Root     : 0x{}", hex_string(&statement.root));
            println!("  Proof Path Depth: {}", statement.proof_path.len());
            let (pk, vk, proof) = selo_core::prove::prove_inclusion(
                statement.root,
                statement.line_index,
                statement.leaf,
                statement.proof_path.clone(),
            )?;
            let public = selo_core::prove::statement_public_inputs(&statement)?;
            let bytes = selo_core::prove::serialize_proof(&proof)?;
            let pk_size = selo_core::prove::proving_key_size(&pk)?;
            println!("  Proving Key     : {} bytes", pk_size);
            println!("  Proof Size      : {} bytes", bytes.len());
            println!("  Public Inputs   : {} (root + {} index bits)", public.len(), statement.proof_path.len());
            match selo_core::prove::verify_inclusion(&vk, &public, &proof) {
                Ok(true) => {
                    println!("  Verification    : OK - the leaf is committed under the root");
                    println!("  Proof (hex)     : 0x{}", hex_string(&bytes));
                }
                Ok(false) => println!("  Verification    : FAILED - proof did not verify locally"),
                Err(e) => println!("  Verification    : ERROR - {e}"),
            }
        }
        Commands::Wallets => {
            let multi_ledger = load_all_multi_ledgers();
            if multi_ledger.wallets.is_empty() {
                println!("No ledger files found. Run 'selo-tool ingest <pubkey> --all' first.");
                return Ok(());
            }
            println!("Ingested wallet ledgers ({}):", multi_ledger.wallets.len());
            println!("{:-<60}", "");
            let mut wallets: Vec<(&String, &selo_core::lots::TaxLedger)> =
                multi_ledger.wallets.iter().collect();
            wallets.sort_by(|a, b| a.0.cmp(b.0));
            for (pubkey, ledger) in wallets {
                let label = rules.get_name(pubkey);
                let label_note = if &label == pubkey {
                    String::new()
                } else {
                    format!(" ({})", label)
                };
                let first = ledger
                    .lots
                    .iter()
                    .map(|l| l.acquired_at_utc.clone())
                    .min()
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "  {}{}\n    lots: {}  gains: {}  from: {}",
                    pubkey,
                    label_note,
                    ledger.lots.len(),
                    ledger.gain_records.len(),
                    first
                );
            }
        }
        Commands::Merchant {
            set,
            name,
            mode,
            add,
            remove,
        } => {
            let mut cfg = load_merchant();
            if let Some(pubkey) = &set {
                let resolved = resolve_address(pubkey, &rules);
                let wallet_name = name.clone().unwrap_or_else(|| rules.get_name(&resolved));
                let mode = mode.clone().unwrap_or_else(|| "personal".to_string());
                if mode != "personal" && mode != "business" {
                    return Err(format!("Unknown mode '{}'. Use personal or business.", mode));
                }
                cfg.mode = mode;
                cfg.updated_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                // Replace any existing primary, then ensure this wallet is
                // the primary tracked wallet.
                cfg.tracked_wallets.retain(|w| w.pubkey != resolved);
                cfg.tracked_wallets
                    .retain(|w| w.pubkey == resolved || !w.primary);
                cfg.tracked_wallets.push(TrackedWallet {
                    pubkey: resolved.clone(),
                    name: wallet_name,
                    primary: true,
                });
                save_merchant(&cfg);
                println!("✓ Merchant configured (mode: {}):", cfg.mode);
                for w in &cfg.tracked_wallets {
                    let mark = if w.primary { "primary" } else { "tracked" };
                    println!("  {}  {}  ({})", mark, w.pubkey, w.name);
                }
                return Ok(());
            }
            if let Some(pubkey) = &add {
                let resolved = resolve_address(pubkey, &rules);
                if cfg.tracked_wallets.iter().any(|w| w.pubkey == resolved) {
                    println!("Wallet {} is already tracked.", resolved);
                    return Ok(());
                }
                let wallet_name = name.clone().unwrap_or_else(|| rules.get_name(&resolved));
                cfg.tracked_wallets.push(TrackedWallet {
                    pubkey: resolved.clone(),
                    name: wallet_name,
                    primary: false,
                });
                cfg.updated_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                save_merchant(&cfg);
                println!("✓ Added tracked wallet {} ({})", resolved, rules.get_name(&resolved));
                return Ok(());
            }
            if let Some(pubkey) = &remove {
                let resolved = resolve_address(pubkey, &rules);
                let before = cfg.tracked_wallets.len();
                cfg.tracked_wallets.retain(|w| w.pubkey != resolved);
                if cfg.tracked_wallets.len() == before {
                    println!("Wallet {} was not tracked.", resolved);
                    return Ok(());
                }
                // If the primary was removed, promote the first remaining.
                if cfg.primary().is_none() && !cfg.tracked_wallets.is_empty() {
                    cfg.tracked_wallets[0].primary = true;
                }
                save_merchant(&cfg);
                println!("✓ Removed tracked wallet {}", resolved);
                return Ok(());
            }
            if cfg.tracked_wallets.is_empty() {
                println!("Merchant: unconfigured (mode: {})", cfg.mode);
                println!("  Run 'selo-tool merchant --set <pubkey> --name <label>' to set up.");
            } else {
                println!("Merchant (mode: {}):", cfg.mode);
                for w in &cfg.tracked_wallets {
                    let mark = if w.primary { "primary" } else { "tracked" };
                    println!("  {:<7} {}  ({})", mark, w.pubkey, w.name);
                }
            }
        }
    }
    Ok(())
}
