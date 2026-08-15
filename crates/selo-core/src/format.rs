use crate::jupiter::{SwapQuote, TokenPrice};
use crate::lots::{GainRecord, TaxLedger};
use crate::priority::FeeEstimate;
use crate::rpc::TokenBalance;
use crate::simulate::Simulation;
use crate::token::TokenTransfer;
use crate::tx::TxSummary;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

/// Parse a human-written SOL amount ("0.5", "1", "2.25") into lamports.
/// Rejects values that do not land on a whole lamport or that overflow.
pub fn sol_to_lamports(sol: &str) -> Result<u64, String> {
    let s = sol.trim();
    if s.is_empty() {
        return Err("empty SOL amount".to_string());
    }
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if frac.len() > 9 {
        return Err(format!(
            "SOL amount '{s}' has more than 9 decimal places; the smallest unit is a lamport"
        ));
    }
    let whole_u: u64 = if whole.is_empty() {
        0
    } else {
        whole
            .parse::<u64>()
            .map_err(|_| format!("'{s}' is not a valid SOL amount"))?
    };
    let frac_u: u64 = if frac.is_empty() {
        0
    } else {
        frac.parse::<u64>()
            .map_err(|_| format!("'{s}' is not a valid SOL amount"))?
    };
    let frac_lamports = frac_u
        .checked_mul(10u64.pow((9 - frac.len()) as u32))
        .ok_or_else(|| format!("SOL amount '{s}' overflows"))?;
    let lamports = whole_u
        .checked_mul(LAMPORTS_PER_SOL)
        .and_then(|w| w.checked_add(frac_lamports))
        .ok_or_else(|| format!("SOL amount '{s}' overflows lamports"))?;
    Ok(lamports)
}

/// Render lamports as a SOL decimal string with trailing zeros trimmed.
pub fn lamports_to_sol(lamports: u64) -> String {
    let whole = lamports / LAMPORTS_PER_SOL;
    let frac = lamports % LAMPORTS_PER_SOL;
    if frac == 0 {
        return whole.to_string();
    }
    let frac_str = format!("{frac:09}");
    let trimmed = frac_str.trim_end_matches('0');
    format!("{whole}.{trimmed}")
}

/// Render the full tool output for a balance query.
pub fn render_balance(address: &str, lamports: u64, tokens: Option<&[TokenBalance]>) -> String {
    let sol = lamports_to_sol(lamports);
    let mut summary = format!("{address} holds {sol} SOL ({lamports} lamports)");
    match tokens {
        None => {}
        Some([]) => summary.push_str(" and no SPL token accounts"),
        Some(list) => {
            summary.push_str(&format!(" and {} SPL token account(s):", list.len()));
            for t in list {
                summary.push_str(&format!("\n  {} of mint {}", t.ui_amount, t.mint));
            }
        }
    }

    let json_block = json!({
        "address": address,
        "lamports": lamports,
        "sol": sol,
        "tokens": tokens.map(|list| {
            list.iter()
                .map(|t| json!({
                    "mint": t.mint,
                    "amount_raw": t.amount_raw,
                    "decimals": t.decimals,
                    "ui_amount": t.ui_amount,
                }))
                .collect::<Vec<_>>()
        }),
    });

    format!("{summary}\n\n{json_block}")
}

/// Render a signed lamport delta as a SOL string with its sign.
fn delta_to_sol(delta: i128) -> String {
    let magnitude = delta.unsigned_abs() as u64;
    let sign = if delta < 0 { "-" } else { "+" };
    format!("{sign}{}", lamports_to_sol(magnitude))
}

/// Render the full tool output for a transaction lookup.
pub fn render_tx(s: &TxSummary) -> String {
    let status = match &s.error {
        None => "succeeded".to_string(),
        Some(e) => format!("FAILED with {e}"),
    };
    let mut summary = format!(
        "Transaction {} {status} in slot {}. Fee {} SOL paid by {}.",
        s.signature,
        s.slot,
        lamports_to_sol(s.fee_lamports),
        s.fee_payer
    );
    if let Some(t) = s.block_time_unix {
        summary.push_str(&format!(" Block time (unix) {t}."));
    }
    if let Some(cu) = s.compute_units {
        summary.push_str(&format!(" Consumed {cu} compute units."));
    }
    if !s.balance_changes.is_empty() {
        summary.push_str("\nBalance changes:");
        for c in &s.balance_changes {
            summary.push_str(&format!(
                "\n  {} {} SOL",
                c.account,
                delta_to_sol(c.delta_lamports)
            ));
        }
    }
    if !s.log_tail.is_empty() {
        summary.push_str("\nLast log lines:");
        for line in &s.log_tail {
            summary.push_str(&format!("\n  {line}"));
        }
    }

    let json_block = json!({
        "signature": s.signature,
        "slot": s.slot,
        "block_time_unix": s.block_time_unix,
        "error": s.error,
        "fee_lamports": s.fee_lamports,
        "fee_payer": s.fee_payer,
        "compute_units": s.compute_units,
        "balance_changes": s.balance_changes.iter().map(|c| json!({
            "account": c.account,
            "delta_lamports": c.delta_lamports.to_string(),
        })).collect::<Vec<_>>(),
    });

    format!("{summary}\n\n{json_block}")
}

/// Render the full tool output for a submitted transfer.
pub fn render_transfer(from: &str, to: &str, lamports: u64, signature: &str) -> String {
    let sol = lamports_to_sol(lamports);
    let summary = format!(
        "Submitted transfer of {sol} SOL ({lamports} lamports) from {from} to {to}. \
         Transaction signature: {signature}. The transaction passed preflight \
         simulation and was accepted by the RPC node; confirm finality by looking \
         up the signature."
    );
    let json_block = json!({
        "from": from,
        "to": to,
        "lamports": lamports,
        "sol": sol,
        "signature": signature,
    });
    format!("{summary}\n\n{json_block}")
}

/// Render a base-unit integer string using `decimals`.
pub fn base_units_to_decimal(raw: &str, decimals: u8) -> String {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return raw.to_string();
    }
    if decimals == 0 {
        return digits;
    }
    let d = decimals as usize;
    let padded = if digits.len() <= d {
        format!("{}{}", "0".repeat(d - digits.len() + 1), digits)
    } else {
        digits
    };
    let split = padded.len() - d;
    let whole = &padded[..split];
    let frac = padded[split..].trim_end_matches('0');
    if frac.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{frac}")
    }
}

/// Render the tool output for a price lookup.
pub fn render_prices(prices: &[TokenPrice], missing: &[String]) -> String {
    let mut summary = if prices.is_empty() {
        "No prices returned.".to_string()
    } else {
        let mut lines = Vec::with_capacity(prices.len());
        for p in prices {
            let change = match p.price_change_24h {
                Some(c) => format!(" ({c:+.2}% 24h)"),
                None => String::new(),
            };
            lines.push(format!("{} is ${:.6}{change}", p.mint, p.usd_price));
        }
        lines.join("\n")
    };
    if !missing.is_empty() {
        summary.push_str(&format!("\nNo price available for: {}", missing.join(", ")));
    }

    let json_block = json!({
        "prices": prices.iter().map(|p| json!({
            "mint": p.mint,
            "usd_price": p.usd_price,
            "decimals": p.decimals,
            "price_change_24h": p.price_change_24h,
            "liquidity": p.liquidity,
        })).collect::<Vec<_>>(),
        "unpriced": missing,
    });
    format!("{summary}\n\n{json_block}")
}

/// Render the tool output for a swap quote.
pub fn render_quote(q: &SwapQuote, in_decimals: Option<u8>, out_decimals: Option<u8>) -> String {
    let in_display = match in_decimals {
        Some(d) => base_units_to_decimal(&q.in_amount, d),
        None => q.in_amount.clone(),
    };
    let out_display = match out_decimals {
        Some(d) => base_units_to_decimal(&q.out_amount, d),
        None => q.out_amount.clone(),
    };
    let min_display = match out_decimals {
        Some(d) => base_units_to_decimal(&q.min_out_amount, d),
        None => q.min_out_amount.clone(),
    };

    let mut summary = format!(
        "Swapping {in_display} of {} yields about {out_display} of {}.",
        q.input_mint, q.output_mint
    );
    if let Some(usd) = q.usd_value {
        summary.push_str(&format!(" Trade value about ${usd:.2}."));
    }
    if let Some(impact) = q.price_impact_pct {
        summary.push_str(&format!(" Price impact {:.4}%.", impact * 100.0));
    }
    summary.push_str(&format!(
        " At {} bps slippage tolerance the guaranteed minimum is {min_display}.",
        q.slippage_bps
    ));
    if !q.route_labels.is_empty() {
        summary.push_str(&format!(" Route: {}.", q.route_labels.join(" then ")));
    }
    summary.push_str(" This is a quote only; nothing was swapped or signed.");

    let json_block = json!({
        "input_mint": q.input_mint,
        "output_mint": q.output_mint,
        "in_amount_base_units": q.in_amount,
        "out_amount_base_units": q.out_amount,
        "min_out_amount_base_units": q.min_out_amount,
        "slippage_bps": q.slippage_bps,
        "price_impact_pct": q.price_impact_pct,
        "usd_value": q.usd_value,
        "route": q.route_labels,
    });
    format!("{summary}\n\n{json_block}")
}

/// Render the tool output for an airdrop.
pub fn render_airdrop(
    address: &str,
    lamports: u64,
    signature: &str,
    status: Option<&str>,
) -> String {
    let sol = lamports_to_sol(lamports);
    let state = match status {
        Some(s) => format!("Status: {s}."),
        None => {
            "The node has not reported a confirmation yet; it usually lands within a few seconds."
                .to_string()
        }
    };
    let summary = format!(
        "Requested an airdrop of {sol} SOL ({lamports} lamports) to {address} on the configured test cluster. Signature: {signature}. {state}"
    );
    let json_block = json!({
        "address": address,
        "lamports": lamports,
        "sol": sol,
        "signature": signature,
        "confirmation_status": status,
    });
    format!("{summary}\n\n{json_block}")
}

/// Render the tool output for a simulated transfer.
pub fn render_simulation(from: &str, to: &str, lamports: u64, sim: &Simulation) -> String {
    let sol = lamports_to_sol(lamports);
    let mut summary = if sim.would_succeed() {
        format!(
            "Dry run only, nothing was sent. A transfer of {sol} SOL ({lamports} lamports) from {from} to {to} WOULD SUCCEED against the current chain state."
        )
    } else {
        format!(
            "Dry run only, nothing was sent. A transfer of {sol} SOL ({lamports} lamports) from {from} to {to} WOULD FAIL with {}.",
            sim.error.as_deref().unwrap_or("an unknown error")
        )
    };
    if let Some(cu) = sim.compute_units {
        summary.push_str(&format!(" Compute units consumed: {cu}."));
    }
    if !sim.logs.is_empty() {
        summary.push_str("\nProgram log:");
        for line in sim.logs.iter().take(8) {
            summary.push_str(&format!("\n  {line}"));
        }
    }

    let json_block = json!({
        "simulated": true,
        "would_succeed": sim.would_succeed(),
        "from": from,
        "to": to,
        "lamports": lamports,
        "sol": sol,
        "error": sim.error,
        "compute_units": sim.compute_units,
    });
    format!("{summary}\n\n{json_block}")
}

/// Render the tool output for a submitted SPL token transfer.
pub fn render_token_transfer(
    t: &TokenTransfer,
    mint_label: &str,
    created_destination: bool,
    signature: &str,
) -> String {
    let ui = base_units_to_decimal(&t.amount.to_string(), t.decimals);
    let mut summary = format!(
        "Submitted a transfer of {ui} {mint_label} ({} base units at {} decimals) to wallet {}. Signature: {signature}.",
        t.amount,
        t.decimals,
        crate::address::encode_pubkey(&t.destination_owner)
    );
    if created_destination {
        summary.push_str(
            " The recipient had no token account for this mint, so one was created in the same transaction; that cost a small amount of SOL in rent from the sending wallet.",
        );
    }
    summary.push_str(
        " The transaction passed preflight simulation and was accepted by the RPC node; confirm finality by looking up the signature.",
    );

    let json_block = json!({
        "signature": signature,
        "amount_base_units": t.amount,
        "amount_ui": ui,
        "decimals": t.decimals,
        "mint": crate::address::encode_pubkey(&t.mint),
        "destination_wallet": crate::address::encode_pubkey(&t.destination_owner),
        "source_token_account": t.source_ata_base58(),
        "destination_token_account": t.destination_ata_base58(),
        "created_destination_account": created_destination,
    });
    format!("{summary}\n\n{json_block}")
}

/// Render the tool output for an executed swap.
pub fn render_swap(
    q: &SwapQuote,
    in_label: &str,
    out_label: &str,
    in_decimals: Option<u8>,
    out_decimals: Option<u8>,
    priority_fee_lamports: Option<u64>,
    signature: &str,
) -> String {
    let in_display = match in_decimals {
        Some(d) => base_units_to_decimal(&q.in_amount, d),
        None => q.in_amount.clone(),
    };
    let out_display = match out_decimals {
        Some(d) => base_units_to_decimal(&q.out_amount, d),
        None => q.out_amount.clone(),
    };
    let min_display = match out_decimals {
        Some(d) => base_units_to_decimal(&q.min_out_amount, d),
        None => q.min_out_amount.clone(),
    };

    let mut summary = format!(
        "Submitted a swap of {in_display} {in_label} for about {out_display} {out_label}. Signature: {signature}."
    );
    summary.push_str(&format!(
        " The route guarantees at least {min_display} {out_label} at {} bps slippage tolerance; the exact amount received depends on execution.",
        q.slippage_bps
    ));
    if !q.route_labels.is_empty() {
        summary.push_str(&format!(" Route: {}.", q.route_labels.join(" then ")));
    }
    if let Some(fee) = priority_fee_lamports {
        summary.push_str(&format!(
            " Jupiter attached a priority fee of {fee} lamports ({} SOL).",
            lamports_to_sol(fee)
        ));
    }
    summary.push_str(" Confirm the outcome by looking up the signature.");

    let json_block = json!({
        "signature": signature,
        "input_mint": q.input_mint,
        "output_mint": q.output_mint,
        "in_amount_base_units": q.in_amount,
        "expected_out_base_units": q.out_amount,
        "min_out_base_units": q.min_out_amount,
        "slippage_bps": q.slippage_bps,
        "price_impact_pct": q.price_impact_pct,
        "priority_fee_lamports": priority_fee_lamports,
        "route": q.route_labels,
    });
    format!("{summary}\n\n{json_block}")
}

/// One compressed account and whether its proof was checked.
pub struct VerifiedAccount {
    pub hash: String,
    pub leaf_index: u64,
    pub tree: String,
    pub lamports: u64,
    pub verified: Option<Result<(), String>>,
}

/// Render the tool output for compressed account lookup.
pub fn render_compressed_accounts(
    owner: &str,
    total: usize,
    accounts: &[VerifiedAccount],
) -> String {
    let checked: Vec<&VerifiedAccount> = accounts.iter().filter(|a| a.verified.is_some()).collect();
    let failures: Vec<&VerifiedAccount> = checked
        .iter()
        .copied()
        .filter(|a| matches!(&a.verified, Some(Err(_))))
        .collect();

    let mut summary =
        format!("{owner} owns {total} compressed account(s) according to the indexer.");
    if checked.is_empty() {
        summary.push_str(" No merkle proofs were checked, so these are the indexer's claims rather than verified state.");
    } else if failures.is_empty() {
        summary.push_str(&format!(
            " {} of them had their merkle proof verified: recomputing the root from each account hash and its proof path reproduced the tree root, so those balances are cryptographically backed rather than merely asserted.",
            checked.len()
        ));
    } else {
        summary.push_str(&format!(
            " WARNING: {} of {} checked proofs FAILED to verify, which means the indexer reported state it cannot prove. Treat its answers as untrusted.",
            failures.len(),
            checked.len()
        ));
        for f in &failures {
            if let Some(Err(e)) = &f.verified {
                summary.push_str(&format!("\n  {}: {e}", f.hash));
            }
        }
    }

    for a in accounts.iter().take(10) {
        let mark = match &a.verified {
            None => "unverified",
            Some(Ok(())) => "verified",
            Some(Err(_)) => "PROOF FAILED",
        };
        summary.push_str(&format!(
            "\n  {} leaf {} in tree {} ({} lamports) [{mark}]",
            a.hash, a.leaf_index, a.tree, a.lamports
        ));
    }

    let json_block = json!({
        "owner": owner,
        "total_accounts": total,
        "checked": checked.len(),
        "failed": failures.len(),
        "accounts": accounts.iter().map(|a| json!({
            "hash": a.hash,
            "leaf_index": a.leaf_index,
            "tree": a.tree,
            "lamports": a.lamports,
            "proof_verified": match &a.verified {
                None => Value::Null,
                Some(Ok(())) => Value::Bool(true),
                Some(Err(_)) => Value::Bool(false),
            },
        })).collect::<Vec<_>>(),
    });
    format!("{summary}\n\n{json_block}")
}

/// Render a lamport amount in USD, given a SOL price.
pub fn lamports_to_usd(lamports: u64, sol_usd: f64) -> String {
    let usd = (lamports as f64 / LAMPORTS_PER_SOL as f64) * sol_usd;
    if usd >= 0.01 {
        format!("${usd:.2}")
    } else if usd >= 0.000001 {
        format!("${usd:.6}")
    } else {
        "under $0.000001".to_string()
    }
}

/// Render the tool output for a priority fee estimate.
pub fn render_fee_estimate(e: &FeeEstimate, accounts: &[String], sol_usd: Option<f64>) -> String {
    let total = e.total_lamports();
    let scope = if accounts.is_empty() {
        "recent network-wide samples".to_string()
    } else {
        format!("recent samples for {}", accounts.join(", "))
    };

    let mut summary = if e.nonzero_count == 0 {
        format!(
            "No priority fees are being paid in {scope} ({} samples, all zero), so no bid is needed right now.",
            e.sample_count
        )
    } else {
        let cost = match sol_usd {
            Some(p) => format!(
                "{total} lamports ({} SOL, about {})",
                lamports_to_sol(total),
                lamports_to_usd(total, p)
            ),
            None => format!("{total} lamports ({} SOL)", lamports_to_sol(total)),
        };
        format!(
            "For {} urgency, bid {} micro-lamports per compute unit. Over a {} unit budget that costs {cost} on top of the base fee.",
            e.urgency.label(),
            e.recommended_micro_lamports,
            e.compute_units
        )
    };
    summary.push_str(&format!(
        " Based on {scope}: {} of {} slots paid anything, percentiles {} / {} / {} micro-lamports at p50 / p75 / p95, peak {}.",
        e.nonzero_count, e.sample_count, e.p50, e.p75, e.p95, e.max
    ));
    summary.push_str(
        " A priority fee buys ordering when blocks are full; it is not refunded and does not make a failing transaction succeed.",
    );

    let json_block = json!({
        "urgency": e.urgency.label(),
        "recommended_micro_lamports_per_cu": e.recommended_micro_lamports,
        "compute_units": e.compute_units,
        "total_priority_fee_lamports": total,
        "total_priority_fee_sol": lamports_to_sol(total),
        "total_priority_fee_usd": sol_usd.map(|p| (total as f64 / LAMPORTS_PER_SOL as f64) * p),
        "sol_usd_price": sol_usd,
        "sample_count": e.sample_count,
        "nonzero_sample_count": e.nonzero_count,
        "p50": e.p50,
        "p75": e.p75,
        "p95": e.p95,
        "max": e.max,
        "accounts": accounts,
    });
    format!("{summary}\n\n{json_block}")
}

fn get_asset_decimals(symbol_or_mint: &str) -> u8 {
    let s = symbol_or_mint.trim();
    if s == "SOL" || s == "So11111111111111111111111111111111111111112" || s.starts_with("So111") {
        9
    } else {
        6
    }
}

impl TaxLedger {
    pub fn generate_html_report(
        &self,
        fiscal_year: Option<&str>,
        anchor_sig: Option<&str>,
        date_from: Option<&str>,
        date_to: Option<&str>,
    ) -> Result<String, String> {
        use crate::ledger::parse_date_to_timestamp;

        let state_root = self.compute_state_root()?;
        let fallback_year = fiscal_year.unwrap_or("2026");

        // Resolve optional date-range filters to unix timestamps.
        let from_ts = date_from.and_then(parse_date_to_timestamp);
        let to_ts = date_to.and_then(parse_date_to_timestamp);

        let mut year_month_groups: BTreeMap<String, BTreeMap<String, Vec<crate::lots::TaxLot>>> =
            BTreeMap::new();

        // Seed the year map with disposal years even when every lot has
        // been consumed, so a gains-only wallet still renders its full
        // history instead of silently dropping earlier fiscal years.
        for gain in &self.gain_records {
            if gain.date_ymd.len() >= 7 {
                let year_key = gain.date_ymd[..4].to_string();
                let month_key = gain.date_ymd[..7].to_string();
                year_month_groups
                    .entry(year_key)
                    .or_default()
                    .entry(month_key)
                    .or_default();
            }
        }

        for lot in &self.lots {
            // If date-range filters are set, drop lots outside the window.
            let lot_ts = parse_date_to_timestamp(&lot.acquired_at_utc);
            if let (Some(ts), Some(from)) = (lot_ts, from_ts) {
                if ts < from {
                    continue;
                }
            }
            if let (Some(ts), Some(to)) = (lot_ts, to_ts) {
                if ts > to {
                    continue;
                }
            }

            let year_key = if lot.acquired_at_utc.len() >= 4 {
                lot.acquired_at_utc[..4].to_string()
            } else {
                fallback_year.to_string()
            };

            let month_key = if lot.acquired_at_utc.len() >= 7 {
                lot.acquired_at_utc[..7].to_string()
            } else {
                format!("{}-01", fallback_year)
            };

            year_month_groups
                .entry(year_key)
                .or_default()
                .entry(month_key)
                .or_default()
                .push(lot.clone());
        }

        if year_month_groups.is_empty() {
            year_month_groups
                .entry(fallback_year.to_string())
                .or_default();
        }

        let small_mark_open = r#"<svg width="17" height="17" viewBox="0 0 128 128" style="display:inline-block; vertical-align:middle; opacity:.45;" role="img" aria-label="Open"><defs><clipPath id="s-open"><circle cx="64" cy="64" r="50"/></clipPath></defs><g clip-path="url(#s-open)"><path d="M64 0H128V128H64Z" fill="currentColor"/></g><circle cx="64" cy="64" r="50" fill="none" stroke="currentColor" stroke-width="13"/></svg>"#;
        // The sealed mark is the seal fully closed: a solid disc in the
        // sealing-wax red, with no split and no ruling. Open periods show
        // the split mark; a closed period shows that the two halves have
        // come together.
        let small_mark_sealed = r#"<svg width="17" height="17" viewBox="0 0 128 128" style="display:inline-block; vertical-align:middle; color:var(--wax-badge);" role="img" aria-label="Sealed"><circle cx="64" cy="64" r="52" fill="currentColor"/></svg>"#;

        let mut cumulative_ledger_cost = 0.0;
        let mut cumulative_ledger_receipts = 0;
        let mut fiscal_years_html = String::new();

        let mut sorted_years: Vec<String> = year_month_groups.keys().cloned().collect();
        sorted_years.sort();

        // Oldest year first (top), most recent year last (bottom), so the
        // sealed closed years read top-down and the open current period sits
        // at the end of the stack.
        let current_calendar_year = sorted_years.last().cloned().unwrap_or_else(|| fallback_year.to_string());

        for target_yr in &sorted_years {
            let months_in_year = year_month_groups.get(target_yr).unwrap();

            let mut year_cost_brl = 0.0;
            let mut year_receipt_count = 0;
            let mut monthly_rows_html = String::new();

            for month_str in (1..=12).rev() {
                let month_code = format!("{:02}", month_str);
                let period_key = format!("{}-{month_code}", target_yr);
                let lots_in_month = months_in_year.get(&period_key);

                let receipt_count = match lots_in_month {
                    Some(lots) => lots.len(),
                    None => 0,
                };

                let mut month_cost_brl = 0.0;
                let mut month_ptax_sum = 0.0;
                let mut ptax_count = 0;

                if let Some(lots) = lots_in_month {
                    for lot in lots {
                        let asset_decimals = get_asset_decimals(&lot.asset_symbol);
                        let ui_amount = lot.amount as f64 / 10f64.powi(asset_decimals as i32);
                        let cost_brl = ui_amount * lot.unit_cost_basis_brl;
                        month_cost_brl += cost_brl;

                        if lot.ptax_rate_used > 0.0 {
                            month_ptax_sum += lot.ptax_rate_used;
                            ptax_count += 1;
                        }
                    }
                }

                year_cost_brl += month_cost_brl;
                year_receipt_count += receipt_count;

                let avg_ptax = if ptax_count > 0 {
                    month_ptax_sum / (ptax_count as f64)
                } else {
                    5.0000
                };

                let sample_date = format!("{}-28 UTC", period_key);
                let has_records = receipt_count > 0;
                let row_class = if has_records {
                    ""
                } else {
                    "style=\"opacity: 0.4;\""
                };
                let accordion_onclick = if has_records {
                    format!("onclick=\"toggleAccordion('month-{}')\"", period_key)
                } else {
                    "".to_string()
                };
                let cursor_style = if has_records {
                    "cursor: pointer;"
                } else {
                    "cursor: default;"
                };
                let chevron_icon = if has_records { "&#9662;" } else { "" };

                monthly_rows_html.push_str(&format!(
                    r#"
                    <div class="accordion-item" id="month-{period_key}" {row_class}>
                        <div class="accordion-header" {accordion_onclick} style="{cursor_style}">
                            <div>
                                <div class="k">Month &middot; {period_key}</div>
                                <div class="v" style="margin:2px 0 0;">{receipt_count} receipts &middot; R$ {month_cost_brl:.2}</div>
                            </div>
                            <div style="display:flex; align-items:center; gap:16px;">
                                <div class="open">
                                    {small_mark_open}
                                    Open &middot; pending close
                                </div>
                                <span class="chevron">{chevron_icon}</span>
                            </div>
                        </div>
                    "#,
                    period_key = period_key,
                    row_class = row_class,
                    accordion_onclick = accordion_onclick,
                    cursor_style = cursor_style,
                    receipt_count = receipt_count,
                    month_cost_brl = month_cost_brl,
                    small_mark_open = small_mark_open,
                    chevron_icon = chevron_icon
                ));

                if has_records {
                    monthly_rows_html.push_str(&format!(
                        r#"
                        <div class="accordion-content">
                            <table>
                                <thead>
                                    <tr><th>PERIOD CODE</th><th>ASSET CLASS</th><th>TOTAL VOLUME</th><th>CUMULATIVE COST BASIS (BRL)</th><th>RATE USED (BRL/UNIT)</th><th>INTERVAL UTC</th></tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td>Month Closing &middot; {period_key}</td>
                                        <td>Aggregated Monthly Period</td>
                                        <td>{receipt_count} receipts</td>
                                        <td>R$ {month_cost_brl:.2}</td>
                                        <td>R$ {avg_ptax:.4} (Avg)</td>
                                        <td>{sample_date}</td>                                    </tr>
                                </tbody>
                            </table>
                        </div>
                        </div>
                        "#,
                        period_key = period_key,
                        receipt_count = receipt_count,
                        month_cost_brl = month_cost_brl,
                        avg_ptax = avg_ptax,
                        sample_date = sample_date
                    ));
                } else {
                    monthly_rows_html.push_str(
                        r#"
                        <div class="accordion-content">
                            <table>
                                <thead>
                                    <tr><th>PERIOD CODE</th><th>ASSET CLASS</th><th>TOTAL VOLUME</th><th>CUMULATIVE COST BASIS (BRL)</th><th>RATE USED (BRL/UNIT)</th><th>INTERVAL UTC</th></tr>
                                </thead>
                                <tbody>
                                    <tr><td colspan="6" style="text-align: center; color: var(--selo-muted);">No transactions recorded for this month.</td></tr>
                                </tbody>
                            </table>
                        </div>
                        </div>
                        "#,
                    );
                }
            }

            cumulative_ledger_cost += year_cost_brl;
            cumulative_ledger_receipts += year_receipt_count;

            let is_year_anchored =
                target_yr.as_str() < current_calendar_year.as_str() || anchor_sig.is_some();
            let year_status_html = if is_year_anchored {
                format!(
                    r#"<div class="sealed">{small_mark_sealed} Sealed &middot; root {}&hellip;</div>"#,
                    state_root.chars().take(12).collect::<String>()
                )
            } else {
                format!(r#"<div class="open">{small_mark_open} Open &middot; pending close</div>"#)
            };

            let year_verify_html = if is_year_anchored {
                format!(
                    r#"<button class="copy-btn" onclick="verifyPoseidon(this)">Verify in Browser</button>
                                    <span class="verify-badge compact">Unverified</span>"#
                )
            } else {
                format!(
                    r#"<span style="font:italic 12px/1.4 var(--selo-font-mono);color:var(--selo-muted);">Open period &mdash; no verification</span>"#
                )
            };

            // ---- per-year capital gains ----
            let months_table: [&str; 12] = [
                "January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December",
            ];
            let year_records: Vec<&GainRecord> = self
                .gain_records
                .iter()
                .filter(|g| g.date_ymd.starts_with(target_yr.as_str()))
                .collect();
            let year_net_total: f64 = year_records.iter().map(|g| g.gain_brl).sum();
            let year_net_total_usd: f64 = year_records.iter().map(|g| g.gain_usd).sum();
            let year_tax_brl: f64 = if year_net_total > 0.0 {
                year_net_total * 0.15
            } else {
                0.0
            };
            let year_tax_usd: f64 = if year_net_total_usd > 0.0 {
                year_net_total_usd * 0.15
            } else {
                0.0
            };
            let year_gains_html = {
                if year_records.is_empty() {
                    String::new()
                } else {
                    let mut by_month: BTreeMap<String, Vec<&&GainRecord>> = BTreeMap::new();
                    for g in &year_records {
                        let mk = &g.date_ymd[..7];
                        by_month.entry(mk.to_string()).or_default().push(g);
                    }
                    let mut month_blocks = String::new();
                    for (mk, recs) in by_month.iter().rev() {
                        let month_net: f64 = recs.iter().map(|g| g.gain_brl).sum();
                        let month_net_usd: f64 = recs.iter().map(|g| g.gain_usd).sum();
                        let m_sign = if month_net >= 0.0 { "+" } else { "" };
                        let m_usd_sign = if month_net_usd >= 0.0 { "+" } else { "" };
                        let m_class = if month_net >= 0.0 {
                            "gain-positive"
                        } else {
                            "gain-negative"
                        };
                        let month_idx: usize =
                            mk[5..7].parse::<usize>().unwrap_or(1).saturating_sub(1);
                        let month_name = format!("{} {}", months_table[month_idx], &mk[..4]);

                        let mut row_html = String::new();
                        for g in recs {
                            let decimals = get_asset_decimals(&g.asset_symbol);
                            let ui_amt =
                                g.amount_base_units as f64 / 10f64.powi(decimals as i32);
                            let swap_label =
                                if g.is_swap { "Swap" } else { "Transfer" };
                            let gain_class = if g.gain_brl >= 0.0 {
                                "gain-positive"
                            } else {
                                "gain-negative"
                            };
                            row_html.push_str(&format!(
                                r#"<tr class="{gain_class}">
                                    <td style="white-space:nowrap;">{date}</td>
                                    <td>{ui_amt:.6} {symbol}</td>
                                    <td>{swap_label}</td>
                                    <td>R$ {cost:.2}<br><span class="usd">${cost_usd:.2}</span></td>
                                    <td>R$ {proceeds:.2}<br><span class="usd">${proceeds_usd:.2}</span></td>
                                    <td>R$ {gain:+.2}<br><span class="usd">${gain_usd:+.2}</span></td>
                                </tr>"#,
                                gain_class = gain_class,
                                date = g.date_ymd,
                                ui_amt = ui_amt,
                                symbol = g.asset_symbol,
                                swap_label = swap_label,
                                cost = g.cost_basis_brl,
                                cost_usd = g.cost_basis_usd,
                                proceeds = g.proceeds_brl,
                                proceeds_usd = g.proceeds_usd,
                                gain = g.gain_brl,
                                gain_usd = g.gain_usd,
                            ));
                        }

                        month_blocks.push_str(&format!(
                            r#"<div style="margin-top:10px;">
                                <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:4px; padding-bottom:4px; border-bottom:1px solid var(--selo-rule);">
                                    <span style="font:600 12px/1.4 var(--selo-font-mono);color:var(--selo-ink);">{month_name}</span>
                                    <span class="{m_class}" style="font:600 12px/1.4 var(--selo-font-mono);">Net {m_sign}R$ {m_net:.2}<span style="font-weight:400;color:var(--selo-muted);margin-left:4px;">{m_usd_sign}${m_usd:.2}</span></span>
                                </div>
                                <table style="margin-bottom:4px;">
                                    <thead><tr><th>Date</th><th>Amount</th><th>Type</th><th>Cost Basis</th><th>Proceeds</th><th>Gain/Loss</th></tr></thead>
                                    <tbody>{row_html}</tbody>
                                </table>
                            </div>"#,
                            month_name = month_name,
                            m_class = m_class,
                            m_sign = m_sign,
                            m_net = month_net,
                            m_usd_sign = m_usd_sign,
                            m_usd = month_net_usd,
                            row_html = row_html,
                        ));
                    }

                    let year_net: f64 = year_records.iter().map(|g| g.gain_brl).sum();
                    let year_net_usd: f64 = year_records.iter().map(|g| g.gain_usd).sum();
                    let net_sign = if year_net >= 0.0 { "+" } else { "" };
                    let net_usd_sign = if year_net_usd >= 0.0 { "+" } else { "" };
                    let tax_brl = if year_net > 0.0 { year_net * 0.15 } else { 0.0 };
                    let tax_usd = if year_net_usd > 0.0 { year_net_usd * 0.15 } else { 0.0 };
                    let tax_note = if year_net > 0.0 {
                        r#"<p style="margin:4px 0 0;font-size:11px;color:var(--selo-muted);">Estimated at 15% (IN RFB 1888/2019). Sales below R$&nbsp;35,000/month are exempt.</p>"#
                    } else {
                        ""
                    };

                    format!(
                        r#"<div style="margin-bottom:16px; padding:12px 14px; background:var(--selo-raised); border:1px solid var(--selo-rule); border-radius:8px;">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                                <div class="k">Capital Gains &amp; Losses &middot; {count} disposal(s)</div>
                                <div style="display:flex; align-items:center; gap:14px;">
                                    <span style="font:600 14px/1.3 var(--selo-font-mono);">Net {net_sign}R$ {net:.2}</span>
                                    <span style="font:600 12px/1.3 var(--selo-font-mono);color:var(--selo-muted);">{net_usd_sign}${net_usd:.2}</span>
                                    <span style="padding:2px 10px;background:var(--wax-badge);border-radius:4px;font:600 14px/1.3 var(--selo-font-mono);color:#fff;">Tax Due R$ {tax:.2}<span style="font-weight:400;margin-left:4px;">${tax_usd:.2}</span></span>
                                </div>
                            </div>
                            {tax_note}
                            {month_blocks}
                        </div>"#,
                        count = year_records.len(),
                        net_sign = net_sign,
                        net = year_net,
                        net_usd_sign = net_usd_sign,
                        net_usd = year_net_usd,
                        tax = tax_brl,
                        tax_usd = tax_usd,
                        tax_note = tax_note,
                        month_blocks = month_blocks,
                    )
                }
            };

            // All accordions start closed; the current year is still flagged
            // as the open period via the status badge but stays collapsed.
            let year_expanded_class = "";
            let year_content_display = "none";

            let year_tax_badge = if year_records.is_empty() {
                String::new()
            } else if year_tax_brl > 0.0 {
                format!(
                    r#"<span style="padding:2px 10px;border:1px solid var(--wax-badge);border-radius:6px;font:600 12px/1.3 var(--selo-font-mono);color:var(--wax-badge);white-space:nowrap;">Tax Due R$ {:.2}<span style="font-weight:400;margin-left:4px;">${:.2}</span></span>"#,
                    year_tax_brl, year_tax_usd
                )
            } else {
                format!(
                    r#"<span style="padding:2px 10px;border:1px solid var(--selo-rule);border-radius:6px;font:600 12px/1.3 var(--selo-font-mono);color:var(--selo-muted);white-space:nowrap;">No tax due</span>"#,
                )
            };

            fiscal_years_html.push_str(&format!(
                r#"
                <div class="accordion-item" id="year-{target_yr}" style="border-color: var(--selo-ink); margin-bottom: 20px;">
                    <div class="accordion-header {year_expanded_class}" onclick="toggleAccordion('year-{target_yr}')">
                        <div>
                            <div class="k">Fiscal Year &middot; {target_yr}</div>
                            <div class="v" style="margin:2px 0 0;">{year_receipt_count} receipts &middot; R$ {year_cost_brl:.2}</div>
                        </div>
                        <div style="display:flex; align-items:center; gap:16px;">
                            {year_tax_badge}
                            {year_status_html}
                            <span class="chevron">&#9662;</span>
                        </div>
                    </div>
                    <div class="accordion-content" style="display: {year_content_display}; padding: 16px;">
                        <div style="margin-bottom: 16px;">
                            <div class="k" style="margin-bottom:6px;">Cryptographic State Root (Poseidon BN254 Commitment)</div>
                            <div class="root-row" style="display:flex; justify-content:space-between; align-items:center; background:var(--selo-raised); padding:10px 14px; border-radius:8px; border:1px solid var(--selo-rule);">
                                <span class="root-hash" style="font: 600 12px/1.4 var(--selo-font-mono); word-break:break-all;">{state_root}</span>
                                <div class="root-buttons" style="display:flex; align-items:center; gap:8px; flex-shrink:0;">
                                    <button class="copy-btn" onclick="copyToClipboard('{state_root}', this)">Copy Root</button>
                                    {year_verify_html}
                                </div>
                            </div>
                        </div>
                        {year_gains_html}
                        <div style="display:flex; flex-direction:column; gap:12px;">
                            {monthly_rows_html}
                        </div>
                    </div>
                </div>
                "#,
                target_yr = target_yr,
                year_receipt_count = year_receipt_count,
                year_cost_brl = year_cost_brl,
                year_status_html = year_status_html,
                year_tax_badge = year_tax_badge,
                year_expanded_class = year_expanded_class,
                year_content_display = year_content_display,
                state_root = state_root,
                year_verify_html = year_verify_html,
                monthly_rows_html = monthly_rows_html
            ));
        }

        // Build a JSON array of all lots for browser-side integrity verification.
        // The JSON is canonical (sorted by id) so the hash is deterministic.
        let mut lots_for_verification: Vec<Value> = self
            .lots
            .iter()
            .map(|lot| {
                json!({
                    "id": lot.id,
                    "asset": lot.asset_symbol,
                    "amount": lot.amount,
                    "cost_basis_brl": lot.unit_cost_basis_brl,
                    "ptax_rate": lot.ptax_rate_used,
                    "acquired": lot.acquired_at_utc,
                })
            })
            .collect();
        lots_for_verification.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let lots_json =
            serde_json::to_string(&lots_for_verification).unwrap_or_else(|_| "[]".to_string());
        let integrity_hash = hex::encode(Sha256::digest(lots_json.as_bytes()));

        // Poseidon fold inputs in self.lots order, exactly the order
        // compute_state_root folds them. The SHA-256 payload above is
        // id-sorted and must NOT be reused here: the fold is order-sensitive.
        let poseidon_lots: Vec<Value> = self
            .lots
            .iter()
            .map(|lot| {
                let ptax_scaled: u64 = (lot.ptax_rate_used * 10_000.0) as u64;
                json!({
                    "amount": lot.amount,
                    "ptax_rate_used": lot.ptax_rate_used,
                    "ptax_scaled": ptax_scaled,
                })
            })
            .collect();
        let poseidon_verify_json = serde_json::to_string(&json!({
            "state_root": state_root,
            "lots": poseidon_lots,
        }))
        .unwrap_or_else(|_| "{\"state_root\":\"0x0\",\"lots\":[]}".to_string())
        // A lot string containing "</script>" would break out of the JSON
        // script tag; escaping "<" as \u003c keeps the payload inert.
        .replace('<', "\\u003c");

        let title_suffix = fiscal_year.map(|y| format!(" · Fiscal Year {}", y)).unwrap_or_default();

        let no_records_note = if cumulative_ledger_receipts == 0 {
            r#"<div class="card" style="text-align:center; padding:48px 24px;">
            <div style="font-size:15px; color:var(--selo-muted);">No tax lots have been recorded for this wallet.</div>
            <div style="font-size:13px; color:var(--selo-muted); margin-top:6px;">Run <code style="background:var(--selo-rule); padding:2px 6px; border-radius:4px;">selo-tool ingest &lt;pubkey&gt; --all</code> to backfill history, then export again.</div>
            </div>"#
        } else {
            ""
        };

        // Capital gains are now rendered per fiscal year, inside each year accordion.

        let html_output = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20viewBox%3D%220%200%20128%20128%22%20width%3D%2232%22%20height%3D%2232%22%3E%3Cdefs%3E%3CclipPath%20id%3D%22fav%22%3E%3Ccircle%20cx%3D%2264%22%20cy%3D%2264%22%20r%3D%2250%22%2F%3E%3C%2FclipPath%3E%3C%2Fdefs%3E%3Cg%20clip-path%3D%22url%28%23fav%29%22%3E%3Cpath%20fill%3D%22%2316130F%22%20d%3D%22M64%200H128V128H64Z%22%2F%3E%3C%2Fg%3E%3Ccircle%20cx%3D%2264%22%20cy%3D%2264%22%20r%3D%2250%22%20fill%3D%22none%22%20stroke%3D%22%2316130F%22%20stroke-width%3D%2213%22%2F%3E%3C%2Fsvg%3E">
<title>Selo · Cryptographic Audit Statement{title_suffix}</title>
<style>
  :root {{
    --selo-seal: #16130F;
    --selo-ink: #16130F;
    --selo-paper: #FAF7F2;
    --selo-muted: #6B625A;
    --selo-rule: #DED5C9;
    --selo-raised: #FFFFFF;
    --wax: #B4381F;
    --wax-badge: #B4381F;
    --green: #1A7D3A;
    --selo-font-sans: ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
    --selo-font-mono: ui-monospace, "JetBrains Mono", Consolas, monospace;
  }}
  html[data-theme="dark"] {{
    --selo-ink: #F2EDE5;
    --selo-paper: #14120F;
    --selo-muted: #9A8F83;
    --selo-rule: #2E2A25;
    --selo-raised: #1D1A16;
    --wax: #F2EDE5;
    --wax-badge: #B4381F;
    --green: #3FB950;
  }}
  * {{ box-sizing: border-box; scroll-behavior: smooth; }}
  body {{
    margin: 0; padding: 40px 20px 100px;
    background: var(--selo-paper); color: var(--selo-ink);
    font: 15px/1.6 var(--selo-font-sans);
    display: flex; justify-content: center;
  }}
  .wrapper {{ width: 100%; max-width: 900px; }}
  .header-area {{ display: flex; align-items: center; gap: 14px; margin-bottom: 24px; }}
  .logo-box {{ width: 42px; height: 42px; background: var(--selo-rule); border-radius: 10px; padding: 8px; display: flex; align-items: center; justify-content: center; }}
  .logo-box svg {{ width: 100%; height: 100%; fill: var(--selo-ink); }}
  h1 {{ font-size: 28px; letter-spacing: -.03em; margin: 0; }}
  .theme-toggle {{
    margin-left: auto;
    background: var(--selo-raised);
    border: 1px solid var(--selo-rule);
    border-radius: 8px;
    padding: 6px 12px;
    font: 600 11px/1 var(--selo-font-sans);
    color: var(--selo-ink);
    cursor: pointer;
    letter-spacing: .04em;
    transition: background 0.2s;
  }}
  .theme-toggle:hover {{ background: var(--selo-rule); }}
  p.lede {{ font-size: 15px; color: var(--selo-muted); margin: 0 0 32px; max-width: 65ch; }}

  .card {{
    border: 1px solid var(--selo-rule);
    border-radius: 12px;
    padding: 24px;
    background: var(--selo-raised);
    margin-bottom: 24px;
  }}
  .k {{ color: var(--selo-muted); font-size: 11px; letter-spacing: .06em; text-transform: uppercase; }}
  .v {{ font: 600 22px/1.3 var(--selo-font-mono); margin: 6px 0 0; }}

  .copy-btn {{
    background: var(--selo-rule);
    border: none;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 11px;
    font-weight: 600;
    color: var(--selo-ink);
    cursor: pointer;
    transition: background 0.2s;
  }}
  .copy-btn:hover {{ background: var(--selo-ink); color: var(--selo-paper); }}

  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--selo-rule); font-family: var(--selo-font-mono); }}
  th {{ font-size: 10px; text-transform: uppercase; letter-spacing: .06em; color: var(--selo-muted); font-family: var(--selo-font-sans); }}

  .accordion-item {{ border: 1px solid var(--selo-rule); border-radius: 10px; background: var(--selo-raised); overflow: hidden; margin-bottom: 12px; }}
  .accordion-header {{ padding: 16px 20px; display: flex; justify-content: space-between; align-items: center; cursor: pointer; user-select: none; }}
  .accordion-content {{ padding: 0 20px 20px; border-top: 1px solid var(--selo-rule); background: var(--selo-paper); display: none; }}
  .accordion-header.expanded .chevron {{ transform: rotate(180deg); }}
  .chevron {{ transition: transform 0.2s; font-size: 12px; color: var(--selo-muted); }}
  .sealed {{ display: flex; align-items: center; gap: 8px; color: var(--wax); font-size: 13px; font-weight: 600; }}
  .open {{ display: flex; align-items: center; gap: 8px; color: var(--selo-muted); font-size: 13px; }}

  .verify-badge {{
    display: inline-flex; align-items: center; gap: 8px;
    padding: 8px 16px; border-radius: 8px;
    font: 600 13px var(--selo-font-mono);
    margin-bottom: 16px;
  }}
  .verify-badge.verified {{
    background: var(--green); color: #fff;
  }}
  .verify-badge.tampered {{
    background: var(--wax); color: #fff;
  }}
  .verify-badge.checking {{
    background: var(--selo-rule); color: var(--selo-muted);
  }}
  .verify-badge.compact {{
    display: inline-flex; align-items: center; gap: 6px;
    padding: 6px 10px; margin-bottom: 0;
    font: 600 11px var(--selo-font-mono);
    border: 1px solid var(--selo-rule); border-radius: 6px;
    color: var(--selo-muted); background: var(--selo-paper);
    white-space: nowrap;
  }}
  .verify-badge.compact.verified {{
    background: var(--green); border-color: var(--green); color: #fff;
  }}
  .verify-badge.compact.tampered {{
    background: var(--wax); border-color: var(--wax); color: #fff;
  }}

  .gain-positive {{ color: var(--green); font-weight: 600; }}
  .gain-negative {{ color: var(--wax); font-weight: 600; }}
  .usd {{ font-size: 11px; color: var(--selo-muted); font-weight: 400; }}

  @media (max-width: 600px) {{
    body {{ padding: 24px 12px 80px; }}
    .header-area {{ flex-wrap: wrap; }}
    h1 {{ font-size: 22px; }}
    .accordion-header {{ flex-direction: column; align-items: flex-start; gap: 10px; }}
    .accordion-content {{ padding: 0 12px 16px; }}
    .root-row {{
      flex-direction: column !important;
      align-items: stretch !important;
      gap: 10px;
    }}
    .root-buttons {{ width: 100%; flex-wrap: wrap; }}
    th, td {{ padding: 8px 6px; font-size: 11px; }}
  }}

  footer {{ margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--selo-rule); color: var(--selo-muted); font-size: 12px; }}
</style>
</head>
<body>
<div class="wrapper">
  <div class="header-area">
    <div class="logo-box">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><defs><clipPath id="hb"><circle cx="64" cy="64" r="52"/></clipPath></defs><g clip-path="url(#hb)"><path d="M64 0H128V128H64Z"/><g stroke="currentColor" stroke-width="7"><line x1="0" y1="37" x2="55" y2="37"/><line x1="0" y1="55" x2="55" y2="55"/><line x1="0" y1="73" x2="55" y2="73"/><line x1="0" y1="91" x2="55" y2="91"/></g></g><circle cx="64" cy="64" r="52" fill="none" stroke="currentColor" stroke-width="9"/></svg>
    </div>
    <h1>Selo Tax Ledger Report</h1>
    <button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()">&#9681; Theme</button>
  </div>

  <div id="verify-badge" class="verify-badge checking">
    <span id="verify-icon">&#9679;</span>
    <span id="verify-text">Verifying integrity...</span>
  </div>

  <p class="lede">Self-verifying cryptographic audit statement. The integrity badge above recomputes a SHA-256 hash over the embedded lot data and compares it against the hash recorded at export time. The Poseidon BN254 state root is shown so it can be checked against an on-chain anchor, and the Verify in Browser button recomputes it from the embedded lot data.</p>

  <div class="card">
    <div class="k">Ledger Cumulative Summary</div>
    <div class="v">{cumulative_ledger_receipts} Total Receipts &middot; R$ {cumulative_ledger_cost:.2}</div>
    <p style="margin:8px 0 0; font-size:13px; color:var(--selo-muted);">Aggregated across {sorted_years_len} fiscal year period(s). Expand any fiscal year below to inspect itemized monthly closes and cryptographic state roots.</p>
  </div>

  <div style="display:flex; flex-direction:column; gap:16px;">
    {fiscal_years_html}
  </div>
  {no_records_note}

  <footer>
    <p>Generated by Selo Core &middot; Integrity hash: {integrity_hash} &middot; Poseidon state root: {state_root}</p>
  </footer>
</div>

<script type="application/json" id="selo-verification-data">
{lots_json}
</script>
<script type="application/json" id="selo-verify-data">
{poseidon_verify_json}
</script>
<script>
  (function() {{
    var badge = document.getElementById('verify-badge');
    var icon = document.getElementById('verify-icon');
    var text = document.getElementById('verify-text');

    function toggleTheme() {{
      var html = document.documentElement;
      var next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-theme', next);
      try {{ localStorage.setItem('selo-theme', next); }} catch (e) {{}}
    }}
    window.toggleTheme = toggleTheme;
    (function initTheme() {{
      var saved = null;
      try {{ saved = localStorage.getItem('selo-theme'); }} catch (e) {{}}
      if (saved === 'dark' || saved === 'light') {{
        document.documentElement.setAttribute('data-theme', saved);
      }} else {{
        document.documentElement.setAttribute('data-theme', 'light');
      }}
    }})();

    var dataEl = document.getElementById('selo-verification-data');
    if (!dataEl) {{
      badge.className = 'verify-badge tampered';
      icon.innerHTML = '&#9679;';
      text.textContent = 'No verification data found';
      return;
    }}

    var lotsJson = dataEl.textContent.trim();
    var claimedHash = '{integrity_hash}';

    function toggleAccordion(id) {{
      var item = document.getElementById(id);
      if (!item) return;
      var content = item.querySelector('.accordion-content');
      var header = item.querySelector('.accordion-header');
      if (content.style.display === 'none' || content.style.display === '') {{
        content.style.display = 'block';
        header.classList.add('expanded');
      }} else {{
        content.style.display = 'none';
        header.classList.remove('expanded');
      }}
    }}

    function copyToClipboard(text, btn) {{
      function done() {{
        var orig = btn.textContent;
        btn.textContent = 'Copied ✓';
        setTimeout(function() {{ btn.textContent = orig; }}, 2000);
      }}
      function fallback() {{
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        try {{ document.execCommand('copy'); done(); }} catch (e) {{ btn.textContent = 'Copy failed'; }}
        document.body.removeChild(ta);
      }}
      if (navigator.clipboard && navigator.clipboard.writeText) {{
        navigator.clipboard.writeText(text).then(done).catch(fallback);
      }} else {{
        fallback();
      }}
    }}

    // Compute SHA-256 over the embedded lot data and compare.
    if (window.crypto && window.crypto.subtle) {{
      var encoder = new TextEncoder();
      var data = encoder.encode(lotsJson);
      window.crypto.subtle.digest('SHA-256', data).then(function(hash) {{
        var computed = Array.from(new Uint8Array(hash))
          .map(function(b) {{ return b.toString(16).padStart(2, '0'); }})
          .join('');
        if (computed === claimedHash) {{
          badge.className = 'verify-badge verified';
          icon.innerHTML = '&#10003;';
          text.textContent = 'VERIFIED · Integrity hash matches the embedded lot data';
        }} else {{
          badge.className = 'verify-badge tampered';
          icon.innerHTML = '&#10007;';
          text.textContent = 'TAMPERED · Computed ' + computed.slice(0,16) + '... vs claimed ' + claimedHash.slice(0,16) + '...';
        }}
      }}).catch(function() {{
        badge.className = 'verify-badge tampered';
        icon.innerHTML = '&#9679;';
        text.textContent = 'Verification failed · crypto API error';
      }});
    }} else {{
      badge.className = 'verify-badge checking';
      icon.innerHTML = '&#9679;';
      text.textContent = 'Verification skipped · crypto API not available';
    }}
    window.toggleAccordion = toggleAccordion;
    window.copyToClipboard = copyToClipboard;
  }})();
</script>
<script>

  // ---- Poseidon BN254 width-4 (t=4) permutation, circom-compatible ----
  //      Matches the Rust light-poseidon 0.4.0 parameters used by
  //      compute_state_root: 8 full rounds, 56 partial rounds, x^5 S-box.
  const BN254_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const C = [

  11633431549750490989983886834189948010834808234699737327785600195936805266405n,
  17353750182810071758476407404624088842693631054828301270920107619055744005334n,
  11575173631114898451293296430061690731976535592475236587664058405912382527658n,
  9724643380371653925020965751082872123058642683375812487991079305063678725624n,
  20936725237749945635418633443468987188819556232926135747685274666391889856770n,
  6427758822462294912934022562310355233516927282963039741999349770315205779230n,
  16782979953202249973699352594809882974187694538612412531558950864304931387798n,
  8979171037234948998646722737761679613767384188475887657669871981433930833742n,
  5428827536651017352121626533783677797977876323745420084354839999137145767736n,
  507241738797493565802569310165979445570507129759637903167193063764556368390n,
  6711578168107599474498163409443059675558516582274824463959700553865920673097n,
  2197359304646916921018958991647650011119043556688567376178243393652789311643n,
  4634703622846121403803831560584049007806112989824652272428991253572845447400n,
  17008376818199175111793852447685303011746023680921106348278379453039148937791n,
  18430784755956196942937899353653692286521408688385681805132578732731487278753n,
  4573768376486344895797915946239137669624900197544620153250805961657870918727n,
  5624865188680173294191042415227598609140934495743721047183803859030618890703n,
  8228252753786907198149068514193371173033070694924002912950645971088002709521n,
  17586714789554691446538331362711502394998837215506284064347036653995353304693n,
  12985198716830497423350597750558817467658937953000235442251074063454897365701n,
  13480076116139680784838493959937969792577589073830107110893279354229821035984n,
  480609231761423388761863647137314056373740727639536352979673303078459561332n,
  19503345496799249258956440299354839375920540225688429628121751361906635419276n,
  16837818502122887883669221005435922946567532037624537243846974433811447595173n,
  5492108497278641078569490709794391352213168666744080628008171695469579703581n,
  11365311159988448419785032079155356000691294261495515880484003277443744617083n,
  13876891705632851072613751905778242936713392247975808888614530203269491723653n,
  10660388389107698747692475159023710744797290186015856503629656779989214850043n,
  18876318870401623474401728758498150977988613254023317877612912724282285739292n,
  15543349138237018307536452195922365893694804703361435879256942490123776892424n,
  2839988449157209999638903652853828318645773519300826410959678570041742458201n,
  7566039810305694135184226097163626060317478635973510706368412858136696413063n,
  6344830340705033582410486810600848473125256338903726340728639711688240744220n,
  12475357769019880256619207099578191648078162511547701737481203260317463892731n,
  13337401254840718303633782478677852514218549070508887338718446132574012311307n,
  21161869193849404954234950798647336336709035097706159414187214758702055364571n,
  20671052961616073313397254362345395594858011165315285344464242404604146448678n,
  2772189387845778213446441819361180378678387127454165972767013098872140927416n,
  3339032002224218054945450150550795352855387702520990006196627537441898997147n,
  14919705931281848425960108279746818433850049439186607267862213649460469542157n,
  17056699976793486403099510941807022658662936611123286147276760381688934087770n,
  16144580075268719403964467603213740327573316872987042261854346306108421013323n,
  15582343953927413680541644067712456296539774919658221087452235772880573393376n,
  17528510080741946423534916423363640132610906812668323263058626230135522155749n,
  3190600034239022251529646836642735752388641846393941612827022280601486805721n,
  8463814172152682468446984305780323150741498069701538916468821815030498611418n,
  16533435971270903741871235576178437313873873358463959658178441562520661055273n,
  11845696835505436397913764735273748291716405946246049903478361223369666046634n,
  18391057370973634202531308463652130631065370546571735004701144829951670507215n,
  262537877325812689820791215463881982531707709719292538608229687240243203710n,
  2187234489894387585309965540987639130975753519805550941279098789852422770021n,
  19189656350920455659006418422409390013967064310525314160026356916172976152967n,
  15839474183930359560478122372067744245080413846070743460407578046890458719219n,
  1805019124769763805045852541831585930225376844141668951787801647576910524592n,
  323592203814803486950280155834638828455175703393817797003361354810251742052n,
  9780393509796825017346015868945480913627956475147371732521398519483580624282n,
  14009429785059642386335012561867511048847749030947687313594053997432177705759n,
  13749550162460745037234826077137388777330401847577727796245150843898019635981n,
  19497187499283431845443758879472819384797584633472792651343926414232528405311n,
  3708428802547661961864524194762556064568867603968214870300574294082023305587n,
  1339414413482882567499652761996854155383863472782829777976929310155400981782n,
  6396261245879814100794661157306877072718690153118140891315137894471052482309n,
  2069661495404347929962833138824526893650803079024564477269192079629046031674n,
  15793521554502133342917616035884588152451122589545915605459159078589855944361n,
  17053424498357819626596285492499512504457128907932827007302385782133229252374n,
  13658536470391360399708067455536748955260723760813498481671323619545320978896n,
  21546095668130239633971575351786704948662094117932406102037724221634677838565n,
  21411726238386979516934941789127061362496195649331822900487557574597304399109n,
  1944776378988765673004063363506638781964264107780425928778257145151172817981n,
  15590719714223718537172639598316570285163081746016049278954513732528516468773n,
  1351266421179051765004709939353170430290500926943038391678843253157009556309n,
  6772476224477167317130064764757502335545080109882028900432703947986275397548n,
  10670120969725161535937685539136065944959698664551200616467222887025111751992n,
  4731853626374224678749618809759140702342195350742653173378450474772131006181n,
  14473527495914528513885847341981310373531349450901830749157165104135412062812n,
  16937191362061486658876740597821783333355021670608822932942683228741190786143n,
  5656559696428674390125424316117443507583679061659043998559560535270557939546n,
  8897648276515725841133578021896617755369443750194849587616503841335248902806n,
  14938684446722672719637788054570691068799510611164812175626676768545923371470n,
  15284149043690546115252102390417391226617211133644099356880071475803043461465n,
  2623479025068612775740107497276979457946709347831661908218182874823658838107n,
  6809791961761836061129379546794905411734858375517368211894790874813684813988n,
  2417620338751920563196799065781703780495622795713803712576790485412779971775n,
  4445143310792944321746901285176579692343442786777464604312772017806735512661n,
  1429019233589939118995503267516676481141938536269008901607126781291273208629n,
  19874283200702583165110559932895904979843482162236139561356679724680604144459n,
  13426632171723830006915194799390005513190035492503509233177687891041405113055n,
  10582332261829184460912611488470654685922576576939233092337240630493625631748n,
  21233753931561918964692715735079738969202507286592442257083521969358109931739n,
  15570526832729960536088203016939646235070527502823725736220985057263010426410n,
  9379993197409194016084018867205217180276068758980710078281820842068357746159n,
  20771047769547788232530761122022227554484215799917531852224053856574439035591n,
  20468066117407230615347036860121267564735050776924839007390915936603720868039n,
  5488458379783632930817704196671117722181776789793038046303454621235628350505n,
  1394272944960494549436156060041871735938329188644910029274839018389507786995n,
  5147716541319265558364686380685869814344975511061045836883803841066664401308n,
  14583556014436264794011679557180458872925270147116325433110111823036572987256n,
  11881598145635709076820802010238799308467020773223027240974808290357539410246n,
  1566675577370566803714158020143436746360531503329117352692311127363508063658n,
  212097210828847555076368799807292486212366234848453077606919035866276438405n,
  7447795983723838393344606913699113402588250391491430720006009618589586043349n,
  7626475329478847982857743246276194948757851985510858890691733676098590062312n,
  148936322117705719734052984176402258788283488576388928671173547788498414614n,
  15456385653678559339152734484033356164266089951521103188900320352052358038156n,
  18207029603568083031075933940507782729612798852390383193518574746240484434885n,
  2783356767974552799246444090988849933848968900471538294757665724820698962027n,
  2721136724873145834448711197875719736776242904173494370334510875996324906822n,
  2101139679159828164567502977338446902934095964116292264803779234163802308621n,
  8995221857405946029753863203034191016106353727035116779995228902499254557482n,
  502050382895618998241481591846956281507455925731652006822624065608151015665n,
  4998642074447347292230083981705092465562944918178587362047610976950173759150n,
  9349925422548495396957991080641322437286312278286826683803695584372829655908n,
  11780347248050333407713097022607360765169543706092266937432199545936788840710n,
  17875657248128792902343900636176628524337469245418171053476833541334867949063n,
  10366707960411170224546487410133378396211437543372531210718212258701730218585n,
  16918708725327525329474486073529093971911689155838787615544405646587858805834n,
  18845394288827839099791436411179859406694814287249240544635770075956540806104n,
  9838806160073701591447223014625214979004281138811495046618998465898136914308n,
  10285680425916086863571101560978592912547567902925573205991454216988033815759n,
  1292119286233210185026381033809498665433650491423040630240164455269575958565n,
  2665524343601461489082054230426835550060387413710679950970616347092017688857n,
  13502286133892103192305476866434484921895765252706158317341618311553476426306n,
  686854655578191041672292972738875170071982317195092845673566320025160026512n,
  9315942923163981372372434957632152754092082859001311184186702151150554806508n,
  17166793131238158480636170455452575971861309825745828685724097210995239015581n,
  4443784618760852757287735236046535266034706880634443644576653970979377878608n,
  21470445782021672615018345703580059646973568891521510437236903770708690160080n,
  6932852445473908850835611723958058203645654625170962537129706393570586565567n,
  17078326120157725640173982185667969009350208542843294226397809921509565607842n,
  19251873001736801921864956728611772738233338338726553113352118847732921831266n,
  13062907978694932362695258750558734366820802962383346229947907261606619788585n,
  16576609187793673559170206379939616900133457644695219057683704871664434872406n,
  17140499059660867342372156843620845644831519603574612796639429147195776838516n,
  16226688173010504218547945848523900236290532501559570164276462499487632388445n,
  2806068123803905806401128967330263340459046260107112845068533446899070326517n,
  17788735370835052317224182711467216134690146479710634688273650370951230404901n,
  9840665370904113434661468973557421114403401847108482949465899631150766783733n,
  17357287363046228581837055771327121704742940914150998420465281177406182088510n,
  8956082469997974864521346025916496675956939495318858500685756691488425559998n,
  10583741436561099911914917245130852199607666337956354910388730829023746895549n,
  15241902639811607164983030447109332729761435946009172128089506810551693978973n,
  10889882303914055687481932975789161945462141459528413507160087442461090813788n,
  19789561133254944544821898921133697408237804586549835559829396563401674817160n,
  20741336668287037026472434608739333171202674306575625457456116338034432647230n,
  17864073449995977742930566850933082711031717858550870842712972350665650521079n,
  6017691253505466300212182439349954426085752315661098358839308909771637792741n,
  5209125836207196173669497054522582922896061838702136844305036341250990710540n,
  8138726312837322624537330169363664364899441867118983214176695868443641051381n,
  15491983986041746833254372934846748393213690608865689646440909282144232382678n,
  5054332867608171303802774230688792431028169804536607979111644888500809938980n,
  15427030776591294577308915282298854681562344215287630895931797573417982096417n,
  21754057982677295571284116502193272661309010996970316384923307174180521790164n,
  16265286590463120486705206231835953324076688991892805307349612983237844034032n,
  17679791107777049796013011282788633179411040182820636236163074053597517790779n,
  4281652562868629887097957174897458165728741859103571825874408386197225591996n,
  9168010397863299719604788533602757515513214141450093775967322808686129400625n,
  17584182367226175071087689123358883902969885218985589531538416263709138156515n,
  15671512310414658663135385639435845966109237059155734764323312289873534719186n,
  10536294659491685326297777845632759824567028904726211134518740400643540109527n,
  13431319759608247201135260841651365578663315527795431484765940626659812285319n,
  9584697124715190200241839387725546204368618031045071660911490086723434692561n,
  5180327104839158483066851400960171505063442195966219343315555549982472660055n,
  18888217223053385111625483360538133292128748730565502371803782424772027937822n,
  19535732913737027522540340630296365525208404217634392013266346283017745945894n,
  8577759627886344995887423695190093296190181539234301534326157005220006624466n,
  16793670928407147476673650839110019799844249677846432113010280456483595763987n,
  13926032620965299897272071104154310460519723329016284975305942957859374938463n,
  4794697578055472890255676575927616606591024075768967985031137397587590174501n,
  3529566190782060578446859853852791941913086545101307988176595267965876143250n,
  3975008029239568933166738482470827494289192118694622729549964538823092192163n,
  17739094873244464728483944474780943281491793683051033330476367597242349886622n,
  7367136451127531266518046223598095299278392589059366687082785080179161005418n,
  11175297939460631138047404082172242706491354303440776362693987984031241399771n,
  21687543815463985355165197827968086406938428974327951792877419032069230058777n,
  21156136641989461785420005321350884477682466566148802533375726181416623358719n,
  17347558768803521970212188258074365309929638984714303299899732035040892048478n,
  16293716234695956076322008955071091921491953458541407305955104663269677475740n,
  4206144021605871396668976569508168522675546062304959729829228403361714668567n,
  19988050626299122864942213847548542155670073758974734015174045163059179151544n,
  747972634423324369570795147739377097591383105262743308036321386836856106229n,
  4612470951309047869982067912468200581649949743307592869671537990797895413707n,
  9630852913694079049153027193127278569487291430069466630362958024525616303220n,
  17941539917430916523930519432495442476511211427972760202450248798031711471474n,
  20332911350443969653703295317915788278109458962706923653715140186132935894113n,
  21764801803055897327474057344100833670291402543384934706514147201527191846513n,
  18792043166429470991157980448329308661526906138700725174612608941551872082876n,
  12308177224490762720061048892842527800271687977085172836705858261595655154325n,
  6234555076867437297776538521925679658360922070165740193866337972293380196151n,
  4651047048822067434403056477377459986292934655827821636179452835839127581305n,
  4762047093602693619418269784972874862577325737690375448572644958129932507374n,
  12373514879531674477721132062882065826558811149582829246378921774344318418269n,
  452512704634345955634014968317367844987135264395068376894497483188243356523n,
  21642936370936057063268550589361090955573362743817395689260298777690935495218n,
  16170209200627740434842090607802586195654207376087117044989637541681675086276n,
  11682826760471401430136435257946377996085824742031456481961511737883954750045n,
  20628055165039718158878805520495324869838279647796500565701893698896698211929n,
  16438375313036818694140277721632185529697783132872683043559674569424388375143n,
  4855690425141732729622202649174026736476144238882856677953515240716341676853n,
  11680269552161854836013784579325442981497075865007420427279871128110023581360n,
  7052688838948398479718163301866620773458411881591190572311273079833122884040n,
  10339199500986679207942447430230758709198802637648680544816596214595887890122n,
  16310974164366557619327768780809157500356605306298690718711623172209302167675n,
  4572051236178600578566286373491186377601851723137133424312445102215267283375n,
  20933392620931420860078756859763708025350478446661033451436796955762857910093n,
  10145870387395991071594748880090507240612313913083518483680901820696866812598n,
  11173854866888110108878560284050142518686158431744851782991510385755602063727n,
  3895357290105797542988795070918100785105415165483657264407967118738833241858n,
  16358886674154007883356717944805100413481233709808000948036974385803613296849n,
  10544067501284177518983466437755150442726536257903869254459488412549270232123n,
  10495171258604974589451578238018388630585794890815982293891430761424812600427n,
  13820724103604550843562070971473423552484851063169471886037640613650155173554n,
  2334954333435579600152488915208745055087482119087065911968347050969338669409n,
  15100284614446277058846085121308897497066957549089629374506920751044105723791n,
  8493821960754696376711287628276980042183127459347650448500304251148421115590n,
  18612435536889941393944858783110719304584209891406420832295898519317994950798n,
  362101794940079733974215941991047456600874474038781578925062694203564740952n,
  11020033081956343850903875701444955317664141075326494650405276926536449284939n,
  9396289482656518627529185765935649373549564165735162258912975312413185691167n,
  6879055176150676925438486069371149089824290576271090206945130252868108043422n,
  12466610601804566637227883322591924115458766539177061670432424956205788935144n,
  6570302110526154075173287644133038486970998888099669190857256824048085590052n,
  20997862990590350605775941983360263378441519274215787225587679916056749626824n,
  2642485040919927233352421501444361753154137311893617974318977215281720542724n,
  18832940311494549247524002614969382413324906834787422940144532352384742506504n,
  18751288968473015103659806087408412890105261892140397690496125593160830694164n,
  13938622158186434739533995447553824444480420613323252752005511269934155122652n,
  12878982657080117316101160964182202074759312554860119090514406868768962707099n,
  13757859113119127982418426758782225628393556023865807897214601826218702003247n,
  11817871682869491875135867072669251115204978941736982465520516648114811792373n,
  11336448548896065624515261709306933490181794458266726453198857687608284871020n,
  194970717714150352477887371297168267861902418496792228400198694925721020795n,
  4999282817977533227652305360183045040853565298259070645110453061034932285549n,
  17094174197873140035316532568922652294881600587639905417701074492648767414173n,
  8484251464872873032022789624790167173458682056313339863651348894878144808746n,
  10260366716129057466862964875306868898686918428814373470382979997177852668590n,
  549263552864476084904464374701167884060947403076520259964592729731619317724n,
  10052714818439832487575851829190658679562445501271745818931448693381812170889n,
  1735373362835209096342827192021124337509188507323448903608623506589963950966n,
  7998373949540733111485892137806629484517602009122941425332571732658301689428n,
  9035170288660659483243066011612158174896974797912618405030929911180945246244n,
  6458619567307414386633203375143968061892762498463026121155477954682976784731n,
  12314261817227551876673777186352972884847144237148169773300066404053441924532n,
  19869454329688183813243851218196625862680921049019496233616575272637276975230n,
  20326917073492686652690019138603910654692396590122884746951129061818467704300n,
  20403270805536666081472738304916561119325397964511536801752236086414818653063n,
  2865941730880218719188224311916978807415673142487507504983320505748719154068n,
  20614246027521726470902405957496110178017768563127335842405314212897493119848n,
  12060194341463088508348622863463208827312128863463014006529428845777217660299n,
  1128906798719793375274166820235650701301189774851381709919492584451845983197n,
  19670876372911656158743764425809421400123168087389888660308456184201759209723n,
  5647230694522866559497222129254930524469944430191328619422533907417776118543n,
  318629082509194371490189248876734616088516535434806492900653650176451776632n,
  13685970881538585172319228162662520285656571966985351768743970447782846353365n,
  8283840607829148567836919316142994745766280854211662326632930274668867638198n,
  8968895518159422029900464138741638511289476298837958524156654785428413265371n,
  10061801991000917366002570579819627134666386452411986168205986791283562415829n,

  ];
  const M = [

  [
    16023668707004248971294664614290028914393192768609916554276071736843535714477n,
    17849615858846139011678879517964683507928512741474025695659909954675835121177n,
    1013663139540921998616312712475594638459213772728467613870351821911056489570n,
    13211800058103802189838759488224684841774731021206389709687693993627918500545n,
  ],
  [
    19204974983793400699898444372535256207646557857575315905278218870961389967884n,
    3722304780857845144568029505892077496425786544014166938942516810831732569870n,
    11920634922168932145084219049241528148129057802067880076377897257847125830511n,
    6085682566123812000257211683010755099394491689511511633947011263229442977967n,
  ],
  [
    14672613178263529785795301930884172260797190868602674472542654261498546023746n,
    20850178060552184587113773087797340350525370429749200838012809627359404457643n,
    7082289538076771741936674361200789891432311337766695368327626572220036527624n,
    1787876543469562003404632310460227730887431311758627706450615128255538398187n,
  ],
  [
    21407770160218607278833379114951608489910182969042472165261557405353704846967n,
    16058955581309173858487265533260133430557379878452348481750737813742488209262n,
    593311177550138061601452020934455734040559402531605836278498327468203888086n,
    341662423637860635938968460722645910313598807845686354625820505885069260074n,
  ]

  ];

  function mod(a) {{
    const r = a % BN254_FIELD;
    return r >= 0n ? r : r + BN254_FIELD;
  }}

  function sbox5(x) {{
    const x2 = mod(x * x);
    const x4 = mod(x2 * x2);
    return mod(x4 * x);
  }}

  // 3 inputs, state = [0, i1, i2, i3]; 8 full rounds, 56 partial rounds.
  function poseidon4(inputs) {{
    const t = 4, nRoundsF = 8, nRoundsP = 56;
    const halfRounds = nRoundsF / 2;
    const totalRounds = nRoundsF + nRoundsP;
    let state = [0n, mod(inputs[0]), mod(inputs[1]), mod(inputs[2])];
    for (let r = 0; r < totalRounds; r++) {{
      for (let i = 0; i < t; i++) state[i] = mod(state[i] + C[r * t + i]);
      if (r < halfRounds || r >= halfRounds + nRoundsP) {{
        for (let i = 0; i < t; i++) state[i] = sbox5(state[i]);
      }} else {{
        state[0] = sbox5(state[0]);
      }}
      const ns = [0n, 0n, 0n, 0n];
      for (let i = 0; i < t; i++) {{
        for (let j = 0; j < t; j++) {{
          ns[i] = mod(ns[i] + state[j] * M[i][j]);
        }}
      }}
      state = ns;
    }}
    return state[0];
  }}

  // Mirrors Rust's `(f64 * 10000.0) as u64` saturating cast semantics.
  function f64ToU64Saturating(x) {{
    if (!Number.isFinite(x)) return x > 0 ? 0xFFFFFFFFFFFFFFFFn : 0n;
    if (x <= 0) return 0n;
    if (x >= 18446744073709551616) return 0xFFFFFFFFFFFFFFFFn;
    return BigInt(Math.trunc(x));
  }}

  // Self-test: pins poseidon4 to vectors produced by the Rust implementation.
  // The Rust side emits fixed-width 64-hex-char strings; BigInt.toString(16)
  // strips leading zeroes, so both sides are padded before comparing.
  const POSEIDON_SELF_TEST_OK = (function () {{
    const hex64 = function (v) {{ return v.toString(16).padStart(64, '0'); }};
    const v1 = hex64(poseidon4([0n, 5000000n, 50500n]));
    const v2 = hex64(poseidon4([1n, 2n, 3n]));
    return v1 === '2f965d1a1ad15eb3351f8e772d681e6287754eb759d579193896e93e219c8bf8'
        && v2 === '0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732';
  }})();

  function verifyPoseidon(btn) {{
    if (!POSEIDON_SELF_TEST_OK) {{
      alert('Poseidon self-test failed; verification aborted.');
      return;
    }}
    const dataEl = document.getElementById('selo-verify-data');
    if (!dataEl) {{
      alert('No Poseidon verification data found in this report.');
      return;
    }}
    let data;
    try {{
      data = JSON.parse(dataEl.textContent.trim());
    }} catch (e) {{
      alert('Poseidon verification data is not valid JSON.');
      return;
    }}
    const expectedRoot = data.state_root;
    let acc = 0n;
    for (const lot of data.lots) {{
      // ptax_scaled is pre-computed in Rust (u64), avoiding f64 rounding mismatch
      acc = poseidon4([acc, BigInt(lot.amount), BigInt(lot.ptax_scaled)]);
    }}
    const computedHex = '0x' + acc.toString(16).padStart(64, '0');
    // An empty ledger reports root 0x0 in Rust; the fold of zero lots is zero.
    const matches = computedHex === expectedRoot || (expectedRoot === '0x0' && acc === 0n);
    const badge = btn.nextElementSibling;
    if (matches) {{
      badge.className = 'verify-badge compact verified';
      badge.textContent = '\u2713 VERIFIED';
    }} else {{
      badge.className = 'verify-badge compact tampered';
      badge.textContent = '\u2717 TAMPERED';
    }}
  }}
</script>
</body>
</html>
"#,
            title_suffix = title_suffix,
            cumulative_ledger_receipts = cumulative_ledger_receipts,
            cumulative_ledger_cost = cumulative_ledger_cost,
            sorted_years_len = sorted_years.len(),
            fiscal_years_html = fiscal_years_html,
            no_records_note = no_records_note,
            integrity_hash = integrity_hash,
            lots_json = lots_json,
            state_root = state_root,
            poseidon_verify_json = poseidon_verify_json,
        );

        Ok(html_output)
    }
}
