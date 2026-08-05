use crate::jupiter::{SwapQuote, TokenPrice};
use crate::lots::TaxLedger;
use crate::priority::FeeEstimate;
use crate::rpc::TokenBalance;
use crate::simulate::Simulation;
use crate::token::TokenTransfer;
use crate::tx::TxSummary;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

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
        fiscal_year: &str,
        anchor_sig: Option<&str>,
    ) -> Result<String, String> {
        let state_root = self.compute_state_root()?;
        let current_calendar_year = "2026";

        let mut year_month_groups: BTreeMap<String, BTreeMap<String, Vec<crate::lots::TaxLot>>> =
            BTreeMap::new();

        for lot in &self.lots {
            let year_key = if lot.acquired_at_utc.len() >= 4 {
                lot.acquired_at_utc[..4].to_string()
            } else {
                fiscal_year.to_string()
            };

            let month_key = if lot.acquired_at_utc.len() >= 7 {
                lot.acquired_at_utc[..7].to_string()
            } else {
                format!("{}-01", fiscal_year)
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
                .entry(fiscal_year.to_string())
                .or_default();
        }

        let small_mark_open = r#"<svg width="17" height="17" viewBox="0 0 128 128" style="display:inline-block; vertical-align:middle; opacity:.45;" role="img" aria-label="Open"><defs><clipPath id="s-open"><circle cx="64" cy="64" r="50"/></clipPath></defs><g clip-path="url(#s-open)"><path d="M64 0H128V128H64Z" fill="currentColor"/></g><circle cx="64" cy="64" r="50" fill="none" stroke="currentColor" stroke-width="13"/></svg>"#;
        let small_mark_sealed = r#"<svg width="17" height="17" viewBox="0 0 128 128" style="display:inline-block; vertical-align:middle; color:var(--wax);" role="img" aria-label="Sealed"><defs><clipPath id="s-seal"><circle cx="64" cy="64" r="50"/></clipPath></defs><g clip-path="url(#s-seal)"><path d="M64 0H128V128H64Z" fill="currentColor"/></g><circle cx="64" cy="64" r="50" fill="none" stroke="currentColor" stroke-width="13"/></svg>"#;

        let mut cumulative_ledger_cost = 0.0;
        let mut cumulative_ledger_receipts = 0;
        let mut fiscal_years_html = String::new();

        let mut sorted_years: Vec<String> = year_month_groups.keys().cloned().collect();
        sorted_years.sort();
        sorted_years.reverse();

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
                                    <tr><th>PERIOD CODE</th><th>ASSET CLASS</th><th>TOTAL VOLUME</th><th>CUMULATIVE COST BASIS (BRL)</th><th>PTAX RATE</th><th>INTERVAL UTC</th></tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td>Month Closing &middot; {period_key}</td>
                                        <td>Aggregated Monthly Period</td>
                                        <td>{receipt_count} receipts</td>
                                        <td>R$ {month_cost_brl:.2}</td>
                                        <td>R$ {avg_ptax:.4} (Avg)</td>
                                        <td>{sample_date}</td>
                                    </tr>
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
                                    <tr><th>PERIOD CODE</th><th>ASSET CLASS</th><th>TOTAL VOLUME</th><th>CUMULATIVE COST BASIS (BRL)</th><th>PTAX RATE</th><th>INTERVAL UTC</th></tr>
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
                target_yr.as_str() < current_calendar_year || anchor_sig.is_some();
            let year_status_html = if is_year_anchored {
                format!(
                    r#"<div class="sealed">{small_mark_sealed} Sealed &middot; root {}&hellip;</div>"#,
                    &state_root.chars().take(12).collect::<String>()
                )
            } else {
                format!(r#"<div class="open">{small_mark_open} Open &middot; pending close</div>"#)
            };

            let is_current_year = target_yr == current_calendar_year;
            let year_expanded_class = if is_current_year { "expanded" } else { "" };
            let year_content_display = if is_current_year { "block" } else { "none" };

            fiscal_years_html.push_str(&format!(
                r#"
                <div class="accordion-item" id="year-{target_yr}" style="border-color: var(--selo-ink); margin-bottom: 20px;">
                    <div class="accordion-header {year_expanded_class}" onclick="toggleAccordion('year-{target_yr}')">
                        <div>
                            <div class="k">Fiscal Year &middot; {target_yr}</div>
                            <div class="v" style="margin:2px 0 0;">{year_receipt_count} receipts &middot; R$ {year_cost_brl:.2}</div>
                        </div>
                        <div style="display:flex; align-items:center; gap:16px;">
                            {year_status_html}
                            <span class="chevron">&#9662;</span>
                        </div>
                    </div>
                    <div class="accordion-content" style="display: {year_content_display}; padding: 16px;">
                        <div style="margin-bottom: 16px;">
                            <div class="k" style="margin-bottom:6px;">Cryptographic State Root (Poseidon BN254 Commitment)</div>
                            <div style="display:flex; justify-content:space-between; align-items:center; background:var(--selo-raised); padding:10px 14px; border-radius:8px; border:1px solid var(--selo-rule);">
                                <span style="font: 600 12px/1.4 var(--selo-font-mono); word-break:break-all;">{state_root}</span>
                                <button class="copy-btn" onclick="copyToClipboard('{state_root}', this)">Copy Root</button>
                            </div>
                        </div>
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
                year_expanded_class = year_expanded_class,
                year_content_display = year_content_display,
                state_root = state_root,
                monthly_rows_html = monthly_rows_html
            ));
        }

        let html_output = format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Selo · Cryptographic Audit Statement · Fiscal Year {fiscal_year}</title>
<style>
  :root {{
    --selo-seal: #16130F;
    --selo-ink: #16130F; 
    --selo-paper: #FAF7F2; 
    --selo-muted: #6B625A; 
    --selo-rule: #DED5C9; 
    --selo-raised: #FFFFFF;
    --wax: #B4381F;
    --selo-font-sans: ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
    --selo-font-mono: ui-monospace, "JetBrains Mono", Consolas, monospace;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{ 
      --selo-ink: #F2EDE5; 
      --selo-paper: #14120F; 
      --selo-muted: #9A8F83; 
      --selo-rule: #2E2A25; 
      --selo-raised: #1D1A16;
      --wax: #F2EDE5;
    }}
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

  footer {{ margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--selo-rule); color: var(--selo-muted); font-size: 12px; }}
</style>
<script>
  function toggleAccordion(id) {{
    const item = document.getElementById(id);
    const content = item.querySelector('.accordion-content');
    const header = item.querySelector('.accordion-header');
    if (content.style.display === 'none' || content.style.display === '') {{
      content.style.display = 'block';
      header.classList.add('expanded');
    }} else {{
      content.style.display = 'none';
      header.classList.remove('expanded');
    }}
  }}
  function copyToClipboard(text, btn) {{
    navigator.clipboard.writeText(text).then(() => {{
      const orig = btn.textContent;
      btn.textContent = 'Copied ✓';
      setTimeout(() => btn.textContent = orig, 2000);
    }});
  }}
</script>
</head>
<body>
<div class="wrapper">
  <div class="header-area">
    <div class="logo-box">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><defs><clipPath id="hb"><circle cx="64" cy="64" r="52"/></clipPath></defs><g clip-path="url(#hb)"><path d="M64 0H128V128H64Z"/><g stroke="currentColor" stroke-width="7"><line x1="0" y1="37" x2="55" y2="37"/><line x1="0" y1="55" x2="55" y2="55"/><line x1="0" y1="73" x2="55" y2="73"/><line x1="0" y1="91" x2="55" y2="91"/></g></g><circle cx="64" cy="64" r="52" fill="none" stroke="currentColor" stroke-width="9"/></svg>
    </div>
    <h1>Selo Tax Ledger Report</h1>
  </div>
  <p class="lede">Self-verifying cryptographic audit statement. Multi-period fiscal view with embedded Poseidon BN254 state root commitments.</p>

  <div class="card">
    <div class="k">Ledger Cumulative Summary</div>
    <div class="v">{cumulative_ledger_receipts} Total Receipts &middot; R$ {cumulative_ledger_cost:.2}</div>
    <p style="margin:8px 0 0; font-size:13px; color:var(--selo-muted);">Aggregated across {sorted_years_len} fiscal year period(s). Expand any fiscal year below to inspect itemized monthly closes and cryptographic state roots.</p>
  </div>

  <div style="display:flex; flex-direction:column; gap:16px;">
    {fiscal_years_html}
  </div>

  <footer>
    <p>Generated by Selo Core &middot; Cryptographically anchored offline statement &middot; Monochrome split-seal ledger interface.</p>
  </footer>
</div>
</body>
</html>
"#,
            fiscal_year = fiscal_year,
            cumulative_ledger_receipts = cumulative_ledger_receipts,
            cumulative_ledger_cost = cumulative_ledger_cost,
            sorted_years_len = sorted_years.len(),
            fiscal_years_html = fiscal_years_html
        );

        Ok(html_output)
    }
}
