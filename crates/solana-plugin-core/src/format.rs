//! Output rendering. The tool's output is read by a language model, so it
//! leads with a short human-readable summary and follows with a compact
//! JSON block the model can quote or post-process reliably.

use serde_json::{json, Value};

use crate::jupiter::{SwapQuote, TokenPrice};
use crate::priority::FeeEstimate;
use crate::rpc::TokenBalance;
use crate::simulate::Simulation;
use crate::token::TokenTransfer;
use crate::tx::TxSummary;

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
///
/// `tokens` is `None` when token accounts were not requested, versus
/// `Some(empty)` when they were requested and there are none. The two
/// read differently on purpose.
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

/// Render a base-unit integer string using `decimals`, so a quote can
/// show "0.1 SOL" next to the raw "100000000" it actually quoted.
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

/// Render the tool output for a price lookup. `missing` lists tokens the
/// caller asked about that Jupiter returned no price for.
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
        lines.join("
")
    };
    if !missing.is_empty() {
        summary.push_str(&format!(
            "
No price available for: {}",
            missing.join(", ")
        ));
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
    format!("{summary}

{json_block}")
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
    format!("{summary}

{json_block}")
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
        None => "The node has not reported a confirmation yet; it usually lands within a few seconds.".to_string(),
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
    format!("{summary}

{json_block}")
}

/// Render the tool output for a simulated transfer.
pub fn render_simulation(
    from: &str,
    to: &str,
    lamports: u64,
    sim: &Simulation,
) -> String {
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
        summary.push_str("
Program log:");
        for line in sim.logs.iter().take(8) {
            summary.push_str(&format!("
  {line}"));
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
    format!("{summary}

{json_block}")
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
    format!("{summary}

{json_block}")
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
    /// None when verification was not attempted for this account.
    pub verified: Option<Result<(), String>>,
}

/// Render the tool output for compressed account lookup.
///
/// The distinction between checked and unchecked accounts is kept
/// explicit, because the whole point of this tool is that a verified
/// balance is a different kind of claim from an indexer's assertion.
pub fn render_compressed_accounts(
    owner: &str,
    total: usize,
    accounts: &[VerifiedAccount],
) -> String {
    let checked: Vec<&VerifiedAccount> =
        accounts.iter().filter(|a| a.verified.is_some()).collect();
    let failures: Vec<&VerifiedAccount> = checked
        .iter()
        .copied()
        .filter(|a| matches!(&a.verified, Some(Err(_))))
        .collect();

    let mut summary = format!(
        "{owner} owns {total} compressed account(s) according to the indexer."
    );
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
    // Priority fees are routinely fractions of a cent, so a fixed two
    // decimal places would render almost every real answer as "$0.00".
    if usd >= 0.01 {
        format!("${usd:.2}")
    } else if usd >= 0.000001 {
        format!("${usd:.6}")
    } else {
        "under $0.000001".to_string()
    }
}

/// Render the tool output for a priority fee estimate.
///
/// `sol_usd` is optional and best effort: an agent deciding whether a
/// fee is worth paying thinks in dollars, not in micro-lamports per
/// compute unit, but a price lookup failing is no reason to withhold
/// the estimate itself.
pub fn render_fee_estimate(
    e: &FeeEstimate,
    accounts: &[String],
    sol_usd: Option<f64>,
) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_fee_estimate_reports_cost_in_sol() {
        let e = FeeEstimate {
            sample_count: 150,
            nonzero_count: 15,
            p50: 50_000,
            p75: 90_000,
            p95: 140_000,
            max: 6_145_297,
            recommended_micro_lamports: 90_000,
            urgency: crate::priority::Urgency::Normal,
            compute_units: 1_000,
        };
        let out = render_fee_estimate(&e, &["Mint1".to_string()], Some(180.0));
        assert!(out.contains("normal urgency"));
        assert!(out.contains("90000 micro-lamports"));
        // 90000 * 1000 / 1e6 is 90 lamports.
        assert!(out.contains("90 lamports"));
        assert!(out.contains("15 of 150 slots"));
        assert!(out.contains("Mint1"));
    }

    #[test]
    fn render_fee_estimate_says_when_no_bid_needed() {
        let e = FeeEstimate {
            sample_count: 20,
            nonzero_count: 0,
            p50: 0,
            p75: 0,
            p95: 0,
            max: 0,
            recommended_micro_lamports: 0,
            urgency: crate::priority::Urgency::High,
            compute_units: 1_000,
        };
        let out = render_fee_estimate(&e, &[], None);
        assert!(out.contains("no bid is needed"));
        assert!(out.contains("network-wide"));
    }

    #[test]
    fn whole_sol() {
        assert_eq!(lamports_to_sol(2_000_000_000), "2");
    }

    #[test]
    fn fractional_sol_trims_zeros() {
        assert_eq!(lamports_to_sol(1_500_000_000), "1.5");
        assert_eq!(lamports_to_sol(1), "0.000000001");
    }

    #[test]
    fn zero() {
        assert_eq!(lamports_to_sol(0), "0");
    }

    #[test]
    fn render_without_tokens() {
        let out = render_balance("Addr", 1_500_000_000, None);
        assert!(out.contains("1.5 SOL"));
        assert!(!out.contains("SPL token account"));
        assert!(out.contains("\"tokens\":null"));
    }

    #[test]
    fn render_with_empty_tokens_says_so() {
        let out = render_balance("Addr", 0, Some(&[]));
        assert!(out.contains("no SPL token accounts"));
    }

    #[test]
    fn render_lists_tokens() {
        let tokens = vec![TokenBalance {
            mint: "Mint1".to_string(),
            amount_raw: "2500000".to_string(),
            decimals: 6,
            ui_amount: "2.5".to_string(),
        }];
        let out = render_balance("Addr", 0, Some(&tokens));
        assert!(out.contains("2.5 of mint Mint1"));
        // JSON block carries the raw amount for exact arithmetic.
        assert!(out.contains("\"amount_raw\":\"2500000\""));
    }

    #[test]
    fn delta_signs() {
        assert_eq!(delta_to_sol(-1_500_000_000), "-1.5");
        assert_eq!(delta_to_sol(100_000), "+0.0001");
    }

    #[test]
    fn render_tx_success_and_failure() {
        let mut s = TxSummary {
            signature: "Sig1".to_string(),
            slot: 42,
            block_time_unix: Some(1_750_000_000),
            error: None,
            fee_lamports: 5000,
            fee_payer: "Payer".to_string(),
            compute_units: Some(450),
            balance_changes: vec![crate::tx::BalanceChange {
                account: "Payer".to_string(),
                delta_lamports: -105_000,
            }],
            log_tail: vec![],
        };
        let ok = render_tx(&s);
        assert!(ok.contains("succeeded in slot 42"));
        assert!(ok.contains("-0.000105 SOL"));

        s.error = Some(r#"{"InstructionError":[0,"Custom"]}"#.to_string());
        s.log_tail = vec!["Program failed".to_string()];
        let failed = render_tx(&s);
        assert!(failed.contains("FAILED"));
        assert!(failed.contains("Program failed"));
    }

    #[test]
    fn render_transfer_mentions_signature() {
        let out = render_transfer("From", "To", 1_500_000_000, "Sig9");
        assert!(out.contains("1.5 SOL"));
        assert!(out.contains("Sig9"));
        assert!(out.contains("\"lamports\":1500000000"));
    }

    #[test]
    fn base_units_render() {
        assert_eq!(base_units_to_decimal("100000000", 9), "0.1");
        assert_eq!(base_units_to_decimal("7750169", 6), "7.750169");
        assert_eq!(base_units_to_decimal("1000000", 6), "1");
        assert_eq!(base_units_to_decimal("5", 9), "0.000000005");
        assert_eq!(base_units_to_decimal("42", 0), "42");
    }

    #[test]
    fn render_prices_and_missing() {
        let prices = vec![TokenPrice {
            mint: "So111".to_string(),
            usd_price: 77.488394,
            decimals: 9,
            price_change_24h: Some(-0.978),
            liquidity: Some(1.0),
        }];
        let out = render_prices(&prices, &["FAKE".to_string()]);
        assert!(out.contains("So111 is $77.488394"));
        assert!(out.contains("-0.98% 24h"));
        assert!(out.contains("No price available for: FAKE"));
    }

    #[test]
    fn render_quote_is_explicit_about_not_swapping() {
        let q = SwapQuote {
            input_mint: "So111".to_string(),
            output_mint: "EPjF".to_string(),
            in_amount: "100000000".to_string(),
            out_amount: "7750169".to_string(),
            min_out_amount: "7711419".to_string(),
            slippage_bps: 50,
            price_impact_pct: Some(0.0000261),
            usd_value: Some(7.7498),
            route_labels: vec!["HumidiFi".to_string()],
        };
        let out = render_quote(&q, Some(9), Some(6));
        assert!(out.contains("Swapping 0.1 of So111"));
        assert!(out.contains("7.750169"));
        assert!(out.contains("guaranteed minimum is 7.711419"));
        assert!(out.contains("Route: HumidiFi"));
        assert!(out.contains("quote only"));
    }

    #[test]
    fn render_airdrop_pending_and_confirmed() {
        let pending = render_airdrop("Addr", 1_000_000_000, "Sig1", None);
        assert!(pending.contains("1 SOL"));
        assert!(pending.contains("not reported a confirmation yet"));

        let done = render_airdrop("Addr", 1_000_000_000, "Sig1", Some("finalized"));
        assert!(done.contains("Status: finalized"));
    }

    #[test]
    fn render_simulation_states_dry_run_first() {
        let ok = Simulation {
            error: None,
            compute_units: Some(450),
            logs: vec!["Program success".to_string()],
        };
        let out = render_simulation("From", "To", 1_500_000_000, &ok);
        assert!(out.starts_with("Dry run only, nothing was sent."));
        assert!(out.contains("WOULD SUCCEED"));
        assert!(out.contains("\"would_succeed\":true"));

        let bad = Simulation {
            error: Some("InstructionError".to_string()),
            compute_units: None,
            logs: vec![],
        };
        let out = render_simulation("From", "To", 1, &bad);
        assert!(out.contains("WOULD FAIL"));
        assert!(out.contains("\"would_succeed\":false"));
    }

    #[test]
    fn render_token_transfer_reports_accounts_and_creation() {
        let owner = crate::address::decode_pubkey(
            "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM",
        )
        .unwrap();
        let t = TokenTransfer::resolve(
            &owner,
            "GThUX1Atko4tqhN2NaiTazWSeFWMuiUvfFnyJyUghFMJ",
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            2_500_000,
            6,
            true,
        )
        .unwrap();

        let out = render_token_transfer(&t, "USDC", true, "SigTok");
        assert!(out.contains("2.5 USDC"));
        assert!(out.contains("SigTok"));
        assert!(out.contains("was created"));
        assert!(out.contains("FGETo8T8wMcN2wCjav8VK6eh3dLk63evNDPxzLSJra8B"));
        assert!(out.contains("\"created_destination_account\":true"));

        let out = render_token_transfer(&t, "USDC", false, "SigTok");
        assert!(!out.contains("was created"));
    }

    #[test]
    fn render_swap_reports_minimum_and_route() {
        let q = SwapQuote {
            input_mint: "So111".to_string(),
            output_mint: "EPjF".to_string(),
            in_amount: "10000000".to_string(),
            out_amount: "774566".to_string(),
            min_out_amount: "770694".to_string(),
            slippage_bps: 50,
            price_impact_pct: Some(0.00001),
            usd_value: Some(0.77),
            route_labels: vec!["HumidiFi".to_string(), "Meteora".to_string()],
        };
        let out = render_swap(&q, "SOL", "USDC", Some(9), Some(6), Some(21000), "SigSwap");
        assert!(out.contains("swap of 0.01 SOL"));
        assert!(out.contains("about 0.774566 USDC"));
        assert!(out.contains("at least 0.770694 USDC"));
        assert!(out.contains("HumidiFi then Meteora"));
        assert!(out.contains("21000 lamports"));
        assert!(out.contains("SigSwap"));
    }

    #[test]
    fn render_swap_without_priority_fee() {
        let q = SwapQuote {
            input_mint: "a".to_string(),
            output_mint: "b".to_string(),
            in_amount: "1".to_string(),
            out_amount: "2".to_string(),
            min_out_amount: "2".to_string(),
            slippage_bps: 50,
            price_impact_pct: None,
            usd_value: None,
            route_labels: vec![],
        };
        let out = render_swap(&q, "A", "B", None, None, None, "Sig");
        assert!(!out.contains("priority fee"));
        assert!(out.contains("\"priority_fee_lamports\":null"));
    }

    #[test]
    fn render_compressed_marks_verified_and_failed() {
        let accounts = vec![
            VerifiedAccount {
                hash: "HashA".into(), leaf_index: 4, tree: "TreeX".into(),
                lamports: 0, verified: Some(Ok(())),
            },
            VerifiedAccount {
                hash: "HashB".into(), leaf_index: 9, tree: "TreeX".into(),
                lamports: 5, verified: None,
            },
        ];
        let out = render_compressed_accounts("Owner1", 534, &accounts);
        assert!(out.contains("owns 534 compressed account(s)"));
        assert!(out.contains("1 of them had their merkle proof verified"));
        assert!(out.contains("HashA leaf 4 in tree TreeX (0 lamports) [verified]"));
        assert!(out.contains("[unverified]"));
        assert!(out.contains("\"proof_verified\":true"));
    }

    #[test]
    fn render_compressed_shouts_when_a_proof_fails() {
        let accounts = vec![VerifiedAccount {
            hash: "HashC".into(), leaf_index: 1, tree: "TreeX".into(),
            lamports: 0, verified: Some(Err("root mismatch".into())),
        }];
        let out = render_compressed_accounts("Owner1", 1, &accounts);
        assert!(out.contains("FAILED to verify"));
        assert!(out.contains("untrusted"));
        assert!(out.contains("root mismatch"));
        assert!(out.contains("\"proof_verified\":false"));
    }

    #[test]
    fn render_compressed_is_explicit_when_nothing_checked() {
        let out = render_compressed_accounts("Owner1", 3, &[]);
        assert!(out.contains("No merkle proofs were checked"));
        assert!(out.contains("rather than verified state"));
    }

    #[test]
    fn usd_rendering_scales_to_tiny_fees() {
        // A typical priority fee is a fraction of a cent, so two
        // decimal places alone would render it as "$0.00".
        assert_eq!(lamports_to_usd(1_000_000_000, 180.0), "$180.00");
        // 0.0001 SOL is 1.8 cents, which reads fine at two places.
        assert_eq!(lamports_to_usd(100_000, 180.0), "$0.02");
        // A tenth of that would round to $0.00, so it gets six places.
        assert_eq!(lamports_to_usd(10_000, 180.0), "$0.001800");
        assert_eq!(lamports_to_usd(1, 180.0), "under $0.000001");
        assert_eq!(lamports_to_usd(0, 180.0), "under $0.000001");
    }

    #[test]
    fn fee_estimate_quotes_dollars_when_price_known() {
        let e = FeeEstimate {
            sample_count: 150, nonzero_count: 15,
            p50: 50_000, p75: 90_000, p95: 140_000, max: 6_145_297,
            recommended_micro_lamports: 90_000,
            urgency: crate::priority::Urgency::Normal,
            compute_units: 1_000,
        };
        let with_price = render_fee_estimate(&e, &[], Some(180.0));
        // 90 lamports at $180/SOL is 0.0000162 dollars.
        assert!(with_price.contains("90 lamports"));
        assert!(with_price.contains("about $0.0000"));
        assert!(with_price.contains("\"sol_usd_price\":180.0"));

        let without = render_fee_estimate(&e, &[], None);
        assert!(without.contains("90 lamports"));
        assert!(!without.contains("about $"));
        assert!(without.contains("\"total_priority_fee_usd\":null"));
    }
}
