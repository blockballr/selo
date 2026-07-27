//! The shop catalog and the settlement addresses, read from config.
//!
//! This module is where the agent's authority over money stops. Prices
//! live here, in operator-controlled config, and nowhere else. The model
//! chooses which item a customer is asking about; it has no way to say
//! what that item costs, because no function here accepts a price as an
//! argument. An injected instruction to apply a discount has nothing to
//! act on: there is no discount parameter to set.
//!
//! The same reasoning covers the merchant address, and there it matters
//! more than anywhere else in the system. If a persuasive message could
//! change the address customers are told to pay, the shop would lose
//! every sale that day and the loss would look like ordinary business
//! until reconciliation. So the address is read from the jailed config
//! section and there is deliberately no code path, anywhere, that takes
//! it from tool arguments.
//!
//! Unlike `RpcConfig`, this config fails closed. An absent RPC URL can
//! sensibly fall back to a public endpoint; an absent catalog cannot
//! sensibly fall back to anything, because a shop with no configured
//! prices should sell nothing rather than sell at a guess. Every missing
//! or malformed field is an error, not a default.

use std::collections::HashMap;

use crate::address::validate_pubkey;
use crate::quote::TAG_SCALE;

/// One sellable item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogItem {
    /// Stable identifier the agent refers to an item by.
    pub sku: String,
    /// Human name, used when talking to a customer.
    pub name: String,
    /// Price for one unit, in the settlement mint's smallest unit.
    pub unit_price_base_units: u64,
}

/// The shop's price list.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    items: Vec<CatalogItem>,
}

impl Catalog {
    /// Parse the catalog from the jailed config section.
    ///
    /// The `catalog` key holds a JSON array of objects with `sku`, `name`
    /// and `price`, where price is a decimal string in whole currency
    /// units such as `"10.00"`. Prices are converted against `decimals`
    /// here so that the rest of the system deals only in base units and
    /// never re-parses a human number.
    pub fn from_section(
        section: &HashMap<String, String>,
        decimals: u8,
    ) -> Result<Self, String> {
        let raw = section
            .get("catalog")
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                "no catalog configured; the operator must set the catalog config key \
                 before this shop can quote anything"
                    .to_string()
            })?;

        #[derive(serde::Deserialize)]
        struct RawItem {
            sku: String,
            name: String,
            price: String,
        }

        let raw_items: Vec<RawItem> = serde_json::from_str(raw)
            .map_err(|e| format!("catalog is not a valid JSON array of items: {e}"))?;
        if raw_items.is_empty() {
            return Err("catalog is empty; there is nothing to sell".to_string());
        }

        let mut items = Vec::with_capacity(raw_items.len());
        for raw in raw_items {
            let sku = raw.sku.trim().to_string();
            if sku.is_empty() {
                return Err("catalog contains an item with an empty sku".to_string());
            }
            let unit_price_base_units = parse_decimal_amount(&raw.price, decimals)
                .map_err(|e| format!("catalog item {sku}: {e}"))?;
            if unit_price_base_units == 0 {
                return Err(format!("catalog item {sku} is priced at zero"));
            }
            // The payment tag occupies the digits below a cent, so a
            // price carrying its own digits there would be corrupted by
            // tagging. Catching it at load time means the operator hears
            // about it once, at startup, rather than at a checkout.
            if unit_price_base_units % TAG_SCALE != 0 {
                return Err(format!(
                    "catalog item {sku} is priced at {} which is finer than one cent on this \
                     mint; payment tagging needs the digits below a cent, so prices must be \
                     whole cents",
                    raw.price
                ));
            }
            items.push(CatalogItem {
                sku,
                name: raw.name.trim().to_string(),
                unit_price_base_units,
            });
        }

        // Two entries for one sku would make the price of that sku depend
        // on lookup order, which is exactly the kind of ambiguity that
        // must not exist anywhere near money.
        for (i, item) in items.iter().enumerate() {
            if let Some(dup) = items[i + 1..]
                .iter()
                .find(|other| other.sku.eq_ignore_ascii_case(&item.sku))
            {
                return Err(format!("catalog lists sku {} more than once", dup.sku));
            }
        }

        Ok(Self { items })
    }

    /// Look up an item by sku.
    ///
    /// Matching is exact, ignoring only case. It is deliberately not
    /// fuzzy: a near-miss match would let a mistaken or manipulated sku
    /// resolve to a different, possibly cheaper item, and quietly selling
    /// the wrong thing is worse than failing to find it.
    pub fn resolve(&self, sku: &str) -> Result<&CatalogItem, String> {
        let wanted = sku.trim();
        self.items
            .iter()
            .find(|i| i.sku.eq_ignore_ascii_case(wanted))
            .ok_or_else(|| {
                format!(
                    "no catalog item with sku {wanted:?}; available skus are {}",
                    self.items
                        .iter()
                        .map(|i| i.sku.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    /// Everything the shop sells, for showing a customer.
    pub fn items(&self) -> &[CatalogItem] {
        &self.items
    }
}

/// Parse a decimal string such as `"10.00"` into base units.
///
/// Done by string manipulation rather than floating point on purpose.
/// A price is exact, and `10.10` has no exact binary representation, so
/// routing money through an f64 introduces error for no benefit.
pub fn parse_decimal_amount(s: &str, decimals: u8) -> Result<u64, String> {
    let text = s.trim();
    if text.is_empty() {
        return Err("price is empty".to_string());
    }
    if text.starts_with('-') {
        return Err(format!("price {text:?} is negative"));
    }

    let (whole, fraction) = match text.split_once('.') {
        Some((w, f)) => (w, f),
        None => (text, ""),
    };
    if whole.is_empty() && fraction.is_empty() {
        return Err(format!("price {text:?} has no digits"));
    }
    if !whole.chars().all(|c| c.is_ascii_digit())
        || !fraction.chars().all(|c| c.is_ascii_digit())
    {
        return Err(format!("price {text:?} is not a decimal number"));
    }
    if fraction.len() > decimals as usize {
        return Err(format!(
            "price {text:?} has {} decimal places but this mint has only {decimals}",
            fraction.len()
        ));
    }

    let whole_units: u64 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| format!("price {text:?} is too large"))?
    };
    let scale = 10u64
        .checked_pow(decimals as u32)
        .ok_or_else(|| format!("a mint with {decimals} decimals is not representable"))?;
    let mut base = whole_units
        .checked_mul(scale)
        .ok_or_else(|| format!("price {text:?} overflows in base units"))?;

    if !fraction.is_empty() {
        // Right-pad so "10.5" and "10.500000" mean the same thing.
        let mut padded = fraction.to_string();
        padded.push_str(&"0".repeat(decimals as usize - fraction.len()));
        let frac_units: u64 = padded
            .parse()
            .map_err(|_| format!("price {text:?} has an unparseable fraction"))?;
        base = base
            .checked_add(frac_units)
            .ok_or_else(|| format!("price {text:?} overflows in base units"))?;
    }

    Ok(base)
}

/// Where money goes and what it is denominated in.
///
/// Every field is operator-set. There is no default merchant address by
/// design: a shop that has not been told where to receive payment must
/// refuse to quote, never invent a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShopConfig {
    /// The wallet that receives payment. Pinned in config, never model
    /// generated, and never accepted from tool arguments.
    pub merchant_address: String,
    /// The settlement mint, usually a stablecoin.
    pub mint: String,
    /// Decimals of that mint, needed to turn prices into base units.
    pub decimals: u8,
    /// Which terminal this agent instance is, one through ninety nine.
    pub sales_point: u8,
    /// How long a quote stays payable.
    pub quote_ttl_secs: u32,
}

/// Default quote lifetime: fifteen minutes. Long enough for a customer
/// to open a wallet and pay, short enough to bound exposure to the rate
/// moving when a shop prices in a local currency.
pub const DEFAULT_QUOTE_TTL_SECS: u32 = 900;

impl ShopConfig {
    /// Read shop settings from the jailed config section.
    ///
    /// Keys: `merchant_address`, `mint`, `mint_decimals`, `sales_point`,
    /// and optionally `quote_ttl_secs`. Everything but the TTL is
    /// required, because there is no safe guess for any of them.
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        let merchant_address = required(section, "merchant_address")?;
        validate_pubkey(&merchant_address).map_err(|e| {
            format!("configured merchant_address is not a valid Solana address: {e}")
        })?;

        let mint = required(section, "mint")?;
        validate_pubkey(&mint)
            .map_err(|e| format!("configured mint is not a valid Solana address: {e}"))?;

        let decimals: u8 = required(section, "mint_decimals")?
            .parse()
            .map_err(|_| "mint_decimals must be an integer from 0 to 255".to_string())?;
        // Tagging spends four digits below the price, so a mint without
        // that much precision cannot carry a tag at all.
        if (decimals as u32) < 4 {
            return Err(format!(
                "this mint has {decimals} decimals, but payment tagging needs at least 4 \
                 digits below the price to identify the sales point and order"
            ));
        }

        let sales_point: u8 = required(section, "sales_point")?
            .parse()
            .map_err(|_| "sales_point must be an integer".to_string())?;
        if !(crate::quote::MIN_SALES_POINT..=crate::quote::MAX_SALES_POINT)
            .contains(&sales_point)
        {
            return Err(format!(
                "sales_point {sales_point} is outside {} to {}",
                crate::quote::MIN_SALES_POINT,
                crate::quote::MAX_SALES_POINT
            ));
        }

        let quote_ttl_secs = section
            .get("quote_ttl_secs")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_QUOTE_TTL_SECS);

        Ok(Self {
            merchant_address,
            mint,
            decimals,
            sales_point,
            quote_ttl_secs,
        })
    }
}

/// Fetch a required key, with a message naming what the operator must set.
fn required(section: &HashMap<String, String>, key: &str) -> Result<String, String> {
    section
        .get(key)
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("required config key {key} is not set"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MERCHANT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn catalog_json() -> String {
        serde_json::json!([
            {"sku": "RICE-5KG", "name": "Rice 5kg", "price": "10.00"},
            {"sku": "OIL-1L", "name": "Cooking oil 1L", "price": "3.50"}
        ])
        .to_string()
    }

    fn shop_section() -> HashMap<String, String> {
        HashMap::from([
            ("merchant_address".to_string(), MERCHANT.to_string()),
            ("mint".to_string(), USDC.to_string()),
            ("mint_decimals".to_string(), "6".to_string()),
            ("sales_point".to_string(), "3".to_string()),
            ("catalog".to_string(), catalog_json()),
        ])
    }

    #[test]
    fn parses_prices_without_floating_point_error() {
        assert_eq!(parse_decimal_amount("10.00", 6).unwrap(), 10_000_000);
        assert_eq!(parse_decimal_amount("10", 6).unwrap(), 10_000_000);
        assert_eq!(parse_decimal_amount("3.50", 6).unwrap(), 3_500_000);
        assert_eq!(parse_decimal_amount("0.01", 6).unwrap(), 10_000);
        // The classic float trap: 10.10 is not exact in binary.
        assert_eq!(parse_decimal_amount("10.10", 6).unwrap(), 10_100_000);
        assert_eq!(parse_decimal_amount("0.1", 6).unwrap(), 100_000);
    }

    #[test]
    fn rejects_malformed_prices() {
        assert!(parse_decimal_amount("", 6).is_err());
        assert!(parse_decimal_amount("-5.00", 6).is_err());
        assert!(parse_decimal_amount("ten", 6).is_err());
        assert!(parse_decimal_amount("1.2.3", 6).is_err());
        // More precision than the mint has.
        assert!(parse_decimal_amount("1.0000001", 6).is_err());
    }

    #[test]
    fn loads_a_catalog_and_resolves_by_sku() {
        let catalog = Catalog::from_section(&shop_section(), 6).unwrap();
        assert_eq!(catalog.items().len(), 2);
        let item = catalog.resolve("RICE-5KG").unwrap();
        assert_eq!(item.unit_price_base_units, 10_000_000);
        assert_eq!(item.name, "Rice 5kg");
    }

    #[test]
    fn sku_matching_ignores_case_but_not_spelling() {
        let catalog = Catalog::from_section(&shop_section(), 6).unwrap();
        assert!(catalog.resolve("rice-5kg").is_ok());
        // A near miss must fail rather than resolve to something else.
        let err = catalog.resolve("RICE").unwrap_err();
        assert!(err.contains("no catalog item"), "{err}");
        assert!(err.contains("RICE-5KG"), "error lists real skus: {err}");
    }

    #[test]
    fn a_missing_catalog_fails_closed() {
        let err = Catalog::from_section(&HashMap::new(), 6).unwrap_err();
        assert!(err.contains("no catalog configured"), "{err}");
    }

    #[test]
    fn an_empty_catalog_is_refused() {
        let section = HashMap::from([("catalog".to_string(), "[]".to_string())]);
        assert!(Catalog::from_section(&section, 6).is_err());
    }

    #[test]
    fn prices_finer_than_a_cent_are_refused_at_load_time() {
        let section = HashMap::from([(
            "catalog".to_string(),
            serde_json::json!([{"sku": "X", "name": "X", "price": "10.000001"}]).to_string(),
        )]);
        let err = Catalog::from_section(&section, 6).unwrap_err();
        assert!(err.contains("whole cents"), "{err}");
    }

    #[test]
    fn duplicate_skus_are_refused() {
        let section = HashMap::from([(
            "catalog".to_string(),
            serde_json::json!([
                {"sku": "X", "name": "One", "price": "1.00"},
                {"sku": "x", "name": "Two", "price": "2.00"}
            ])
            .to_string(),
        )]);
        let err = Catalog::from_section(&section, 6).unwrap_err();
        assert!(err.contains("more than once"), "{err}");
    }

    #[test]
    fn shop_config_reads_every_required_field() {
        let cfg = ShopConfig::from_section(&shop_section()).unwrap();
        assert_eq!(cfg.merchant_address, MERCHANT);
        assert_eq!(cfg.mint, USDC);
        assert_eq!(cfg.decimals, 6);
        assert_eq!(cfg.sales_point, 3);
        assert_eq!(cfg.quote_ttl_secs, DEFAULT_QUOTE_TTL_SECS);
    }

    #[test]
    fn shop_config_fails_closed_on_a_missing_merchant_address() {
        let mut section = shop_section();
        section.remove("merchant_address");
        let err = ShopConfig::from_section(&section).unwrap_err();
        assert!(err.contains("merchant_address"), "{err}");
    }

    #[test]
    fn shop_config_rejects_a_merchant_address_that_is_not_an_address() {
        let mut section = shop_section();
        section.insert(
            "merchant_address".to_string(),
            "pay-me-here-please".to_string(),
        );
        let err = ShopConfig::from_section(&section).unwrap_err();
        assert!(err.contains("not a valid Solana address"), "{err}");
    }

    #[test]
    fn shop_config_rejects_a_mint_too_coarse_to_carry_a_tag() {
        let mut section = shop_section();
        section.insert("mint_decimals".to_string(), "2".to_string());
        let err = ShopConfig::from_section(&section).unwrap_err();
        assert!(err.contains("at least 4"), "{err}");
    }

    #[test]
    fn shop_config_rejects_an_out_of_range_sales_point() {
        for bad in ["0", "100"] {
            let mut section = shop_section();
            section.insert("sales_point".to_string(), bad.to_string());
            assert!(ShopConfig::from_section(&section).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn quote_ttl_override_is_honored_and_nonsense_falls_back() {
        let mut section = shop_section();
        section.insert("quote_ttl_secs".to_string(), "300".to_string());
        assert_eq!(ShopConfig::from_section(&section).unwrap().quote_ttl_secs, 300);
        for bad in ["0", "soon"] {
            let mut section = shop_section();
            section.insert("quote_ttl_secs".to_string(), bad.to_string());
            assert_eq!(
                ShopConfig::from_section(&section).unwrap().quote_ttl_secs,
                DEFAULT_QUOTE_TTL_SECS
            );
        }
    }
}
