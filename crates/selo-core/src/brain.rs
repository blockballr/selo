//! Selo Brain: business logic engine
//!
//! this module houses the core accounting state machine. it is designed
//! to be transport-agnostic, using the `RpcSeam` trait to interface with
//! the blockchain rather than hard-coded HTTP calls

use crate::RpcSeam;

/// native request struct for quoting
/// replacement for old WASM generator
pub struct QuoteArgs {
    pub sku: String,
    pub quantity: u32,
    pub now_unix: i64,
}

/// main entry.
/// pure and I/O-free. uses the `RpcSeam`
/// trait to handle network interactions if needed
pub fn action_quote<T: RpcSeam>(_rpc: &T, args: &QuoteArgs) -> Result<String, String> {
    //{logic here}
    Ok(format!("Quoting {}...", args.sku))
}
