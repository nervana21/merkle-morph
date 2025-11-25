//! Anchor output helpers for channel transactions
//!
//! This module provides helper functions for constructing BOLT3-style
//! anchor outputs using the P2A (pay-to-anchor) address type from
//! `rust-bitcoin`. Anchor outputs allow child transactions to \"bring
//! their own fees\" instead of requiring a static reserve in the
//! channel balance.

use bitcoin::script::ScriptBuf as ScriptPubKeyBuf;
use bitcoin::{Amount, TxOut};

/// Default anchor output value in satoshis.
///
/// BOLT3 specifies anchor outputs that are small (just large enough
/// to be economical to sweep when fee rates decrease). Implementations
/// typically use values around 330 sats; we choose a small fixed value
/// here as a placeholder.
///
/// In a production deployment this should be wired to a policy module
/// that takes fee rates and dust limits into account.
pub const DEFAULT_ANCHOR_VALUE_SATS: u64 = 330;

/// Builds a P2A (pay-to-anchor) script_pubkey.
///
/// This uses `ScriptPubKeyBuf::new_p2a()` from `rust-bitcoin`, which
/// encodes the standard anchor witness program (version 1, program
/// bytes `[0x4e, 0x73]`).
pub fn build_anchor_script() -> ScriptPubKeyBuf { ScriptPubKeyBuf::new_p2a() }

/// Builds a P2A (pay-to-anchor) output with the default value.
pub fn build_anchor_output_default() -> TxOut {
    TxOut {
        value: Amount::from_sat(DEFAULT_ANCHOR_VALUE_SATS),
        script_pubkey: build_anchor_script(),
    }
}

/// Builds a P2A (pay-to-anchor) output with a custom value.
pub fn build_anchor_output(value_sats: u64) -> TxOut {
    TxOut { value: Amount::from_sat(value_sats), script_pubkey: build_anchor_script() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_anchor_script() {
        let script = build_anchor_script();
        let bytes = script.as_bytes();

        assert_eq!(bytes[0], 0x51);
        assert_eq!(bytes[1], 0x02);
        assert_eq!(bytes[2], 0x4e);
        assert_eq!(bytes[3], 0x73);
    }

    #[test]
    fn test_build_anchor_output_default() {
        let output = build_anchor_output_default();

        assert_eq!(output.value.to_sat(), DEFAULT_ANCHOR_VALUE_SATS);
    }

    #[test]
    fn test_build_anchor_output() {
        let value_sats = 1000u64;
        let output = build_anchor_output(value_sats);

        assert_eq!(output.value.to_sat(), value_sats);
    }
}
