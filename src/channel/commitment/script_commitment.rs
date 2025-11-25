//! Script commitment computation
//!
//! This module provides functions for computing commitments related to
//! Bitcoin scripts used in channel transactions.
//!
//! Script commitments are used for binding channel states to specific
//! script paths in Taproot outputs.

use crate::types::{Bytes32, SCRIPT_DOMAIN_TAG};
use crate::zkp::poseidon2_hash_bytes;

/// Computes a commitment over a script
///
/// This function computes a commitment for script-related data using
/// Poseidon2 hashing with domain separation. The commitment is computed as:
/// `poseidon2(SCRIPT_DOMAIN_TAG || script_bytes)`
///
/// Uses domain separation tag `SCRIPT_DOMAIN_TAG` to prevent collisions
/// with other hash contexts.
///
/// # Arguments
/// * `script_bytes` - Script bytes to commit
///
/// # Returns
/// Script commitment
pub fn compute_script_commitment(script_bytes: &[u8]) -> Bytes32 {
    let mut input = Vec::new();
    input.extend_from_slice(SCRIPT_DOMAIN_TAG);
    input.extend_from_slice(script_bytes);
    poseidon2_hash_bytes(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_script_commitment() {
        let script_bytes = b"test_script";
        let result = compute_script_commitment(script_bytes);
        #[rustfmt::skip]
        assert_eq!(
            result,
            [
                0x18, 0x67, 0x31, 0x66, 0xbc, 0x2d, 0xf2, 0x2c,
                0xc1, 0xc0, 0x60, 0x4d, 0x08, 0x6a, 0x6a, 0x6a,
                0x91, 0xea, 0xa2, 0x75, 0xc9, 0xc5, 0x72, 0x07,
                0x66, 0xb9, 0xa8, 0x30, 0x79, 0x1e, 0x63, 0x23,
            ]
        );
    }
}
