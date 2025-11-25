// SPDX-License-Identifier: CC0-1.0

//! Commitment format for Merkle-Morph global root anchoring
//!
//! This module defines the canonical commitment format used to anchor
//! Merkle-Morph global roots to Bitcoin. The commitment is computed as:
//!
//! ```text
//! preimage = "MM_P2A_v0" || global_root || nonce
//! commitment_hash = SHA256(preimage)
//! ```
//!
//! This commitment hash matches the P2A taproot tweak calculation and can be
//! independently verified by third parties using only the global root, nonce,
//! and standard hash functions.

use bitcoin::hashes::sha256;

use crate::global::commitment::types::GlobalRoot;
use crate::types::{Bytes32, P2A_DOMAIN_TAG};

/// Domain separator for Merkle-Morph commitment
///
/// This matches the domain tag used in P2A taproot tweak calculation.
pub const MERKLE_MORPH_DOMAIN: &[u8] = P2A_DOMAIN_TAG;

/// Size of the commitment preimage in bytes
///
/// Calculated as: domain (9 bytes) + global_root (32 bytes) + nonce (4 bytes) = 45 bytes
const PREIMAGE_SIZE: usize = 45;

/// Compute the commitment preimage
///
/// The preimage is constructed as:
/// - Domain separator: "MM_P2A_v0" (9 bytes)
/// - Global root: 32 bytes
/// - Nonce: 4 bytes (little-endian u32)
///
/// Total: 45 bytes
///
/// # Arguments
/// * `global_root` - The Merkle-Morph global root (32 bytes)
/// * `nonce` - The nonce for this anchor (u32)
///
/// # Returns
/// The preimage as a byte vector (45 bytes)
pub fn compute_commitment_preimage(global_root: GlobalRoot, nonce: u32) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(PREIMAGE_SIZE);
    preimage.extend_from_slice(MERKLE_MORPH_DOMAIN);
    preimage.extend_from_slice(&global_root);
    preimage.extend_from_slice(&nonce.to_le_bytes());
    preimage
}

/// Compute the commitment hash from a global root and nonce
///
/// This is the canonical commitment hash that is embedded in Bitcoin
/// transactions. It can be independently verified by third parties.
///
/// # Arguments
/// * `global_root` - The Merkle-Morph global root (32 bytes)
/// * `nonce` - The nonce for this anchor (u32)
///
/// # Returns
/// The commitment hash (32 bytes, SHA256 of preimage)
pub fn compute_commitment_hash(global_root: GlobalRoot, nonce: u32) -> Bytes32 {
    let preimage = compute_commitment_preimage(global_root, nonce);
    sha256::Hash::hash(&preimage).to_byte_array()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_compute_commitment_preimage() {
        let global_root = [1u8; 32];
        let nonce = 42u32;

        let preimage = compute_commitment_preimage(global_root, nonce);

        assert_eq!(preimage.len(), 45);
        assert_eq!(&preimage[0..9], MERKLE_MORPH_DOMAIN);
        assert_eq!(&preimage[9..41], &global_root);
        assert_eq!(&preimage[41..45], &nonce.to_le_bytes());
    }

    #[test]
    fn test_compute_commitment_hash() {
        let global_root = [2u8; 32];
        let nonce = 100u32;

        let hash1 = compute_commitment_hash(global_root, nonce);

        let hash2 = compute_commitment_hash(global_root, nonce);

        assert_eq!(hash1, hash2);

        let preimage = compute_commitment_preimage(global_root, nonce);

        let expected_hash = sha256::Hash::hash(&preimage).to_byte_array();
        assert_eq!(hash1, expected_hash);
    }
}
