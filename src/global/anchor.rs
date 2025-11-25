//! Bitcoin anchoring for global state
//!
//! This module provides the interface and types for anchoring global state
//! roots to Bitcoin. Bitcoin anchoring provides:
//! - Global ordering and timestamping
//! - Double-spending prevention
//! - Canonical state for dispute resolution

use crate::types::{
    Bytes32, OP_RETURN_MAGIC_BYTES, OP_RETURN_NONCE_LEN, OP_RETURN_OFFSET_GLOBAL_ROOT,
    OP_RETURN_OFFSET_MAGIC, OP_RETURN_OFFSET_NONCE, OP_RETURN_OFFSET_VERSION, OP_RETURN_TOTAL_LEN,
    OP_RETURN_VERSION,
};

/// Bitcoin anchor structure
///
/// Bitcoin anchor information for a global state root. Anchors provide global ordering,
/// timestamping, and canonical state for dispute resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinAnchor {
    /// The global root that was anchored
    pub global_root: Bytes32,
    /// Bitcoin transaction ID (32 bytes, little-endian)
    pub txid: Bytes32,
    /// Block height when anchored
    pub block_height: u32,
    /// Block hash containing the transaction
    pub block_hash: Bytes32,
    /// Nonce for this anchor
    pub nonce: u32,
}

/// Result of attempting to anchor a global root to Bitcoin
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorResult {
    /// Successfully anchored to Bitcoin
    Anchored(BitcoinAnchor),
    /// Failed to anchor (e.g., network error, insufficient fees, or not yet confirmed)
    Failed {
        /// The global root that failed to anchor
        global_root: Bytes32,
        /// Error message
        error: String,
    },
}

/// Trait for Bitcoin anchoring operations
///
/// Implementations of this trait handle the actual Bitcoin transaction
/// creation and broadcasting.
///
/// Implementations can leverage backend abstraction patterns to support
/// multiple Bitcoin backends (RPC clients, libraries, etc.) without code
/// duplication. For example:
///
/// ```rust,no_run
/// use merkle_morph::global::anchor::{BitcoinAnchoring, AnchorResult};
/// use merkle_morph::types::Bytes32;
///
/// struct ExampleAnchoring {
///     // Example implementation fields
/// }
///
/// impl BitcoinAnchoring for ExampleAnchoring {
///     fn anchor_global_root(
///         &mut self,
///         global_root: Bytes32,
///         nonce: u32,
///     ) -> Result<AnchorResult, String> {
///         // Implementation would create and broadcast Bitcoin transaction here
///         // For example: use a Bitcoin RPC client to create raw transaction
///         Err("Not implemented".to_string())
///     }
///
///     fn get_latest_anchor(&self) -> Option<merkle_morph::global::anchor::BitcoinAnchor> {
///         None
///     }
///
///     fn verify_against_anchor(&self, _global_root: Bytes32) -> Result<bool, String> {
///         Ok(false)
///     }
/// }
/// ```
pub trait BitcoinAnchoring {
    /// Anchor a global root to the Bitcoin blockchain via OP_RETURN
    ///
    /// # Arguments
    /// * `global_root` - The global wallets root to anchor
    /// * `nonce` - Nonce for this anchor
    ///
    /// # Returns
    /// * `Ok(AnchorResult::Anchored)` - Successfully anchored and confirmed in a block
    /// * `Ok(AnchorResult::Failed)` - Failed to anchor (not confirmed, network error, etc.)
    /// * `Err` - Error during anchoring process
    fn anchor_global_root(
        &mut self,
        global_root: Bytes32,
        nonce: u32,
    ) -> Result<AnchorResult, String>;

    /// Get the latest anchored global root
    ///
    /// Returns the most recent Bitcoin-anchored global root, or None if
    /// no roots have been anchored yet.
    fn get_latest_anchor(&self) -> Option<BitcoinAnchor>;

    /// Verify that a global root matches the latest Bitcoin-anchored root
    ///
    /// This is used to ensure local state is consistent with the canonical
    /// Bitcoin-anchored state.
    fn verify_against_anchor(&self, global_root: Bytes32) -> Result<bool, String>;
}

/// Helper function to encode global root for OP_RETURN
pub fn encode_op_return_data(global_root: Bytes32, nonce: u32) -> Vec<u8> {
    let mut encoded_bytes = Vec::with_capacity(OP_RETURN_TOTAL_LEN);
    encoded_bytes.extend_from_slice(OP_RETURN_MAGIC_BYTES);
    encoded_bytes.push(OP_RETURN_VERSION);
    encoded_bytes.extend_from_slice(&global_root);
    encoded_bytes.extend_from_slice(&nonce.to_le_bytes());
    encoded_bytes
}

/// Helper function to decode OP_RETURN data back to global root and nonce
pub fn decode_op_return_data(encoded_bytes: &[u8]) -> Result<(Bytes32, u32), String> {
    if encoded_bytes.len() != OP_RETURN_TOTAL_LEN {
        return Err(format!(
            "OP_RETURN data must be exactly {} bytes, got {}",
            OP_RETURN_TOTAL_LEN,
            encoded_bytes.len()
        ));
    }

    if &encoded_bytes[OP_RETURN_OFFSET_MAGIC..OP_RETURN_OFFSET_VERSION] != OP_RETURN_MAGIC_BYTES {
        return Err("Invalid magic bytes".to_string());
    }

    let version = encoded_bytes[OP_RETURN_OFFSET_VERSION];
    if version != OP_RETURN_VERSION {
        return Err(format!("Unsupported version: {}", version));
    }

    let global_root: Bytes32 = encoded_bytes[OP_RETURN_OFFSET_GLOBAL_ROOT..OP_RETURN_OFFSET_NONCE]
        .try_into()
        .map_err(|_| "Invalid root bytes")?;

    let nonce_bytes: [u8; OP_RETURN_NONCE_LEN] = encoded_bytes
        [OP_RETURN_OFFSET_NONCE..OP_RETURN_OFFSET_NONCE + OP_RETURN_NONCE_LEN]
        .try_into()
        .map_err(|_| "Invalid nonce bytes")?;
    let nonce_u32 = u32::from_le_bytes(nonce_bytes);

    Ok((global_root, nonce_u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_op_return_data() {
        let global_root = [1u8; 32];
        let nonce = 21u32;

        let encoded = encode_op_return_data(global_root, nonce);

        assert_eq!(encoded.len(), OP_RETURN_TOTAL_LEN);
        assert_eq!(
            &encoded[OP_RETURN_OFFSET_MAGIC..OP_RETURN_OFFSET_VERSION],
            OP_RETURN_MAGIC_BYTES
        );
        assert_eq!(encoded[OP_RETURN_OFFSET_VERSION], OP_RETURN_VERSION);
        assert_eq!(&encoded[OP_RETURN_OFFSET_GLOBAL_ROOT..OP_RETURN_OFFSET_NONCE], &global_root);
        let decoded_nonce = u32::from_le_bytes(
            encoded[OP_RETURN_OFFSET_NONCE..OP_RETURN_OFFSET_NONCE + OP_RETURN_NONCE_LEN]
                .try_into()
                .expect("nonce slice should be exactly 4 bytes"),
        );
        assert_eq!(decoded_nonce, nonce);
    }

    #[test]
    fn test_decode_op_return_data() {
        let global_root = [2u8; 32];
        let nonce = 21u32;
        let encoded = encode_op_return_data(global_root, nonce);

        let decoded =
            decode_op_return_data(&encoded).expect("encoded data should decode successfully");

        assert_eq!(decoded.0, global_root);
        assert_eq!(decoded.1, nonce);

        let wrong_length = vec![0u8; OP_RETURN_TOTAL_LEN - 1];
        assert!(decode_op_return_data(&wrong_length).is_err());

        let mut wrong_magic = encoded.clone();
        wrong_magic[0] = 0xFF;
        assert!(decode_op_return_data(&wrong_magic).is_err());

        let mut wrong_version = encoded.clone();
        wrong_version[OP_RETURN_OFFSET_VERSION] = 0xFF;
        assert!(decode_op_return_data(&wrong_version).is_err());
    }
}
