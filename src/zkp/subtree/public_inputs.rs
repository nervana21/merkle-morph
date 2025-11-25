//! Subtree root public inputs for zero-knowledge proof verification
//!
//! This module defines the public inputs structure for subtree root validity proofs.

use crate::types::Bytes32;
use crate::zkp::types::bytes32_to_fields;
// use crate::zkp::poseidon2_common::POSEIDON2_OUTPUT_SIZE;

// Public value indices for subtree root validity proofs
// Public values layout: [subtree_root (8)]
pub(crate) const PUBLIC_SUBTREE_ROOT_START: usize = 0;

/// Subtree root public input type alias
///
/// Public input for subtree root validity proof verification. This is the subtree
/// root value that is committed in the proof. This value is revealed to the verifier
/// and must match what is attested in the zero-knowledge proof.
///
/// Note: min_id, max_id, and start_depth are not included in public inputs as they
/// are not verified in-circuit for performance reasons. They are only used during
/// trace generation to filter wallets and determine the starting depth.
///
/// Total: 8 field elements (subtree_root only)
pub type SubtreeRootPublicInput = Bytes32;

/// Build public values vector from subtree root public input
///
/// This function converts SubtreeRootPublicInput to field elements
/// and builds a public values vector suitable for proof verification.
///
/// # Arguments
/// * `subtree_root`: The subtree root public input
///
/// # Returns
/// A vector of field elements: [subtree_root (8)]
pub(crate) fn build_public_values(
    subtree_root: &SubtreeRootPublicInput,
) -> Vec<crate::zkp::types::Val> {
    let mut public_values = Vec::new();

    // Subtree root (8 fields)
    let root_fields = bytes32_to_fields(*subtree_root);
    public_values.extend(root_fields.iter().copied());

    public_values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_public_values() {
        let subtree_root: SubtreeRootPublicInput = [1u8; 32];

        let result = build_public_values(&subtree_root);

        assert_eq!(result.len(), 8);

        let root_fields = bytes32_to_fields(subtree_root);
        for (i, &expected) in root_fields.iter().enumerate() {
            assert_eq!(result[i], expected);
        }
    }
}
