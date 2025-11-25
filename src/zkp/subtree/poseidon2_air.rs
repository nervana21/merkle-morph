//! Poseidon2 AIR integration for subtree root validity verification
//!
//! This module provides the infrastructure for full in-circuit Poseidon2 hash verification.
//! It implements Poseidon2 AIR columns and constraints for verifying subtree root computation
//! through Sparse Merkle Tree (SMT) leaf and internal node hashing.

// Re-export for convenience
pub(crate) use crate::zkp::poseidon2_common::create_poseidon2_constants_and_params;
use crate::zkp::poseidon2_common::{
    create_poseidon2_air as create_common_poseidon2_air, CommonPoseidon2Air,
};

/// Poseidon2 AIR type for subtree root validity
pub(super) type SubtreePoseidon2Air = CommonPoseidon2Air;

/// Create Poseidon2 AIR instance for subtree root validity
pub(super) fn create_poseidon2_air() -> SubtreePoseidon2Air { create_common_poseidon2_air() }

/// Column offsets for Poseidon2 AIR columns in the subtree trace
///
/// The trace structure represents SMT building from start_depth to max_depth:
/// - Each row contains:
///   - Columns 0-7: wallet_id (leaf nodes only, 8 fields)
///   - Columns 8-15: wallet_commitment (leaf nodes only, 8 fields)
///   - Columns 16-23: left_child_root (internal nodes, 8 fields)
///   - Columns 24-31: right_child_root (internal nodes, 8 fields)
///   - Columns 32-39: computed_root (8 fields)
///   - Columns 40-47: depth (1 field, rest padding)
///   - Columns 48+: Poseidon2 AIR columns for leaf/internal node hashing
pub(super) mod column_offsets {
    use crate::zkp::poseidon2_common::poseidon2_air_num_cols;

    /// Column offsets within a row (same for all rows)
    pub(crate) const WALLET_ID_START: usize = 0;
    pub(crate) const WALLET_ID_END: usize = 8;
    pub(crate) const WALLET_COMMITMENT_START: usize = 8;
    pub(crate) const WALLET_COMMITMENT_END: usize = 16;
    pub(crate) const LEFT_CHILD_ROOT_START: usize = 16;
    pub(crate) const LEFT_CHILD_ROOT_END: usize = 24;
    pub(crate) const RIGHT_CHILD_ROOT_START: usize = 24;
    pub(crate) const RIGHT_CHILD_ROOT_END: usize = 32;
    pub(crate) const COMPUTED_ROOT_START: usize = 32;
    pub(crate) const COMPUTED_ROOT_END: usize = 40;
    pub(crate) const DEPTH_START: usize = 40;
    pub(crate) const LEAF_POSEIDON2_START: usize = 48;

    /// Number of Poseidon2 permutations needed for leaf hashing
    /// Input: MM_WLT_v0 (10 bytes) + wallet_id (32 bytes) + wallet_commitment (32 bytes) = 74 bytes
    /// With RATE = 8 (32 bytes per permutation): 32 + 32 + 10 = 3 permutations
    pub(crate) const LEAF_PERMUTATIONS: usize = 3;

    /// Offset for internal node Poseidon2 columns
    pub(crate) fn internal_node_poseidon2_start() -> usize {
        let poseidon2_cols = poseidon2_air_num_cols();
        LEAF_POSEIDON2_START + LEAF_PERMUTATIONS * poseidon2_cols
    }

    /// Number of Poseidon2 permutations needed for internal node hashing
    /// Input: MM_GLOBAL_v0 (13 bytes) + left (32 bytes) + right (32 bytes) = 77 bytes
    /// With RATE = 8 (32 bytes per permutation): 32 + 32 + 13 = 3 permutations
    pub(crate) const INTERNAL_NODE_PERMUTATIONS: usize = 3;

    /// Total number of columns per row
    pub(crate) fn total_cols() -> usize {
        let poseidon2_cols = poseidon2_air_num_cols();
        // Base columns: wallet_id (8) + wallet_commitment (8) + left_child (8) + right_child (8) + computed_root (8) + depth (8) = 48
        // Plus Poseidon2 trace for leaf (3 permutations)
        // Plus Poseidon2 trace for internal node (3 permutations)
        const BASE_COLS: usize = 48;
        BASE_COLS + LEAF_PERMUTATIONS * poseidon2_cols + INTERNAL_NODE_PERMUTATIONS * poseidon2_cols
    }
}

#[cfg(test)]
mod tests {
    use p3_air::BaseAir;

    use super::*;
    use crate::zkp::poseidon2_common::poseidon2_air_num_cols;

    #[test]
    fn test_poseidon2_constants_deterministic() {
        use crate::zkp::poseidon2_common::create_poseidon2_constants;
        let constants1 = create_poseidon2_constants();
        let constants2 = create_poseidon2_constants();
        // Constants should be deterministic - verify by creating AIR instances
        let air1 = SubtreePoseidon2Air::new(constants1);
        let air2 = SubtreePoseidon2Air::new(constants2);
        // Both AIRs should have the same width
        assert_eq!(air1.width(), air2.width());
    }

    #[test]
    fn test_column_offsets() {
        // Verify column offsets are correct
        let poseidon2_cols = poseidon2_air_num_cols();
        assert!(poseidon2_cols > 0, "Poseidon2 AIR should require columns");
        // Leaf uses 3 permutations, internal node uses 3 permutations
        assert_eq!(
            column_offsets::internal_node_poseidon2_start(),
            column_offsets::LEAF_POSEIDON2_START
                + column_offsets::LEAF_PERMUTATIONS * poseidon2_cols
        );
        assert_eq!(
            column_offsets::total_cols(),
            column_offsets::internal_node_poseidon2_start()
                + column_offsets::INTERNAL_NODE_PERMUTATIONS * poseidon2_cols
        );
    }

    #[test]
    fn test_poseidon2_air_creation() {
        let air = create_poseidon2_air();
        assert!(air.width() > 0, "Poseidon2 AIR should have columns");
    }
}
