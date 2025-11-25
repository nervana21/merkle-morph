//! Poseidon2 AIR integration for global root composition verification
//!
//! This module provides the infrastructure for full in-circuit Poseidon2 hash verification.
//! It implements Poseidon2 AIR columns and constraints for verifying global root composition
//! through Sparse Merkle Tree (SMT) internal node hashing.
//!
//! ## Architecture
//!
//! The module verifies Poseidon2 hash computations for SMT internal nodes:
//! - Internal node hashing: `hash = poseidon2("MM_GLOBAL_v0" || left || right)`
//! - Each Poseidon2 computation requires Poseidon2 AIR columns for intermediate states,
//!   which are included in the trace structure.

// Re-export for convenience
pub(crate) use crate::zkp::poseidon2_common::create_poseidon2_constants_and_params;
use crate::zkp::poseidon2_common::{
    create_poseidon2_air as create_common_poseidon2_air, CommonPoseidon2Air,
};

/// Poseidon2 AIR type for global root composition
pub(super) type GlobalPoseidon2Air = CommonPoseidon2Air;

/// Create Poseidon2 AIR instance for global root composition
pub(super) fn create_poseidon2_air() -> GlobalPoseidon2Air { create_common_poseidon2_air() }

/// Get the total number of columns per row in a global trace
/// This is useful for benchmarking and understanding trace dimensions
pub fn global_trace_cols() -> usize { column_offsets::total_cols() }

/// Column offsets for Poseidon2 AIR columns in the global trace
///
/// The trace structure represents SMT composition level by level:
/// - Each row contains:
///   - Columns 0-7: left_subtree_root (8 fields)
///   - Columns 8-15: right_subtree_root (8 fields)
///   - Columns 16-23: composed_root (8 fields)
///   - Columns 24+: Poseidon2 AIR columns for internal node computation
pub(super) mod column_offsets {
    use crate::zkp::poseidon2_common::poseidon2_air_num_cols;

    /// Column offsets within a row (same for all rows)
    pub(crate) const LEFT_ROOT_START: usize = 0;
    pub(crate) const LEFT_ROOT_END: usize = 8;
    pub(crate) const RIGHT_ROOT_START: usize = 8;
    pub(crate) const RIGHT_ROOT_END: usize = 16;
    pub(crate) const COMPOSED_ROOT_START: usize = 16;
    pub(crate) const COMPOSED_ROOT_END: usize = 24;
    pub(crate) const INTERNAL_NODE_POSEIDON2_START: usize = 24;

    /// Number of Poseidon2 permutations needed for internal node hashing
    /// Input: MM_GLOBAL_v0 (13 bytes) + left (32 bytes) + right (32 bytes) = 77 bytes
    /// With RATE = 8 (32 bytes per permutation): 32 + 32 + 13 = 3 permutations
    pub(crate) const INTERNAL_NODE_PERMUTATIONS: usize = 3;

    /// Total number of columns per row
    pub(crate) fn total_cols() -> usize {
        let poseidon2_cols = poseidon2_air_num_cols();
        // Base columns: left_root (8) + right_root (8) + composed_root (8) = 24
        // Plus Poseidon2 trace for internal node (3 permutations)
        const BASE_COLS: usize = 24;
        BASE_COLS + INTERNAL_NODE_PERMUTATIONS * poseidon2_cols
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::poseidon2_common::poseidon2_air_num_cols;

    #[test]
    fn test_global_trace_cols() {
        let poseidon2_cols = poseidon2_air_num_cols();
        let expected = 24 + 3 * poseidon2_cols;

        assert_eq!(global_trace_cols(), expected);
    }
}
