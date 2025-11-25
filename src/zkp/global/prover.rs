//! Global root proof generation
//!
//! This module provides functions for generating zero-knowledge proofs
//! for global root composition from subtree roots.

use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;

use crate::global::commitment::{compose_to_global_root, SubtreeRoot};
use crate::zkp::global::air::GlobalRootCompositionAir;
use crate::zkp::global::trace::build_global_trace;
use crate::zkp::prover_common::prove_with_commitment;
use crate::zkp::types::{Proof, StarkConfig, Val};
use crate::Result;

/// Generate a proof for global root composition
///
/// This function proves that multiple subtree roots compose correctly into a global root
/// following the Sparse Merkle Tree (SMT) structure with Poseidon2 hashing.
///
/// # Arguments
/// * `config` - Proof system configuration (`StarkConfig`)
/// * `subtrees` - Slice of subtree roots to compose
///
/// # Returns
/// A proof for the global root composition
pub fn prove_global_root_composition(
    config: &StarkConfig,
    subtrees: &[SubtreeRoot],
) -> Result<Proof> {
    let trace = build_global_trace(subtrees)?;
    let global_root = compose_to_global_root(subtrees)?;
    let air = GlobalRootCompositionAir::new();

    prove_with_commitment(
        config,
        trace,
        |trace| {
            if trace.height() == 0 {
                // Empty case: return zero root
                Ok(vec![Val::ZERO; 8])
            } else {
                // Extract the final composed root from the first row (depth 0 is the root)
                let first_row = trace.row_slice(0).expect("Trace must have first row");
                use crate::zkp::global::poseidon2_air::column_offsets;
                let mut root_fields = vec![Val::ZERO; 8];
                for (i, j) in (column_offsets::COMPOSED_ROOT_START
                    ..column_offsets::COMPOSED_ROOT_END)
                    .enumerate()
                {
                    root_fields[i] = first_row[j];
                }
                Ok(root_fields)
            }
        },
        global_root,
        [0u8; 32], // No wallet_id for global root
        &air,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::global::commitment::compute_subtree_root;
    use crate::zkp::types::create_config;

    #[test]
    fn test_prove_global_root_composition() {
        let config = create_config().expect("Should create config");

        let empty_result = prove_global_root_composition(&config, &[]);

        assert!(empty_result.is_ok());

        let mut wallet_commitments = BTreeMap::new();
        let wallet_id = [1u8; 32];
        wallet_commitments.insert(wallet_id, [2u8; 32]);
        let subtree = compute_subtree_root(&config, &wallet_commitments, wallet_id, wallet_id)
            .expect("Should compute subtree");

        let non_empty_result = prove_global_root_composition(&config, &[subtree]);

        assert!(non_empty_result.is_ok());
    }
}
