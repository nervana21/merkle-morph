//! Global root proof generation
//!
//! This module provides functions for generating zero-knowledge proofs
//! for global root composition from subtree roots.

use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;

use crate::errors::Result;
use crate::global::commitment::{compose_to_global_root, SubtreeRoot};
use crate::zkp::global::air::GlobalRootCompositionAir;
use crate::zkp::global::trace::build_global_trace;
use crate::zkp::prover_common::prove_with_commitment;
use crate::zkp::types::{Proof, StarkConfig, Val};

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
    use crate::zkp::global::verifier::verify_global_root_composition;
    use crate::zkp::types::create_config;

    #[test]
    fn test_prove_global_root_composition_empty() {
        let config = create_config().expect("Should create config");
        let proof = prove_global_root_composition(&config, &[])
            .expect("Should generate proof for empty subtrees");

        let global_root = compose_to_global_root(&[]).expect("Should compute global root");

        verify_global_root_composition(&config, global_root, &proof)
            .expect("Should verify empty proof");
    }

    #[test]
    fn test_prove_global_root_composition_single_subtree() {
        let config = create_config().expect("Should create config");

        let mut commitments = BTreeMap::new();
        commitments.insert([1u8; 32], [2u8; 32]);
        let subtree = compute_subtree_root(&commitments, [1u8; 32], [1u8; 32])
            .expect("Should compute subtree");

        let proof = prove_global_root_composition(&config, std::slice::from_ref(&subtree))
            .expect("Should generate proof for single subtree");

        let global_root = compose_to_global_root(&[subtree]).expect("Should compute global root");

        verify_global_root_composition(&config, global_root, &proof)
            .expect("Should verify single subtree proof");
    }

    #[test]
    fn test_prove_global_root_composition_multiple_subtrees() {
        let config = create_config().expect("Should create config");

        let mut commitments1 = BTreeMap::new();
        commitments1.insert([1u8; 32], [2u8; 32]);
        let subtree1 = compute_subtree_root(&commitments1, [1u8; 32], [1u8; 32])
            .expect("Should compute subtree1");

        let mut commitments2 = BTreeMap::new();
        commitments2.insert([3u8; 32], [4u8; 32]);
        let subtree2 = compute_subtree_root(&commitments2, [3u8; 32], [3u8; 32])
            .expect("Should compute subtree2");

        let subtrees = vec![subtree1.clone(), subtree2.clone()];
        let proof = prove_global_root_composition(&config, &subtrees)
            .expect("Should generate proof for multiple subtrees");

        let global_root = compose_to_global_root(&subtrees).expect("Should compute global root");

        verify_global_root_composition(&config, global_root, &proof)
            .expect("Should verify multiple subtrees proof");
    }
}
