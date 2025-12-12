// SPDX-License-Identifier: CC0-1.0

//! Proof aggregation across partitions.
//!
//! This module provides the `PartitionProofAggregator` for aggregating proofs
//! from individual partitions. It verifies each partition proof against its
//! partition root, constructs SubtreeRoot objects from the partition roots,
//! and generates a composition proof that these partition roots compose to the
//! global root. The aggregated proof is then verified to ensure it matches the
//! expected global root.

use crate::global::commitment::types::GlobalRoot;
use crate::scheduler::partition::types::PartitionRoot;
use crate::zkp::global::{prove_global_root_composition, verify_global_root_composition};
use crate::{Proof, Result, StarkConfig, SubtreeRoot};

/// Aggregator for partition proofs.
pub struct PartitionProofAggregator;

impl PartitionProofAggregator {
    /// Aggregate proofs from multiple partitions into a single proof.
    ///
    /// This function:
    /// 1. Verifies each partition proof against its corresponding partition root
    /// 2. Creates SubtreeRoot objects from the partition roots
    /// 3. Generates a composition proof that these partition roots compose to the global root
    ///
    /// # Arguments
    /// * `config` - STARK configuration for proof generation and verification
    /// * `partition_roots` - Vector of partition roots to compose
    /// * `partition_proofs` - Vector of proofs from individual partitions verifying each root
    /// * `global_root` - The target global root that partition roots should compose to
    ///
    /// # Returns
    /// The aggregated proof that attests to the global root composition
    pub fn aggregate_partition_proofs(
        config: &StarkConfig,
        partition_roots: &[PartitionRoot],
        partition_proofs: Vec<Proof>,
        global_root: GlobalRoot,
    ) -> Result<Proof> {
        if partition_proofs.is_empty() {
            return Err(crate::errors::GlobalError::Internal(
                "no partition proofs to aggregate".into(),
            )
            .into());
        }

        if partition_proofs.len() != partition_roots.len() {
            return Err(crate::errors::GlobalError::Internal(format!(
                "partition_proofs.len() ({}) != partition_roots.len() ({})",
                partition_proofs.len(),
                partition_roots.len()
            ))
            .into());
        }

        // Verify each partition proof against its partition root
        for (proof, &expected_root) in partition_proofs.iter().zip(partition_roots.iter()) {
            verify_global_root_composition(config, expected_root, proof)?;
        }

        // Create SubtreeRoot objects from partition roots
        // We use sequential wallet ID ranges based on partition index to ensure
        // proper ordering in the composition. The start_depth is 0 since we're
        // treating partition roots as top-level subtrees.
        // Use single-wallet ranges (min_id == max_id) to match how partition roots
        // are typically computed from single-wallet subtrees.
        let subtrees: Vec<SubtreeRoot> = partition_roots
            .iter()
            .enumerate()
            .map(|(idx, &root)| {
                // Create a single-wallet ID range for this partition
                // Using the partition index as the first byte, with all other bytes set to 0
                // This creates distinct single-wallet ranges that match typical partition root usage
                let mut wallet_id = [0u8; 32];
                wallet_id[0] = idx as u8;
                // Use same ID for min and max to create a single-wallet range
                let min_id = wallet_id;
                let max_id = wallet_id;

                SubtreeRoot {
                    root,
                    wallet_id_range: (min_id, max_id),
                    start_depth: 0,       // Partition roots are treated as top-level
                    validity_proof: None, // We've already verified the partition proofs above
                }
            })
            .collect();

        // Sort subtrees by wallet_id_range to ensure consistent composition
        // This matches how compose_to_global_root expects subtrees to be ordered
        let mut sorted_subtrees = subtrees.clone();
        sorted_subtrees.sort_by_key(|s| s.wallet_id_range.0);

        // Generate aggregated proof that partition roots compose to global root
        // First, compute what global root the synthetic subtrees would produce
        use crate::global::commitment::compose_to_global_root as compute_global;
        let computed_global_from_synthetic = compute_global(&sorted_subtrees)?;
        // Verify that the computed global root matches the expected one
        if computed_global_from_synthetic != global_root {
            return Err(crate::errors::GlobalError::Internal(format!(
                "Computed global root from synthetic subtrees ({:?}) does not match expected global root ({:?})",
                computed_global_from_synthetic, global_root
            ))
            .into());
        }
        let aggregated_proof = prove_global_root_composition(config, &sorted_subtrees)?;

        // Verify the aggregated proof against the global root
        verify_global_root_composition(config, global_root, &aggregated_proof)?;

        Ok(aggregated_proof)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::global::commitment::{compose_to_global_root, compute_subtree_root};
    use crate::zkp::global::prove_global_root_composition;
    use crate::zkp::types::create_config;

    #[test]
    fn test_aggregate_partition_proofs() {
        let config = create_config().expect("should create config");

        let empty_result = PartitionProofAggregator::aggregate_partition_proofs(
            &config,
            &[],
            Vec::new(),
            [0u8; 32],
        );
        assert!(empty_result.is_err());

        // Use wallet IDs that match the synthetic ranges created by aggregate_partition_proofs
        // Partition 0 uses range starting with 0, partition 1 uses range starting with 1
        let mut wallet_id_1 = [0u8; 32];
        wallet_id_1[0] = 0;
        let mut wallet_id_2 = [0u8; 32];
        wallet_id_2[0] = 1;

        let mut wallet_commitments_1 = BTreeMap::new();
        wallet_commitments_1.insert(wallet_id_1, [2u8; 32]);
        let subtree_1 =
            compute_subtree_root(&config, &wallet_commitments_1, wallet_id_1, wallet_id_1)
                .expect("should compute subtree");
        let partition_root_1 = subtree_1.root;
        let partition_proof_1a =
            prove_global_root_composition(&config, std::slice::from_ref(&subtree_1))
                .expect("should generate proof");
        let partition_proof_1b =
            prove_global_root_composition(&config, std::slice::from_ref(&subtree_1))
                .expect("should generate proof");

        let length_mismatch_result = PartitionProofAggregator::aggregate_partition_proofs(
            &config,
            &[partition_root_1],
            vec![partition_proof_1a, partition_proof_1b],
            [0u8; 32],
        );

        assert!(length_mismatch_result.is_err());

        let mut wallet_commitments_2 = BTreeMap::new();
        wallet_commitments_2.insert(wallet_id_2, [4u8; 32]);
        let subtree_2 =
            compute_subtree_root(&config, &wallet_commitments_2, wallet_id_2, wallet_id_2)
                .expect("should compute subtree");
        let partition_root_2 = subtree_2.root;
        let partition_proof_2 =
            prove_global_root_composition(&config, std::slice::from_ref(&subtree_2))
                .expect("should generate proof");

        let _partition_proof_1_for_wrong =
            prove_global_root_composition(&config, std::slice::from_ref(&subtree_1))
                .expect("should generate proof");

        let wrong_proof_result = PartitionProofAggregator::aggregate_partition_proofs(
            &config,
            &[partition_root_1],
            vec![partition_proof_2],
            [0u8; 32],
        );

        assert!(wrong_proof_result.is_err());

        let subtrees = vec![subtree_1.clone(), subtree_2.clone()];
        let global_root = compose_to_global_root(&subtrees).expect("should compose to global root");
        let wrong_global_root = [0xFFu8; 32];

        let partition_proof_1_for_final =
            prove_global_root_composition(&config, std::slice::from_ref(&subtree_1))
                .expect("should generate proof");
        let partition_proof_2_for_final =
            prove_global_root_composition(&config, std::slice::from_ref(&subtree_2))
                .expect("should generate proof");
        let final_verification_failure_result =
            PartitionProofAggregator::aggregate_partition_proofs(
                &config,
                &[partition_root_1, partition_root_2],
                vec![partition_proof_1_for_final, partition_proof_2_for_final],
                wrong_global_root,
            );
        assert!(final_verification_failure_result.is_err());

        let partition_proof_1_success =
            prove_global_root_composition(&config, std::slice::from_ref(&subtree_1))
                .expect("should generate proof");
        let partition_proof_2_success =
            prove_global_root_composition(&config, std::slice::from_ref(&subtree_2))
                .expect("should generate proof");

        let success_result = PartitionProofAggregator::aggregate_partition_proofs(
            &config,
            &[partition_root_1, partition_root_2],
            vec![partition_proof_1_success, partition_proof_2_success],
            global_root,
        );

        if let Err(e) = &success_result {
            panic!("Expected success but got error: {:?}", e);
        }
    }
}
