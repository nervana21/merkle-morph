// SPDX-License-Identifier: CC0-1.0

//! Global composition from partition-local batches.
//!
//! The [`GlobalComposer`] gathers `PartitionBatch` instances from all partitions and
//! computes a global root and batch number, producing a [`GlobalBatch`] for
//! verification and anchoring.
//!
//! # System Architecture Diagram
//!
//! ```text
//! +-----------------------------------------------------------------------------+
//! |                    PARTITIONING SYSTEM OVERVIEW                             |
//! +-----------------------------------------------------------------------------+
//!
//!     +--------------+    +--------------+    +--------------+    +--------------+
//!     |  Partition 0 |    |  Partition 1 |    |  Partition 2 |    |  Partition N |
//!     |              |    |              |    |              |    |              |
//!     | +----------+ |    | +----------+ |    | +----------+ |    | +----------+ |
//!     | | Wallet A | |    | | Wallet D | |    | | Wallet G | |    | | Wallet X | |
//!     | | Wallet B | |    | | Wallet E | |    | | Wallet H | |    | | Wallet Y | |
//!     | | Wallet C | |    | | Wallet F | |    | | Wallet I | |    | | Wallet Z | |
//!     | +----------+ |    | +----------+ |    | +----------+ |    | +----------+ |
//!     |              |    |              |    |              |    |              |
//!     |              |    |              |    |              |    |              |
//!     | Processes    |    | Processes    |    | Processes    |    | Processes    |
//!     | transactions |    | transactions |    | transactions |    | transactions |
//!     | independently|    | independently|    | independently|    | independently|
//!     |              |    |              |    |              |    |              |
//!     | Builds local |    | Builds local |    | Builds local |    | Builds local |
//!     | Sparse Merkle|    | Sparse Merkle|    | Sparse Merkle|    | Sparse Merkle|
//!     | Tree (SMT)   |    | Tree (SMT)   |    | Tree (SMT)   |    | Tree (SMT)   |
//!     |              |    |              |    |              |    |              |
//!     +------+-------+    +------+-------+    +------+-------+    +------+-------+
//!            |                   |                   |                   |
//!            |                   |                   |                   |
//!            |                   |                   |                   |
//!            |                   |                   |                   |
//!            |                   |                   |                   |
//!            v                   v                   v                   v
//!     +----------------------------------------------------------------------+
//!     |                    PartitionBatch (per partition)                    |
//!     |  +-----------------------------------------------------------------+ |
//!     |  | partition_id: 0                                                 | |
//!     |  | local_batch: Batch {                                            | |
//!     |  |   transitions: [WalletTransition, ...]                          | |
//!     |  |   pre_commitment_root:  [0x...]  <- state before batch          | |
//!     |  |   post_commitment_root: [0xAB...] <- state after batch          | |
//!     |  |   local_batch_num: local_batch_num <- partition-local batch num | |
//!     |  |                                                                 | |
//!     |  |   proofs: BatchProofBundle { ... }                              | |
//!     |  | }                                                               | |
//!     |  | cross_partition_dependencies: [...]                             | |
//!     |  +-----------------------------------------------------------------+ |
//!     +----------------------------------------------------------------------+
//!                                       |
//!                                       | All PartitionBatches collected
//!                                       v
//!     +----------------------------------------------------------------------+
//!     |                        GlobalComposer                                |
//!     |                                                                      |
//!     |  1. Extract partition commitment roots:                              |
//!     |     [PartitionRoot0, PartitionRoot1, ..., PartitionRootN]            |
//!     |                                                                      |
//!     |  2. Compose into global Merkle tree:                                 |
//!     |                                                                      |
//!     |              +-------------------------------------+                 |
//!     |              |      Global Root (32 bytes)         |                 |
//!     |              |    hash(hash(R0,R1), hash(R2,R3))   |                 |
//!     |              +-------------------------------------+                 |
//!     |                         /              \                             |
//!     |              +------------------+  +------------------+              |
//!     |              | hash(R0, R1)     |  | hash(R2, R3)     |              |
//!     |              +------------------+  +------------------+              |
//!     |                   /        \              /        \                 |
//!     |           +----------+ +----------+ +----------+ +----------+        |
//!     |           | Root0    | | Root1    | | Root2    | | Root3    |        |
//!     |           | (32B)    | | (32B)    | | (32B)    | | (32B)    |        |
//!     |           +----------+ +----------+ +----------+ +----------+        |
//!     |              |            |            |            |                |
//!     |              +------------+------------+------------+                |
//!     |                   Each partition's local commitment root (SMT)       |
//!     |                                                                      |
//!     |  3. Compute global batch number for total ordering:                  |
//!     |     max(encode(partition_id, local_batch_num) for all partitions)    |
//!     |     where encode(id, batch_num) = (id << 32) | batch_num             |
//!     +----------------------------------------------------------------------+
//!                                        |
//!                                        v
//!     +----------------------------------------------------------------------+
//!     |                         GlobalBatch                                  |
//!     |  +-----------------------------------------------------------------+ |
//!     |  | partition_batches: [PartitionBatch0, PartitionBatch1, ...]      | |
//!     |  | global_commitment_root:  [0xCDEF...]  <- global commitment root | |
//!     |  | global_batch_num: 0x000000010000000N  <- max encoded batch num  | |
//!     |  +-----------------------------------------------------------------+ |
//!     +----------------------------------------------------------------------+
//!                                        |
//!                                        v
//!
//!                            [Verification & Anchoring]
//! ```

use crate::global::commitment::types::GlobalRoot;
use crate::global::commitment::{MerkleMorphV0Config, Poseidon2Hasher};
use crate::global::smt::{SmtConfig, SmtHasher};
use crate::scheduler::partition::batch::PartitionBatch;
use crate::scheduler::partition::types::{GlobalBatch, PartitionId, PartitionRoot};

/// Composes partition roots (already-verified global roots for disjoint partitions)
/// into a single global commitment.
///
/// In the current design each partition maintains its own global SMT over its local
/// wallet subset, producing a `PartitionRoot` which is just a `GlobalRoot` hash. At
/// the global layer we treat these as leaves of a higher-level Merkle tree and
/// hash them pairwise until a single root remains.
pub fn compose_partition_roots(partition_roots: &[PartitionRoot]) -> GlobalRoot {
    let hasher = Poseidon2Hasher;
    let config = MerkleMorphV0Config;
    let zero = hasher.zero_hash();

    if partition_roots.is_empty() {
        return zero;
    }

    // Simple pairwise Merkle composition over the partition roots.
    let mut layer: Vec<PartitionRoot> = partition_roots.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            let combined = if chunk.len() == 2 {
                hasher.hash_internal(config.internal_domain_tag(), chunk[0], chunk[1])
            } else {
                // If odd number of leaves, hash the last one with zero.
                hasher.hash_internal(config.internal_domain_tag(), chunk[0], zero)
            };
            next.push(combined);
        }
        layer = next;
    }
    layer[0]
}

/// Composer that aggregates partition batches into a global batch.
#[derive(Default)]
pub struct GlobalComposer;

impl GlobalComposer {
    /// Composes partition-local commitment roots into a global commitment root.
    ///
    /// This function expects that each partition batch contains a standard
    /// `Batch` whose `post_commitment_root` represents the partition-local state
    /// commitment. It then composes these partition commitment roots into a
    /// higher-level Merkle root and assigns a global batch number derived from
    /// per-partition batch numbers.
    pub fn compose_partition_batches(
        &self,
        partition_batches: Vec<PartitionBatch>,
    ) -> crate::Result<GlobalBatch> {
        if partition_batches.is_empty() {
            return Ok(GlobalBatch {
                partition_batches: Vec::new(),
                global_commitment_root: [0u8; 32],
                global_batch_num: 0,
            });
        }

        let mut partition_roots: Vec<PartitionRoot> = Vec::with_capacity(partition_batches.len());
        for pb in partition_batches.iter() {
            partition_roots.push(pb.local_batch.post_commitment_root);
        }
        let global_root: GlobalRoot = compose_partition_roots(&partition_roots);

        let mut global_batch_num: u64 = 0;
        for pb in partition_batches.iter() {
            let partition_batch_num =
                Self::encode_global_batch_num(pb.partition_id, pb.local_batch.local_batch_num);
            if partition_batch_num > global_batch_num {
                global_batch_num = partition_batch_num;
            }
        }

        Ok(GlobalBatch { partition_batches, global_commitment_root: global_root, global_batch_num })
    }

    /// Verify that partition-local commitment roots and proofs are consistent with the claimed global batch.
    ///
    /// This implementation checks that:
    /// - each partition batch carries a `batch_proof`, and
    /// - composing the partition-local post-commitment roots reproduces `global_commitment_root`.
    pub fn verify_partition_proofs(&self, batches: &GlobalBatch) -> crate::Result<()> {
        if batches.partition_batches.is_empty() {
            if batches.global_commitment_root != [0u8; 32] || batches.global_batch_num != 0 {
                return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                    "empty GlobalBatch must have zero root and batch number".to_string(),
                )));
            }
            return Ok(());
        }

        let mut partition_roots: Vec<PartitionRoot> =
            Vec::with_capacity(batches.partition_batches.len());
        for pb in batches.partition_batches.iter() {
            if pb.local_batch.proofs.batch_proof.is_none() {
                return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                    "missing partition batch proof".to_string(),
                )));
            }
            partition_roots.push(pb.local_batch.post_commitment_root);
        }

        let composed_root = compose_partition_roots(&partition_roots);
        if composed_root != batches.global_commitment_root {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                "global partition root mismatch".to_string(),
            )));
        }

        Ok(())
    }

    /// Encode a global batch number from a `(partition_id, local_batch_num)` pair.
    pub fn encode_global_batch_num(partition_id: PartitionId, local_batch_num: u32) -> u64 {
        ((partition_id as u64) << 32) | (local_batch_num as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compose_partition_batches() {
        let composer = GlobalComposer;

        let empty_global = composer.compose_partition_batches(Vec::new()).expect("ok");

        assert_eq!(empty_global.partition_batches.len(), 0);
        assert_eq!(empty_global.global_commitment_root, [0u8; 32]);
        assert_eq!(empty_global.global_batch_num, 0);

        let post_root = [1u8; 32];
        let local_batch = crate::scheduler::batch::Batch::new(
            Vec::new(),
            Vec::new(),
            [0u8; 32],
            post_root,
            5,
            [0u8; 32],
            crate::scheduler::batch::FeeMetadata { fee_rate: None, payer: None },
            crate::scheduler::batch::BatchProofBundle {
                batch_proof: None,
                wallet_transition_proofs: Vec::new(),
            },
        );
        let partition_batch = PartitionBatch::from_local(0, local_batch);

        let global = composer.compose_partition_batches(vec![partition_batch]).expect("ok");

        assert_eq!(global.partition_batches.len(), 1);
        assert_ne!(global.global_commitment_root, [0u8; 32]);
        assert_eq!(global.global_commitment_root.len(), post_root.len());
        assert_eq!(global.global_batch_num, GlobalComposer::encode_global_batch_num(0, 5));
    }

    #[test]
    fn test_verify_partition_proofs() {
        let composer = GlobalComposer;

        let empty_bad = crate::scheduler::partition::types::GlobalBatch {
            partition_batches: Vec::new(),
            global_commitment_root: [1u8; 32],
            global_batch_num: 1,
        };

        assert!(composer.verify_partition_proofs(&empty_bad).is_err());

        let empty_ok = crate::scheduler::partition::types::GlobalBatch {
            partition_batches: Vec::new(),
            global_commitment_root: [0u8; 32],
            global_batch_num: 0,
        };

        assert!(composer.verify_partition_proofs(&empty_ok).is_ok());

        let local_batch_missing = crate::scheduler::batch::Batch::new(
            Vec::new(),
            Vec::new(),
            [0u8; 32],
            [2u8; 32],
            3,
            [0u8; 32],
            crate::scheduler::batch::FeeMetadata { fee_rate: None, payer: None },
            crate::scheduler::batch::BatchProofBundle {
                batch_proof: None,
                wallet_transition_proofs: Vec::new(),
            },
        );
        let partition_missing = PartitionBatch::from_local(0, local_batch_missing);
        let global_missing = crate::scheduler::partition::types::GlobalBatch {
            partition_batches: vec![partition_missing],
            global_commitment_root: [0u8; 32],
            global_batch_num: 0,
        };

        assert!(composer.verify_partition_proofs(&global_missing).is_err());
    }

    #[test]
    fn test_encode_global_batch_num() {
        let partition_id: PartitionId = 7;
        let local_batch_num: u32 = 11;

        let encoded = GlobalComposer::encode_global_batch_num(partition_id, local_batch_num);

        assert_eq!(encoded, ((partition_id as u64) << 32) | (local_batch_num as u64));
    }
}
