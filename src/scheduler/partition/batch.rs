// SPDX-License-Identifier: CC0-1.0

//! Partition-local batch types.

use super::types::{CrossPartitionRef, PartitionId};
use crate::scheduler::Batch;
use crate::types::{ChannelId, WalletId};

/// Dependency on wallets or channels that live on a different partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossPartitionDependency {
    /// Local wallet ids whose state depends on remote partitions.
    pub local_wallets: Vec<WalletId>,
    /// Remote references grouped by partition.
    pub remote_refs: Vec<(PartitionId, CrossPartitionRef)>,
}

impl CrossPartitionDependency {
    /// Construct a new dependency with a single remote partition reference.
    pub fn single(
        local_wallets: Vec<WalletId>,
        remote_partition: PartitionId,
        remote_wallets: Vec<WalletId>,
        remote_channels: Vec<ChannelId>,
    ) -> Self {
        let remote = CrossPartitionRef { wallets: remote_wallets, channels: remote_channels };
        Self { local_wallets, remote_refs: vec![(remote_partition, remote)] }
    }
}

/// Batch produced by a single partition.
pub struct PartitionBatch {
    /// Identifier for the partition that produced this batch.
    pub partition_id: PartitionId,
    /// The partition's normal scheduler `Batch` (without cross-partition wrapper metadata).
    pub local_batch: Batch,
    /// Cross-partition dependencies referenced by this batch.
    pub cross_partition_dependencies: Vec<CrossPartitionDependency>,
}

impl PartitionBatch {
    /// Convenience constructor for a partition batch with no dependencies.
    pub fn from_local(partition_id: PartitionId, local_batch: Batch) -> Self {
        Self { partition_id, local_batch, cross_partition_dependencies: Vec::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single() {
        let local_wallets = vec![[1u8; 32]];
        let remote_partition: PartitionId = 2;
        let remote_wallets = vec![[3u8; 32]];
        let remote_channels = vec![[4u8; 32]];

        let dependency = CrossPartitionDependency::single(
            local_wallets.clone(),
            remote_partition,
            remote_wallets.clone(),
            remote_channels.clone(),
        );

        assert_eq!(dependency.local_wallets, local_wallets);
        assert_eq!(dependency.remote_refs.len(), 1);
        let (partition, remote_ref) = &dependency.remote_refs[0];
        assert_eq!(*partition, remote_partition);
        assert_eq!(remote_ref.wallets, remote_wallets);
        assert_eq!(remote_ref.channels, remote_channels);
    }

    #[test]
    fn test_from_local() {
        let partition_id: PartitionId = 5;
        let pre_commitment_root = [0u8; 32];
        let post_commitment_root = [1u8; 32];
        let da_hash = [2u8; 32];
        let fee_info = crate::scheduler::batch::FeeMetadata { fee_rate: None, payer: None };
        let proofs = crate::scheduler::batch::BatchProofBundle {
            batch_proof: None,
            wallet_transition_proofs: Vec::new(),
        };
        let local_batch = crate::scheduler::batch::Batch {
            transitions: Vec::new(),
            affected_wallets: Vec::new(),
            pre_commitment_root,
            post_commitment_root,
            local_batch_num: 0,
            da_hash,
            fee_info,
            proofs,
        };

        let partition_batch = PartitionBatch::from_local(partition_id, local_batch);

        assert_eq!(partition_batch.partition_id, partition_id);
        assert!(partition_batch.cross_partition_dependencies.is_empty());
        assert_eq!(partition_batch.local_batch.pre_commitment_root, [0u8; 32]);
        assert_eq!(partition_batch.local_batch.post_commitment_root, [1u8; 32]);
        assert_eq!(partition_batch.local_batch.da_hash, [2u8; 32]);
    }
}
