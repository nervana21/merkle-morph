// SPDX-License-Identifier: CC0-1.0

//! Partition-related type definitions.

use crate::global::commitment::types::GlobalRoot;
use crate::scheduler::partition::PartitionBatch;
use crate::types::{ChannelId, WalletId};

/// Identifier for a partition.
///
/// This is intentionally small to allow compact encoding inside batch numbers and
/// batch metadata.
pub type PartitionId = u32;

/// SMT root for a partition's wallet subset.
pub type PartitionRoot = GlobalRoot;

/// Network endpoint for a partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionEndpoint {
    /// Opaque address for the partition (e.g. URL, node ID).
    pub address: String,
}

/// Cross-partition reference to wallets or channels that live on another partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossPartitionRef {
    /// Wallets referenced on other partitions.
    pub wallets: Vec<WalletId>,
    /// Channels referenced on other partitions.
    pub channels: Vec<ChannelId>,
}

/// Final batch containing all partition-local batches and global metadata.
pub struct GlobalBatch {
    /// Batches produced by individual partitions.
    pub partition_batches: Vec<PartitionBatch>,
    /// Global post-state root composed from partition roots.
    pub global_commitment_root: GlobalRoot,
    /// Global batch number providing total ordering across partitions.
    pub global_batch_num: u64,
}
