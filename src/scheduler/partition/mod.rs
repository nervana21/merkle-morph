// SPDX-License-Identifier: CC0-1.0

//! Partition-aware scheduling and batch composition.
//!
//! This module provides abstractions for routing updates to partitions, running
//! partition-local sequencers, coordinating cross-partition transactions, and
//! composing partition-local batches into a global batch.

pub mod batch;
pub mod composer;
pub mod coordinator;
pub mod cross_partition;
pub mod proof;
pub mod router;
pub mod sequencer;
pub mod types;

pub use batch::{CrossPartitionDependency, PartitionBatch};
pub use composer::GlobalComposer;
pub use coordinator::{PartitionCoordinator, RebalancePlan};
pub use cross_partition::{
    CrossPartitionCoordinator, CrossPartitionTransaction, PartitionPrepareResponse, PrepareId,
};
pub use proof::PartitionProofAggregator;
pub use router::{PartitionRouter, SeaHashRouter};
pub use sequencer::PartitionedSequencer;
pub use types::{GlobalBatch, PartitionEndpoint, PartitionId, PartitionRoot};
