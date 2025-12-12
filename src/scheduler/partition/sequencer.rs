// SPDX-License-Identifier: CC0-1.0

//! Partition-local sequencer wrapper.
//!
//! This module defines [`PartitionedSequencer`], which routes updates to
//! per-partition [`InMemorySequencer`] instances using a [`PartitionRouter`]. Each
//! partition maintains its own wallet map, pending queue, and sequence number. The
//! `PartitionedSequencer` implements the global [`Sequencer`] trait by delegating
//! to the appropriate partition for each operation.

use std::collections::BTreeMap;

use super::cross_partition::{CrossPartitionCoordinator, CrossPartitionTransaction, PrepareId};
use super::router::PartitionRouter;
use super::types::PartitionId;
use crate::global::commitment::types::GlobalRoot;
use crate::scheduler::batch::{BatchProofBundle, FeeMetadata};
use crate::scheduler::partition::composer::compose_partition_roots;
use crate::scheduler::partition::{
    GlobalBatch, GlobalComposer, PartitionBatch, PartitionProofAggregator,
};
use crate::scheduler::sequencer::{
    InMemorySequencer, SchedulingRules, Sequencer, SimulationResult,
};
use crate::scheduler::{Executor, InMemoryExecutor, TransitionId, UpdateEnvelope};
use crate::types::{P2A_DEFAULT_NETWORK, P2A_DEFAULT_VALUE_SATS};
use crate::{
    build_p2a_txout, derive_default_p2a_internal_key, Batch, ChannelId, Result, StarkConfig,
    WalletId, WalletState,
};

/// Partition-aware sequencer that wraps sequencer instances.
///
/// This sequencer routes updates to per-partition sequencer instances using a `PartitionRouter`.
/// Each partition maintains its own wallet map, pending queue, and sequence number. The
/// `PartitionedSequencer` implements the global `Sequencer` trait by delegating
/// to the appropriate partition for each operation.
///
/// # Type Parameters
///
/// * `R` - The scheduling rules type
/// * `S` - The partition router type
/// * `Seq` - The sequencer type to use for each partition (defaults to `InMemorySequencer<R>`)
pub struct PartitionedSequencer<
    R: SchedulingRules,
    S: PartitionRouter,
    Seq: Sequencer = InMemorySequencer<R>,
> {
    rules: R,
    router: S,
    /// Per-partition sequencers.
    partitions: BTreeMap<PartitionId, Seq>,
    /// Optional coordinator for cross-partition transaction coordination.
    coordinator: Option<CrossPartitionCoordinator>,
    /// Track prepare_ids for cross-partition transactions that need to be committed during batch building.
    pending_prepare_ids: Vec<PrepareId>,
}

impl<R: SchedulingRules + Clone + Send + Sync, S: PartitionRouter>
    PartitionedSequencer<R, S, InMemorySequencer<R>>
{
    /// Create a new partitioned sequencer from an initial wallet map.
    ///
    /// Wallets are distributed across partitions using the provided `router`.
    /// This constructor uses `InMemorySequencer` by default.
    pub fn new(router: S, rules: R, wallets: BTreeMap<WalletId, WalletState>) -> Self {
        let mut partition_wallets: BTreeMap<PartitionId, BTreeMap<WalletId, WalletState>> =
            BTreeMap::new();
        for (id, state) in wallets.into_iter() {
            // Route wallet to its partition; fall back to partition 0 if router has no opinion.
            let partition_id = router.route_wallet(id);
            partition_wallets.entry(partition_id).or_default().insert(id, state);
        }

        let mut partitions = BTreeMap::new();
        for (partition_id, wallets) in partition_wallets.into_iter() {
            partitions.insert(partition_id, InMemorySequencer::new(rules.clone(), wallets));
        }

        Self {
            rules,
            router,
            partitions,
            coordinator: Some(CrossPartitionCoordinator::new()),
            pending_prepare_ids: Vec::new(),
        }
    }
}

impl<R: SchedulingRules + Clone + Send + Sync, S: PartitionRouter> Sequencer
    for PartitionedSequencer<R, S, InMemorySequencer<R>>
{
    fn ingest(&mut self, envelope: UpdateEnvelope) -> Result<TransitionId> {
        // Check if this is a cross-partition transaction
        if let Some(coordinator) = &self.coordinator {
            if let Some(transaction) = self.detect_cross_partition(&envelope) {
                // Prepare the cross-partition transaction
                let (prepare_id, responses) = coordinator.prepare_cross_partition(transaction)?;

                // Check if all partitions prepared successfully
                if !responses.iter().all(|r| r.success) {
                    coordinator.abort_cross_partition(prepare_id).ok();
                    return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                        format!("cross-partition preparation failed: {responses:?}"),
                    )));
                }

                // Store prepare_id for commit during batch building
                self.pending_prepare_ids.push(prepare_id);
            }
        }

        let partition_id = self
            .router
            .get_partition_for_update(&envelope)
            .unwrap_or_else(|| self.router.route_wallet([0u8; 32]));
        // For InMemorySequencer, we can create partitions on demand
        let sequencer = self
            .partitions
            .entry(partition_id)
            .or_insert_with(|| InMemorySequencer::new(self.rules.clone(), BTreeMap::new()));
        sequencer.ingest(envelope)
    }

    fn schedulable(&self, envelope: &UpdateEnvelope) -> bool {
        if let Some(partition_id) = self.router.get_partition_for_update(envelope) {
            if let Some(seq) = self.partitions.get(&partition_id) {
                return seq.schedulable(envelope);
            }
        }
        true
    }

    fn simulate(&self, envelope: &UpdateEnvelope) -> Result<SimulationResult> {
        if let Some(partition_id) = self.router.get_partition_for_update(envelope) {
            if let Some(seq) = self.partitions.get(&partition_id) {
                return seq.simulate(envelope);
            }
        }

        let wallet_id = *envelope.access_set.wallets.first().ok_or_else(|| {
            crate::errors::GlobalError::InvalidParameters(
                "access_set must contain at least one wallet id".into(),
            )
        })?;
        // Create a temporary executor for simulation
        let mut wallets = BTreeMap::new();
        if let Some(wallet_id) = envelope.access_set.wallets.first() {
            wallets.insert(*wallet_id, WalletState::new(*wallet_id));
        }
        let mut sim_executor = InMemoryExecutor::new(wallets);
        sim_executor.apply_wallet_transition(wallet_id, &envelope.transition)?;
        let tentative_root = sim_executor.compute_global_root()?;
        Ok(SimulationResult {
            affected_wallets: vec![wallet_id],
            tentative_root: Some(tentative_root),
            admissible: true,
        })
    }

    fn build_next_batch(&mut self) -> Result<Batch> { self.build_batch_from_partitions(None) }

    fn build_next_batch_with_proofs(&mut self, config: &StarkConfig) -> Result<Batch> {
        self.build_batch_from_partitions(Some(config))
    }

    fn anchor_payload(&self, batch: &Batch) -> Result<bitcoin::TxOut> {
        if let Some((_, partition_seq)) = self.partitions.iter().next() {
            partition_seq.anchor_payload(batch)
        } else {
            let (root, local_batch_num) = (batch.post_commitment_root, batch.local_batch_num);
            let anchor_internal_key =
                derive_default_p2a_internal_key().expect("default P2A internal key must be valid");
            build_p2a_txout(
                root,
                local_batch_num,
                anchor_internal_key,
                P2A_DEFAULT_VALUE_SATS,
                P2A_DEFAULT_NETWORK,
            )
            .map_err(|e| {
                crate::errors::GlobalError::InvalidParameters(format!(
                    "Failed to build P2A txout: {e}"
                ))
                .into()
            })
        }
    }

    fn head(&self) -> (GlobalRoot, u32) {
        let mut max_local_batch_num: u32 = 0;
        for seq in self.partitions.values() {
            let (_root, local_batch_num) = seq.head();
            if local_batch_num > max_local_batch_num {
                max_local_batch_num = local_batch_num;
            }
        }
        (self.compute_global_root(), max_local_batch_num)
    }
}

impl<R: SchedulingRules + Clone + Send + Sync, S: PartitionRouter, Seq: Sequencer>
    PartitionedSequencer<R, S, Seq>
{
    /// Create a new partitioned sequencer with custom sequencer instances.
    ///
    /// This allows using different sequencer implementations for each partition,
    /// such as database-backed sequencers or other custom implementations.
    ///
    /// # Arguments
    ///
    /// * `router` - The partition router to use for routing wallets/channels
    /// * `rules` - The scheduling rules to use
    /// * `partitions` - A map of partition IDs to their sequencer instances
    pub fn with_sequencers(router: S, rules: R, partitions: BTreeMap<PartitionId, Seq>) -> Self {
        Self {
            rules,
            router,
            partitions,
            coordinator: Some(CrossPartitionCoordinator::new()),
            pending_prepare_ids: Vec::new(),
        }
    }

    /// Build a global batch by composing partition-local batches from all partitions.
    ///
    /// This method processes all partitions in parallel using `std::thread::scope`, building
    /// batches from each partition's sequencer simultaneously. The partition-local batches are
    /// then composed into a single `GlobalBatch` using the [`GlobalComposer`].
    ///
    /// # Parallelization
    ///
    /// The batch building is parallelized across all partitions using Rust's standard library
    /// scoped threads. Each partition's `build_next_batch()` call (which includes CPU-intensive
    /// operations like Poseidon2 hashing) runs in parallel.
    ///
    /// # Note
    ///
    /// This method requires that the sequencer type `Seq` is `Send + Sync` to be used in
    /// parallel threads. For sequencers that don't implement these traits, use a sequential
    /// batch building approach.
    pub fn build_global_batch(&mut self) -> crate::Result<GlobalBatch>
    where
        Seq: Send + Sync,
    {
        let mut partitions_vec: Vec<(PartitionId, Seq)> =
            std::mem::take(&mut self.partitions).into_iter().collect();
        partitions_vec.sort_by_key(|(id, _)| *id);

        let partition_batches: Vec<PartitionBatch> = std::thread::scope(|s| {
            let handles: Vec<_> = partitions_vec
                .iter_mut()
                .map(|(partition_id, seq)| {
                    s.spawn(|| -> crate::Result<PartitionBatch> {
                        let local_batch = seq.build_next_batch()?;
                        Ok(PartitionBatch::from_local(*partition_id, local_batch))
                    })
                })
                .collect();

            let results: Vec<crate::Result<PartitionBatch>> =
                handles.into_iter().map(|h| h.join().expect("thread join failed")).collect();

            results.into_iter().collect::<crate::Result<Vec<_>>>()
        })?;

        self.partitions = partitions_vec.into_iter().collect();

        let composer = GlobalComposer;
        composer.compose_partition_batches(partition_batches)
    }

    /// Compute the global root as the hash-chain composition over all partition
    /// heads.
    fn compute_global_root(&self) -> GlobalRoot {
        if self.partitions.is_empty() {
            return [0u8; 32];
        }
        let roots: Vec<GlobalRoot> = self.partitions.values().map(|s| s.head().0).collect();
        compose_partition_roots(&roots)
    }

    /// Get a reference to the cross-partition coordinator.
    pub fn coordinator(&self) -> Option<&CrossPartitionCoordinator> { self.coordinator.as_ref() }

    /// Internal helper to build a batch from partition batches.
    /// The `with_proofs` parameter determines whether to generate proofs or not.
    ///
    /// # Note
    ///
    /// This method requires that the sequencer type `Seq` is `Send + Sync` to be used in
    /// parallel threads.
    fn build_batch_from_partitions(&mut self, with_proofs: Option<&StarkConfig>) -> Result<Batch>
    where
        Seq: Send + Sync,
    {
        if self.partitions.is_empty() {
            let pre_root = [0u8; 32];
            let post_root = pre_root;
            let local_batch_num = 0;
            let fee_info = FeeMetadata { fee_rate: None, payer: None };
            let proofs = BatchProofBundle { batch_proof: None, wallet_transition_proofs: vec![] };
            return Ok(Batch::new(
                vec![],
                vec![],
                pre_root,
                post_root,
                local_batch_num,
                [0u8; 32],
                fee_info,
                proofs,
            ));
        }

        // Process all partitions in parallel
        let pre_root = self.compute_global_root();
        let mut partitions_vec: Vec<(PartitionId, Seq)> =
            std::mem::take(&mut self.partitions).into_iter().collect();
        partitions_vec.sort_by_key(|(id, _)| *id);

        type BatchBuildResult<Seq> =
            crate::Result<(Vec<(PartitionId, Batch)>, Vec<(PartitionId, Seq)>)>;

        let (mut partition_batches, restored_partitions) = {
            // with_proofs is valid for the entire scope, so we can reference it in each thread
            std::thread::scope(|s| -> BatchBuildResult<Seq> {
                let handles: Vec<_> = partitions_vec
                    .into_iter()
                    .map(|(partition_id, mut seq)| {
                        s.spawn(move || -> crate::Result<(PartitionId, Batch, Seq)> {
                            let local_batch = match with_proofs {
                                Some(cfg) => seq.build_next_batch_with_proofs(cfg)?,
                                None => seq.build_next_batch()?,
                            };
                            Ok((partition_id, local_batch, seq))
                        })
                    })
                    .collect();

                let results: std::result::Result<Vec<(PartitionId, Batch, Seq)>, crate::Error> =
                    handles.into_iter().map(|h| h.join().expect("thread join failed")).collect();

                let mut batches = Vec::new();
                let mut partitions = Vec::new();
                for (id, batch, seq) in results? {
                    batches.push((id, batch));
                    partitions.push((id, seq));
                }
                Ok((batches, partitions))
            })
        }?;

        self.partitions = restored_partitions.into_iter().collect();

        // Commit all prepared cross-partition transactions that are included in this batch
        if let Some(coordinator) = &self.coordinator {
            let prepare_ids = std::mem::take(&mut self.pending_prepare_ids);
            for prepare_id in prepare_ids {
                // Commit is idempotent, so it's safe to commit even if the transaction
                // was already committed or if it's not in this batch
                coordinator.commit_cross_partition(prepare_id).ok();
            }
        }

        // Compose partition batches into a single Batch
        let mut all_transitions = Vec::new();
        let mut all_affected_wallets = Vec::new();
        let mut max_local_batch_num = 0u32;
        let mut partition_roots = Vec::new();
        let mut all_wallet_proofs = Vec::new();
        let mut partition_batch_proofs = Vec::new();

        for (_, batch) in partition_batches.iter() {
            all_transitions.extend_from_slice(&batch.transitions);
            all_affected_wallets.extend_from_slice(&batch.affected_wallets);
            if batch.local_batch_num > max_local_batch_num {
                max_local_batch_num = batch.local_batch_num;
            }
            partition_roots.push(batch.post_commitment_root);
            all_wallet_proofs.extend_from_slice(&batch.proofs.wallet_transition_proofs);
        }

        // Compute global root from all partition roots
        let post_root = if partition_roots.is_empty() {
            [0u8; 32]
        } else {
            compose_partition_roots(&partition_roots)
        };

        // Collect partition batch proofs for aggregation
        for (_, batch) in partition_batches.iter_mut() {
            if let Some(proof) = batch.proofs.batch_proof.take() {
                partition_batch_proofs.push(proof);
            }
        }

        // Aggregate partition batch proofs into a single proof
        let batch_proof = if partition_batch_proofs.is_empty() {
            None
        } else if let Some(config) = with_proofs {
            Some(PartitionProofAggregator::aggregate_partition_proofs(
                config,
                &partition_roots,
                partition_batch_proofs,
                post_root,
            )?)
        } else {
            None
        };

        let fee_info = FeeMetadata { fee_rate: None, payer: None };
        let proofs = BatchProofBundle { batch_proof, wallet_transition_proofs: all_wallet_proofs };

        let mut composed_batch = Batch::new(
            all_transitions,
            all_affected_wallets,
            pre_root,
            post_root,
            max_local_batch_num,
            [0u8; 32],
            fee_info,
            proofs,
        );
        let da_hash = composed_batch.compute_da_hash();
        composed_batch.da_hash = da_hash;

        Ok(composed_batch)
    }

    /// Detect if an update envelope affects multiple partitions.
    ///
    /// This analyzes both wallets in the access set and channels referenced in the transition
    /// to determine if the transaction spans multiple partitions. A transaction is considered
    /// cross-partition if the total number of unique partitions (across both wallets and channels)
    /// is greater than one. This occurs when:
    /// - Wallets are routed to different partitions, or
    /// - The channel referenced in the transition is routed to a partition that is not in the
    ///   set of partitions containing wallets
    fn detect_cross_partition(
        &self,
        envelope: &UpdateEnvelope,
    ) -> Option<CrossPartitionTransaction> {
        let mut wallets_by_partition: BTreeMap<PartitionId, Vec<WalletId>> = BTreeMap::new();
        let mut channels_by_partition: BTreeMap<PartitionId, Vec<ChannelId>> = BTreeMap::new();

        // Route wallets to their partitions
        for wallet_id in &envelope.access_set.wallets {
            let partition_id = self.router.route_wallet(*wallet_id);
            wallets_by_partition.entry(partition_id).or_default().push(*wallet_id);
        }

        // Extract and route the channel from the transition
        let channel_id = envelope.transition.channel_id();
        let channel_partition_id = self.router.route_channel(channel_id);
        channels_by_partition.entry(channel_partition_id).or_default().push(channel_id);

        // Collect all unique partition IDs involved (from both wallets and channels)
        let mut all_partitions: BTreeMap<PartitionId, ()> = BTreeMap::new();
        for partition_id in wallets_by_partition.keys() {
            all_partitions.insert(*partition_id, ());
        }
        for partition_id in channels_by_partition.keys() {
            all_partitions.insert(*partition_id, ());
        }

        // Only return cross-partition transaction if we span multiple partitions
        if all_partitions.len() > 1 {
            Some(CrossPartitionTransaction { wallets_by_partition, channels_by_partition })
        } else {
            None
        }
    }
}

// Note: The generic Sequencer implementation for PartitionedSequencer<R, S, Seq>
// is only provided for the default InMemorySequencer case above to avoid trait conflicts.
// For custom sequencer types, users should use with_sequencers() and implement
// Sequencer for their custom PartitionedSequencer type if needed.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::sequencer::{AccessSet, BasicSchedulingRules, UpdateEnvelope};
    use crate::types::P2A_DEFAULT_VALUE_SATS;
    use crate::wallet::operation::WalletTransition;
    use crate::zkp::types::create_config;

    #[test]
    fn test_new() {
        let router = crate::scheduler::partition::SeaHashRouter::new(4);
        let rules = BasicSchedulingRules::new(1);
        let empty_wallets = BTreeMap::new();

        let partitioned_empty =
            PartitionedSequencer::new(router.clone(), rules.clone(), empty_wallets);

        assert!(partitioned_empty.partitions.is_empty());

        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));

        let partitioned = PartitionedSequencer::new(router, rules, wallets);

        assert!(!partitioned.partitions.is_empty());
    }

    #[test]
    fn test_with_sequencers() {
        let router = crate::scheduler::partition::SeaHashRouter::new(4);
        let rules = BasicSchedulingRules::new(1);
        let mut partitions = BTreeMap::new();
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        partitions.insert(0u32, InMemorySequencer::new(rules.clone(), wallets));

        let partitioned = PartitionedSequencer::with_sequencers(router, rules, partitions);

        assert!(partitioned.coordinator().is_some());
    }

    #[test]
    fn test_build_global_batch() {
        let router = crate::scheduler::partition::SeaHashRouter::new(4);
        let rules = BasicSchedulingRules::new(1);
        let empty_wallets = BTreeMap::new();
        let mut partitioned_empty =
            PartitionedSequencer::new(router.clone(), rules.clone(), empty_wallets);

        let _batch_empty =
            partitioned_empty.build_global_batch().expect("build_global_batch should succeed");

        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let mut partitioned = PartitionedSequencer::new(router, rules, wallets);

        let _batch = partitioned.build_global_batch().expect("build_global_batch should succeed");
    }

    #[test]
    fn test_coordinator() {
        let router = crate::scheduler::partition::SeaHashRouter::new(4);
        let rules = BasicSchedulingRules::new(1);
        let wallets = BTreeMap::new();
        let partitioned = PartitionedSequencer::new(router, rules, wallets);

        assert!(partitioned.coordinator().is_some());
    }

    #[test]
    fn test_ingest() {
        let router = crate::scheduler::partition::SeaHashRouter::new(4);
        let rules = BasicSchedulingRules::new(1);
        let wallet_id1 = [1u8; 32];
        let wallet_id2 = [2u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id1, WalletState::new(wallet_id1));
        let mut partitioned = PartitionedSequencer::new(router.clone(), rules.clone(), wallets);
        let envelope_existing = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [3u8; 32],
                channel_commitment: [4u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id1]),
            fee_rate: None,
            submit_order: 0,
        };

        let _id1 = partitioned.ingest(envelope_existing).expect("ingest should succeed");

        let envelope_new_partition = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [5u8; 32],
                channel_commitment: [6u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id2]),
            fee_rate: None,
            submit_order: 1,
        };

        let _id2 = partitioned.ingest(envelope_new_partition).expect("ingest should succeed");

        let mut partitioned_fallback =
            PartitionedSequencer::new(router.clone(), rules.clone(), BTreeMap::new());
        let envelope_no_wallet = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [7u8; 32],
                channel_commitment: [8u8; 32],
            },
            access_set: AccessSet { wallets: Vec::new(), prefixes: Vec::new() },
            fee_rate: None,
            submit_order: 2,
        };

        let _id3 = partitioned_fallback.ingest(envelope_no_wallet).expect("ingest should succeed");

        let wallet_cross1 = [100u8; 32];
        let wallet_cross2 = [200u8; 32];
        let mut partitioned_cross =
            PartitionedSequencer::new(router.clone(), rules.clone(), BTreeMap::new());
        let envelope_cross_success = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [30u8; 32],
                channel_commitment: [40u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_cross1, wallet_cross2]),
            fee_rate: None,
            submit_order: 3,
        };

        let _id4 = partitioned_cross.ingest(envelope_cross_success).expect("ingest should succeed");

        let envelope_cross_fail = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [31u8; 32],
                channel_commitment: [60u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_cross1, wallet_cross2]),
            fee_rate: None,
            submit_order: 4,
        };

        let result = partitioned_cross.ingest(envelope_cross_fail);

        assert!(result.is_err());
    }

    #[test]
    fn test_schedulable() {
        let router = crate::scheduler::partition::SeaHashRouter::new(4);
        let rules = BasicSchedulingRules::new(1);
        let wallet_id1 = [1u8; 32];
        let wallet_id2 = [2u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id1, WalletState::new(wallet_id1));
        let partitioned = PartitionedSequencer::new(router.clone(), rules.clone(), wallets);
        let envelope_existing = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [3u8; 32],
                channel_commitment: [4u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id1]),
            fee_rate: None,
            submit_order: 0,
        };

        let _result1 = partitioned.schedulable(&envelope_existing);

        let envelope_new_partition = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [5u8; 32],
                channel_commitment: [6u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id2]),
            fee_rate: None,
            submit_order: 1,
        };

        let result2 = partitioned.schedulable(&envelope_new_partition);

        assert!(result2);
        let envelope_no_wallet = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [7u8; 32],
                channel_commitment: [8u8; 32],
            },
            access_set: AccessSet { wallets: Vec::new(), prefixes: Vec::new() },
            fee_rate: None,
            submit_order: 2,
        };

        let result3 = partitioned.schedulable(&envelope_no_wallet);

        assert!(result3);
    }

    #[test]
    fn test_simulate() {
        let router = crate::scheduler::partition::SeaHashRouter::new(4);
        let rules = BasicSchedulingRules::new(1);
        let wallet_id1 = [1u8; 32];
        let wallet_id2 = [2u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id1, WalletState::new(wallet_id1));
        let partitioned = PartitionedSequencer::new(router.clone(), rules.clone(), wallets);
        let envelope_existing = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [3u8; 32],
                channel_commitment: [4u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id1]),
            fee_rate: None,
            submit_order: 0,
        };

        let _result1 = partitioned.simulate(&envelope_existing).expect("simulate should succeed");

        let partitioned_empty =
            PartitionedSequencer::new(router.clone(), rules.clone(), BTreeMap::new());
        let envelope_new_partition = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [5u8; 32],
                channel_commitment: [6u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id2]),
            fee_rate: None,
            submit_order: 1,
        };

        let _result2 =
            partitioned_empty.simulate(&envelope_new_partition).expect("simulate should succeed");

        let envelope_no_wallet = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [7u8; 32],
                channel_commitment: [8u8; 32],
            },
            access_set: AccessSet { wallets: Vec::new(), prefixes: Vec::new() },
            fee_rate: None,
            submit_order: 2,
        };

        assert!(partitioned_empty.simulate(&envelope_no_wallet).is_err());
    }

    #[test]
    fn test_build_next_batch() {
        let router = crate::scheduler::partition::SeaHashRouter::new(4);
        let rules = BasicSchedulingRules::new(1);
        let empty_wallets = BTreeMap::new();
        let mut partitioned =
            PartitionedSequencer::new(router.clone(), rules.clone(), empty_wallets);

        let _batch_empty = partitioned.build_next_batch().expect("build_next_batch should succeed");

        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let mut partitioned_with_wallets = PartitionedSequencer::new(router, rules, wallets);

        let _batch =
            partitioned_with_wallets.build_next_batch().expect("build_next_batch should succeed");
    }

    #[test]
    fn test_build_next_batch_with_proofs() {
        let router = crate::scheduler::partition::SeaHashRouter::new(4);
        let rules = BasicSchedulingRules::new(1);
        let empty_wallets = BTreeMap::new();
        let mut partitioned =
            PartitionedSequencer::new(router.clone(), rules.clone(), empty_wallets);
        let config = create_config().expect("should create config");

        let _batch_empty = partitioned
            .build_next_batch_with_proofs(&config)
            .expect("build_next_batch_with_proofs should succeed");

        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let mut partitioned_with_wallets = PartitionedSequencer::new(router, rules, wallets);

        let _batch = partitioned_with_wallets
            .build_next_batch_with_proofs(&config)
            .expect("build_next_batch_with_proofs should succeed");
    }

    #[test]
    fn test_anchor_payload() {
        let router = crate::scheduler::partition::SeaHashRouter::new(4);
        let rules = BasicSchedulingRules::new(1);
        let empty_wallets = BTreeMap::new();
        let partitioned_empty =
            PartitionedSequencer::new(router.clone(), rules.clone(), empty_wallets);
        let batch = Batch::new(
            vec![],
            vec![],
            [0u8; 32],
            [1u8; 32],
            0,
            [2u8; 32],
            crate::scheduler::batch::FeeMetadata { fee_rate: None, payer: None },
            crate::scheduler::batch::BatchProofBundle {
                batch_proof: None,
                wallet_transition_proofs: vec![],
            },
        );

        let anchor_empty =
            partitioned_empty.anchor_payload(&batch).expect("anchor_payload should succeed");

        assert_eq!(anchor_empty.amount.to_sat(), P2A_DEFAULT_VALUE_SATS);
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let partitioned = PartitionedSequencer::new(router, rules, wallets);

        let _anchor = partitioned.anchor_payload(&batch).expect("anchor_payload should succeed");
    }

    #[test]
    fn test_head() {
        let router = crate::scheduler::partition::SeaHashRouter::new(4);
        let rules = BasicSchedulingRules::new(1);
        let empty_wallets = BTreeMap::new();
        let partitioned_empty =
            PartitionedSequencer::new(router.clone(), rules.clone(), empty_wallets);

        let (root_empty, batch_num_empty) = partitioned_empty.head();

        assert_eq!(root_empty, [0u8; 32]);
        assert_eq!(batch_num_empty, 0);
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let partitioned = PartitionedSequencer::new(router, rules, wallets.clone());

        let (root, batch_num) = partitioned.head();

        let executor = InMemoryExecutor::new(wallets);
        let expected_root = executor.compute_global_root().expect("should compute root");
        assert_eq!(root, expected_root);
        assert_eq!(batch_num, 0);
    }
}
