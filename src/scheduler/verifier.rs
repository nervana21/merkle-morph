// SPDX-License-Identifier: CC0-1.0

//! Verifier-facing API for batches.
//!
//! Light clients use this surface to reconstruct and check batch effects given an
//! anchor transaction and a DA provider. Implementations can choose how much
//! state to cache; the trait remains minimal. Proof checking is batch-level: we
//! bind the entire execution to the post-state commitment via a single proof.
//! An optimistic/fraud-proof flow can hook into the same interface by
//! optionally gating acceptance on a challenge window rather than immediate
//! proof presence.

use std::collections::BTreeMap;
use std::rc::Rc;

use crate::global::commitment::types::GlobalRoot;
use crate::global::commitment::{
    generate_merkle_proof, verify_merkle_proof_with, InMemorySiblingProvider, MerkleMorphV0Config,
    Poseidon2Hasher, TransitionWitnessCache,
};
use crate::scheduler::batch::deserialize_body;
use crate::scheduler::da::DAStore;
use crate::scheduler::executor::{compute_global_root_from_wallets, Executor, InMemoryExecutor};
use crate::scheduler::partition::{GlobalBatch, GlobalComposer};
use crate::zkp::{verify_wallet_transition, WalletTransitionPublicInputs};
use crate::{
    compose_to_global_root, compute_commitment_from_channels, compute_subtree_root, Batch, Result,
    WalletCommitment, WalletId, WalletState, WalletTransition,
};

/// Trait for verifying batches against anchors and prior roots.
pub trait BatchVerifier {
    /// Verify a batch given the previous root and return the new root.
    ///
    /// Expected steps for implementers:
    /// - fetch DA blob using `da_hash`
    /// - deserialize batch body
    /// - re-run ordered applies to compute post root
    /// - verify the batch-level proof that binds execution to the post root
    /// - ensure batch number continuity and anchor payload match
    fn verify_batch(&self, prev_root: GlobalRoot, batch: &Batch) -> Result<GlobalRoot>;

    /// Replay a batch without proof verification (useful for simulation or testing).
    fn replay_batch(&self, prev_root: GlobalRoot, batch: &Batch) -> Result<GlobalRoot>;
}

/// In-memory verifier that replays transitions using wallet/channel state.
pub struct InMemoryBatchVerifier<S: DAStore> {
    da: S,
    wallets: BTreeMap<crate::types::WalletId, WalletState>,
    config: Rc<crate::zkp::types::StarkConfig>,
}

impl<S: DAStore> InMemoryBatchVerifier<S> {
    /// Construct a verifier backed by a DA store and initial wallet state.
    pub fn new(
        da: S,
        wallets: BTreeMap<crate::types::WalletId, WalletState>,
        config: Rc<crate::zkp::types::StarkConfig>,
    ) -> Self {
        Self { da, wallets, config }
    }
}

/// Verifier for partitioned batches that first verifies each partition-local batch and
/// then checks global composition.
pub struct PartitionedBatchVerifier<S: DAStore> {
    /// Underlying verifier used for partition-local batches.
    inner: InMemoryBatchVerifier<S>,
    composer: GlobalComposer,
}

impl<S: DAStore> PartitionedBatchVerifier<S> {
    /// Construct a partitioned verifier from an in-memory verifier.
    pub fn new(inner: InMemoryBatchVerifier<S>) -> Self { Self { inner, composer: GlobalComposer } }

    /// Verify a `GlobalBatch` by verifying each partition-local batch and then
    /// checking that the composed partition roots match the claimed global root.
    pub fn verify_global_batch(
        &self,
        prev_root: GlobalRoot,
        global: &GlobalBatch,
    ) -> Result<GlobalRoot> {
        // Create shared transition witness cache to enforce uniqueness invariant across all partitions
        let mut witness_cache = TransitionWitnessCache::new();

        // First verify each partition-local batch individually
        let mut partition_roots = Vec::with_capacity(global.partition_batches.len());
        for partition_batch in global.partition_batches.iter() {
            let post = self.inner.verify_batch_with_cache(
                prev_root,
                &partition_batch.local_batch,
                &mut witness_cache,
            )?;
            partition_roots.push(post);
        }

        // Verify that the composed roots match the claimed global root
        let composed =
            crate::scheduler::partition::composer::compose_partition_roots(&partition_roots);
        if composed != global.global_commitment_root {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                "global partition root mismatch".to_string(),
            )));
        }

        // Additionally verify the global batch structure using the composer
        // This ensures proofs exist and validates the batch number consistency
        self.composer.verify_partition_proofs(global)?;

        Ok(global.global_commitment_root)
    }
}

impl<S: DAStore> BatchVerifier for InMemoryBatchVerifier<S> {
    fn verify_batch(&self, prev_root: GlobalRoot, batch: &Batch) -> Result<GlobalRoot> {
        // Create local transition witness cache for per-batch enforcement
        let mut witness_cache = TransitionWitnessCache::new();
        self.verify_batch_with_cache(prev_root, batch, &mut witness_cache)
    }

    fn replay_batch(&self, prev_root: GlobalRoot, batch: &Batch) -> Result<GlobalRoot> {
        // Fetch DA blob if provided; otherwise use batch body.
        let body = self.da.get(&batch.da_hash)?.unwrap_or_else(|| batch.serialize_body());
        let (local_batch_num, wallets, transitions) = deserialize_body(&body).ok_or_else(|| {
            crate::Error::Global(crate::errors::GlobalError::Internal(
                "failed to deserialize batch body".to_string(),
            ))
        })?;
        if local_batch_num != batch.local_batch_num {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                "batch number mismatch".to_string(),
            )));
        }
        let state = self.wallets.clone();
        let roots = self.compute_roots(&state)?;
        enum RootFlavor {
            HashChain,
            Proof,
        }
        let flavor = if prev_root == roots.proof {
            RootFlavor::Proof
        } else if prev_root == roots.hash_chain {
            RootFlavor::HashChain
        } else {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                "prev_root mismatch".to_string(),
            )));
        };

        // Skip proof verification for replay
        // self.verify_wallet_transition_proofs(&state, &wallets, &transitions, &batch)?;

        // Use executor for applying transitions
        let mut executor = InMemoryExecutor::new(state);
        for (wallet_id, transition) in wallets.into_iter().zip(transitions.iter()) {
            executor.apply_wallet_transition(wallet_id, transition)?;
        }
        let post_state = executor.get_all_wallets()?;
        let post_roots = self.compute_roots(&post_state)?;
        let post = match flavor {
            RootFlavor::Proof => post_roots.proof,
            RootFlavor::HashChain => post_roots.hash_chain,
        };
        if post != batch.post_commitment_root {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                "post_root mismatch".to_string(),
            )));
        }
        // Skip batch proof verification for replay
        // self.verify_proofs(batch)?;
        Ok(post)
    }
}

impl<S: DAStore> InMemoryBatchVerifier<S> {
    /// Verify a batch with an optional transition witness cache for uniqueness invariant enforcement
    pub(crate) fn verify_batch_with_cache(
        &self,
        prev_root: GlobalRoot,
        batch: &Batch,
        witness_cache: &mut TransitionWitnessCache,
    ) -> Result<GlobalRoot> {
        // Fetch DA blob if provided; otherwise use batch body.
        let body = self.da.get(&batch.da_hash)?.unwrap_or_else(|| batch.serialize_body());
        let (local_batch_num, wallets, transitions) = deserialize_body(&body).ok_or_else(|| {
            crate::Error::Global(crate::errors::GlobalError::Internal(
                "failed to deserialize batch body".to_string(),
            ))
        })?;
        if local_batch_num != batch.local_batch_num {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                "batch number mismatch".to_string(),
            )));
        }
        let state = self.wallets.clone();
        let roots = self.compute_roots(&state)?;
        enum RootFlavor {
            HashChain,
            Proof,
        }
        let flavor = if prev_root == roots.proof {
            RootFlavor::Proof
        } else if prev_root == roots.hash_chain {
            RootFlavor::HashChain
        } else {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                "prev_root mismatch".to_string(),
            )));
        };

        self.verify_wallet_transition_proofs(&state, &wallets, &transitions, batch)?;

        // Use executor for applying transitions
        let mut executor = InMemoryExecutor::new(state);
        for (wallet_id, transition) in wallets.iter().zip(transitions.iter()) {
            executor.apply_wallet_transition(*wallet_id, transition)?;
        }
        let post_state = executor.get_all_wallets()?;
        let post_roots = self.compute_roots(&post_state)?;
        let post = match flavor {
            RootFlavor::Proof => post_roots.proof,
            RootFlavor::HashChain => post_roots.hash_chain,
        };
        if post != batch.post_commitment_root {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                "post_root mismatch".to_string(),
            )));
        }

        // Enforce uniqueness transition witness invariant
        // Use pre_state and post_state from executor (already computed above)
        let next_root = post;

        // Build commitments_before from pre_state (self.wallets)
        // Use stored commitments to match what was used to compute prev_root
        // For wallets being updated, ensure they're in the map (even if with uninitialized commitment)
        let mut commitments_before: std::collections::BTreeMap<WalletId, WalletCommitment> =
            self.wallets.iter().map(|(id, state)| (*id, state.commitment)).collect();
        // Add wallets from the batch that might not be in self.wallets yet
        for wallet_id in wallets.iter() {
            if !commitments_before.contains_key(wallet_id) {
                // Wallet doesn't exist yet, use empty commitment
                let empty_commitment = compute_commitment_from_channels(
                    *wallet_id,
                    &std::collections::BTreeMap::new(),
                )
                .unwrap_or([0u8; 32]);
                commitments_before.insert(*wallet_id, empty_commitment);
            }
        }

        // Build commitments_after from post_state
        // Use stored commitments to match what will be used to compute next_root
        let commitments_after: std::collections::BTreeMap<WalletId, WalletCommitment> =
            post_state.iter().map(|(id, state)| (*id, state.commitment)).collect();

        // Create providers once and reuse them for all wallets (O(n) instead of O(n²))
        let mut provider_old = InMemorySiblingProvider::new(&commitments_before);
        let mut provider_new = InMemorySiblingProvider::new(&commitments_after);

        // Create transition witnesses for each wallet transition and enforce invariant
        for wallet_id in wallets.iter() {
            // Use commitments from the maps (which match what was used to compute roots)
            // This ensures merkle proofs verify correctly
            let old_wallet_commitment = *commitments_before.get(wallet_id).ok_or_else(|| {
                crate::Error::Global(crate::errors::GlobalError::Internal(format!(
                    "Wallet {:?} not found in commitments_before",
                    wallet_id
                )))
            })?;

            // Belt-and-suspenders: verify stored commitment matches recomputed (when initialized)
            if let Some(state) = self.wallets.get(wallet_id) {
                let recomputed = compute_commitment_from_channels(*wallet_id, &state.channels)?;
                // Only check if stored commitment is initialized (not all zeros)
                if state.commitment != [0u8; 32] && state.commitment != recomputed {
                    return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                        format!(
                        "Wallet commitment mismatch for wallet {:?}: stored {:?}, recomputed {:?}",
                        wallet_id, state.commitment, recomputed
                    ),
                    )));
                }
            }

            let new_wallet_commitment = *commitments_after.get(wallet_id).ok_or_else(|| {
                crate::Error::Global(crate::errors::GlobalError::Internal(format!(
                    "Wallet {:?} not found in commitments_after",
                    wallet_id
                )))
            })?;

            // Belt-and-suspenders: verify stored commitment matches recomputed (when initialized)
            if let Some(state) = post_state.get(wallet_id) {
                let recomputed = compute_commitment_from_channels(*wallet_id, &state.channels)?;
                // Only check if stored commitment is initialized (not all zeros)
                if state.commitment != [0u8; 32] && state.commitment != recomputed {
                    return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                        format!(
                        "Wallet commitment mismatch for wallet {:?}: stored {:?}, recomputed {:?}",
                        wallet_id, state.commitment, recomputed
                    ),
                    )));
                }
            }

            // Generate old merkle proof from commitments_before snapshot
            let merkle_proof_old = generate_merkle_proof(
                *wallet_id,
                &Poseidon2Hasher,
                &MerkleMorphV0Config,
                &mut provider_old,
            )?;

            // Generate new merkle proof from commitments_after snapshot
            let merkle_proof_new = generate_merkle_proof(
                *wallet_id,
                &Poseidon2Hasher,
                &MerkleMorphV0Config,
                &mut provider_new,
            )?;

            // Verify proofs against the roots they claim to prove
            let old_proof_valid = verify_merkle_proof_with(
                *wallet_id,
                old_wallet_commitment,
                &merkle_proof_old,
                prev_root,
                &Poseidon2Hasher,
                &MerkleMorphV0Config,
            )?;
            if !old_proof_valid {
                return Err(crate::Error::Global(crate::errors::GlobalError::Internal(format!(
                    "Old merkle proof does not verify against prev_root for wallet {:?}",
                    wallet_id
                ))));
            }

            let new_proof_valid = verify_merkle_proof_with(
                *wallet_id,
                new_wallet_commitment,
                &merkle_proof_new,
                next_root,
                &Poseidon2Hasher,
                &MerkleMorphV0Config,
            )?;
            if !new_proof_valid {
                return Err(crate::Error::Global(crate::errors::GlobalError::Internal(format!(
                    "New merkle proof does not verify against next_root for wallet {:?}",
                    wallet_id
                ))));
            }

            // Create transition witness
            let witness = crate::global::commitment::GlobalTransitionWitness {
                wallet_id: *wallet_id,
                prev_root,
                old_wallet_commitment,
                merkle_proof_old,
                next_root,
                new_wallet_commitment,
                merkle_proof_new,
            };

            // Insert into cache (enforces invariant)
            witness_cache.insert(&witness)?;
        }

        self.verify_proofs(batch)?;
        Ok(post)
    }

    fn compute_roots(
        &self,
        wallets: &BTreeMap<crate::types::WalletId, WalletState>,
    ) -> Result<ComputedRoots> {
        Ok(ComputedRoots {
            hash_chain: compute_global_root_from_wallets(wallets),
            proof: self.compute_proof_root(wallets)?,
        })
    }

    fn compute_proof_root(
        &self,
        wallets: &BTreeMap<crate::types::WalletId, WalletState>,
    ) -> Result<GlobalRoot> {
        if wallets.is_empty() {
            return Ok([0u8; 32]);
        }

        let wallet_commitments: BTreeMap<crate::types::WalletId, WalletCommitment> =
            wallets.iter().map(|(id, state)| (*id, state.commitment)).collect();
        let min_id = *wallet_commitments.keys().next().ok_or_else(|| {
            crate::Error::Global(crate::errors::GlobalError::Internal(
                "wallet commitments unexpectedly empty".to_string(),
            ))
        })?;
        let max_id = *wallet_commitments.keys().last().ok_or_else(|| {
            crate::Error::Global(crate::errors::GlobalError::Internal(
                "wallet commitments unexpectedly empty".to_string(),
            ))
        })?;
        let subtree = compute_subtree_root(&self.config, &wallet_commitments, min_id, max_id)?;
        compose_to_global_root(std::slice::from_ref(&subtree))
    }

    fn verify_proofs(&self, batch: &Batch) -> Result<()> {
        if let Some(batch_proof) = &batch.proofs.batch_proof {
            crate::zkp::global::verify_global_root_composition(
                &self.config,
                batch.post_commitment_root,
                batch_proof,
            )?;
        }
        Ok(())
    }

    /// Verify wallet transition proofs for all transitions in a batch.
    ///
    /// Groups transitions by wallet and verifies the proof for each wallet's sequence of transitions.
    fn verify_wallet_transition_proofs(
        &self,
        pre_state: &BTreeMap<WalletId, WalletState>,
        affected_wallets: &[WalletId],
        transitions: &[WalletTransition],
        batch: &Batch,
    ) -> Result<()> {
        use std::collections::HashMap;

        // Group transitions by wallet
        let mut wallet_transitions: HashMap<WalletId, Vec<(usize, &WalletTransition)>> =
            HashMap::new();
        for (idx, (wallet_id, transition)) in
            affected_wallets.iter().zip(transitions.iter()).enumerate()
        {
            wallet_transitions.entry(*wallet_id).or_default().push((idx, transition));
        }

        // Verify proof for each wallet's sequence of transitions
        for (wallet_id, wallet_trans_list) in wallet_transitions.iter() {
            if wallet_trans_list.is_empty() {
                continue;
            }

            let first_idx = wallet_trans_list[0].0;
            let proof = match batch.proofs.wallet_transition_proofs.get(first_idx) {
                Some(Some(p)) => p.as_ref(),
                Some(None) => {
                    return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                        format!("proof is missing for wallet transition at index {}", first_idx),
                    )));
                }
                None => {
                    return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                        format!("missing proof index {} for wallet transition", first_idx),
                    )));
                }
            };

            // Get initial wallet state
            let initial_wallet =
                pre_state.get(wallet_id).cloned().unwrap_or_else(|| WalletState::new(*wallet_id));

            // Replay transitions to get final state
            let mut current_wallet = initial_wallet.clone();
            for (_, transition) in wallet_trans_list.iter() {
                current_wallet =
                    crate::wallet::transition::apply_operation(current_wallet, transition)?;
            }

            // Compute commitments
            let initial_commitment =
                compute_commitment_from_channels(*wallet_id, &initial_wallet.channels)?;
            let final_commitment =
                compute_commitment_from_channels(*wallet_id, &current_wallet.channels)?;

            // Verify the proof
            let public_inputs = WalletTransitionPublicInputs {
                wallet_id: *wallet_id,
                initial_wallet_commitment: initial_commitment,
                final_wallet_commitment: final_commitment,
            };

            verify_wallet_transition(&self.config, &public_inputs, proof).map_err(|e| {
                crate::Error::Global(crate::errors::GlobalError::Internal(format!(
                    "wallet transition proof verification failed for wallet {:?}: {:?}",
                    wallet_id, e
                )))
            })?;
        }

        Ok(())
    }
}

struct ComputedRoots {
    hash_chain: GlobalRoot,
    proof: GlobalRoot,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use super::*;
    use crate::scheduler::batch::{BatchProofBundle, FeeMetadata};
    use crate::scheduler::da::InMemoryDAStore;
    use crate::scheduler::sequencer::{BasicSchedulingRules, InMemorySequencer};
    use crate::scheduler::{AccessSet, Sequencer, UpdateEnvelope};
    use crate::{create_config, WalletTransition};

    #[test]
    fn test_new() {
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let config = Rc::new(create_config().expect("config should build"));
        let da = InMemoryDAStore::new();
        let _verifier = InMemoryBatchVerifier::new(da, wallets, config);
    }

    #[test]
    fn test_verify_batch() -> crate::Result<()> {
        let wallet_id = [1u8; 32];
        let channel_id = [2u8; 32];
        let channel_commitment = [3u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let config = Rc::new(create_config().expect("config should build"));

        let mut sequencer = InMemorySequencer::new(BasicSchedulingRules::new(4), wallets.clone());
        let envelope = UpdateEnvelope {
            transition: WalletTransition::InsertChannel { channel_id, channel_commitment },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: Some(1),
            submit_order: 0,
        };
        sequencer.ingest(envelope)?;
        let batch_with_proofs = sequencer.build_next_batch_with_proofs(&config)?;
        let _batch_no_proofs = sequencer.build_next_batch()?;

        let da_store = InMemoryDAStore::new();
        let body = batch_with_proofs.serialize_body();
        let _da_hash = da_store.publish(&body)?;

        let verifier = InMemoryBatchVerifier::new(da_store, wallets.clone(), config.clone());
        let verified_root =
            verifier.verify_batch(batch_with_proofs.pre_commitment_root, &batch_with_proofs)?;
        assert_eq!(verified_root, batch_with_proofs.post_commitment_root);

        let da_empty = InMemoryDAStore::new();
        let verifier_empty = InMemoryBatchVerifier::new(da_empty, wallets.clone(), config.clone());
        let _body_serialized = batch_with_proofs.serialize_body();
        let _result_empty =
            verifier_empty.verify_batch(batch_with_proofs.pre_commitment_root, &batch_with_proofs);

        let invalid_hash = [255u8; 32];
        let invalid_batch = Batch::new(
            batch_with_proofs.transitions.clone(),
            batch_with_proofs.affected_wallets.clone(),
            batch_with_proofs.pre_commitment_root,
            batch_with_proofs.post_commitment_root,
            batch_with_proofs.local_batch_num,
            invalid_hash,
            batch_with_proofs.fee_info.clone(),
            BatchProofBundle {
                batch_proof: None,
                wallet_transition_proofs: vec![
                    None;
                    batch_with_proofs
                        .proofs
                        .wallet_transition_proofs
                        .len()
                ],
            },
        );
        let invalid_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config.clone());
        let _result_invalid =
            invalid_verifier.verify_batch(invalid_batch.pre_commitment_root, &invalid_batch);

        let batch_num_mismatch = Batch::new(
            batch_with_proofs.transitions.clone(),
            batch_with_proofs.affected_wallets.clone(),
            batch_with_proofs.pre_commitment_root,
            batch_with_proofs.post_commitment_root,
            batch_with_proofs.local_batch_num + 1,
            batch_with_proofs.da_hash,
            batch_with_proofs.fee_info.clone(),
            BatchProofBundle {
                batch_proof: None,
                wallet_transition_proofs: vec![
                    None;
                    batch_with_proofs
                        .proofs
                        .wallet_transition_proofs
                        .len()
                ],
            },
        );
        let batch_num_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config.clone());
        let _result_batch_num = batch_num_verifier
            .verify_batch(batch_num_mismatch.pre_commitment_root, &batch_num_mismatch);

        let hash_chain_root = compute_global_root_from_wallets(&wallets);
        let proof_root_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config.clone());
        let batch_hash_chain = Batch::new(
            vec![],
            vec![],
            hash_chain_root,
            hash_chain_root,
            0,
            [0u8; 32],
            FeeMetadata { fee_rate: None, payer: None },
            BatchProofBundle { batch_proof: None, wallet_transition_proofs: vec![] },
        );
        let _result_hash_chain =
            proof_root_verifier.verify_batch(hash_chain_root, &batch_hash_chain);

        let wrong_prev = [9u8; 32];
        let prev_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config.clone());
        let _result_prev = prev_verifier.verify_batch(wrong_prev, &batch_with_proofs);

        let post_mismatch = Batch::new(
            batch_with_proofs.transitions.clone(),
            batch_with_proofs.affected_wallets.clone(),
            batch_with_proofs.pre_commitment_root,
            [7u8; 32],
            batch_with_proofs.local_batch_num,
            batch_with_proofs.da_hash,
            batch_with_proofs.fee_info.clone(),
            BatchProofBundle {
                batch_proof: None,
                wallet_transition_proofs: vec![
                    None;
                    batch_with_proofs
                        .proofs
                        .wallet_transition_proofs
                        .len()
                ],
            },
        );
        let post_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config.clone());
        let _result_post =
            post_verifier.verify_batch(post_mismatch.pre_commitment_root, &post_mismatch);

        let batch_empty = Batch::new(
            vec![],
            vec![],
            batch_with_proofs.pre_commitment_root,
            batch_with_proofs.post_commitment_root,
            batch_with_proofs.local_batch_num,
            batch_with_proofs.da_hash,
            FeeMetadata { fee_rate: None, payer: None },
            BatchProofBundle { batch_proof: None, wallet_transition_proofs: vec![] },
        );
        let empty_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config.clone());
        let _result_empty =
            empty_verifier.verify_batch(batch_empty.pre_commitment_root, &batch_empty);

        let batch_no_wallet_proof = Batch::new(
            batch_with_proofs.transitions.clone(),
            batch_with_proofs.affected_wallets.clone(),
            batch_with_proofs.pre_commitment_root,
            batch_with_proofs.post_commitment_root,
            batch_with_proofs.local_batch_num,
            batch_with_proofs.da_hash,
            batch_with_proofs.fee_info.clone(),
            BatchProofBundle { batch_proof: None, wallet_transition_proofs: vec![None] },
        );
        let no_wallet_proof_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config.clone());
        let _result_no_wallet_proof = no_wallet_proof_verifier
            .verify_batch(batch_no_wallet_proof.pre_commitment_root, &batch_no_wallet_proof);

        let batch_missing_proof_index = Batch::new(
            batch_with_proofs.transitions.clone(),
            batch_with_proofs.affected_wallets.clone(),
            batch_with_proofs.pre_commitment_root,
            batch_with_proofs.post_commitment_root,
            batch_with_proofs.local_batch_num,
            batch_with_proofs.da_hash,
            batch_with_proofs.fee_info.clone(),
            BatchProofBundle { batch_proof: None, wallet_transition_proofs: vec![] },
        );
        let missing_index_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config);
        let _result_missing_index = missing_index_verifier.verify_batch(
            batch_missing_proof_index.pre_commitment_root,
            &batch_missing_proof_index,
        );

        Ok(())
    }

    #[test]
    fn test_replay_batch() -> crate::Result<()> {
        let wallet_id = [1u8; 32];
        let channel_id = [2u8; 32];
        let channel_commitment = [3u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, WalletState::new(wallet_id));
        let config = Rc::new(create_config().expect("config should build"));

        let mut sequencer = InMemorySequencer::new(BasicSchedulingRules::new(4), wallets.clone());
        let envelope = UpdateEnvelope {
            transition: WalletTransition::InsertChannel { channel_id, channel_commitment },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: Some(1),
            submit_order: 0,
        };
        sequencer.ingest(envelope)?;
        let batch = sequencer.build_next_batch()?;

        let da_store = InMemoryDAStore::new();
        let body = batch.serialize_body();
        let _da_hash = da_store.publish(&body)?;

        let verifier = InMemoryBatchVerifier::new(da_store, wallets.clone(), config.clone());
        let replayed = verifier.replay_batch(batch.pre_commitment_root, &batch)?;
        assert_eq!(replayed, batch.post_commitment_root);

        let da_empty = InMemoryDAStore::new();
        let verifier_empty = InMemoryBatchVerifier::new(da_empty, wallets.clone(), config.clone());
        let replayed_empty = verifier_empty.replay_batch(batch.pre_commitment_root, &batch)?;
        assert_eq!(replayed_empty, batch.post_commitment_root);

        let invalid_hash = [255u8; 32];
        let invalid_batch = Batch::new(
            batch.transitions.clone(),
            batch.affected_wallets.clone(),
            batch.pre_commitment_root,
            batch.post_commitment_root,
            batch.local_batch_num,
            invalid_hash,
            batch.fee_info.clone(),
            BatchProofBundle {
                batch_proof: None,
                wallet_transition_proofs: vec![None; batch.proofs.wallet_transition_proofs.len()],
            },
        );
        let invalid_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config.clone());
        let _result_invalid =
            invalid_verifier.replay_batch(invalid_batch.pre_commitment_root, &invalid_batch);

        let batch_num_mismatch = Batch::new(
            batch.transitions.clone(),
            batch.affected_wallets.clone(),
            batch.pre_commitment_root,
            batch.post_commitment_root,
            batch.local_batch_num + 1,
            batch.da_hash,
            batch.fee_info.clone(),
            BatchProofBundle {
                batch_proof: None,
                wallet_transition_proofs: vec![None; batch.proofs.wallet_transition_proofs.len()],
            },
        );
        let batch_num_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config.clone());
        let _result_batch_num = batch_num_verifier
            .replay_batch(batch_num_mismatch.pre_commitment_root, &batch_num_mismatch);

        let hash_chain_root = compute_global_root_from_wallets(&wallets);
        let proof_root_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config.clone());
        let batch_hash_chain = Batch::new(
            vec![],
            vec![],
            hash_chain_root,
            hash_chain_root,
            0,
            [0u8; 32],
            FeeMetadata { fee_rate: None, payer: None },
            BatchProofBundle { batch_proof: None, wallet_transition_proofs: vec![] },
        );
        let _result_hash_chain =
            proof_root_verifier.replay_batch(hash_chain_root, &batch_hash_chain);

        let wrong_prev = [9u8; 32];
        let prev_verifier =
            InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets.clone(), config.clone());
        let _result_prev = prev_verifier.replay_batch(wrong_prev, &batch);

        let post_mismatch = Batch::new(
            batch.transitions.clone(),
            batch.affected_wallets.clone(),
            batch.pre_commitment_root,
            [7u8; 32],
            batch.local_batch_num,
            batch.da_hash,
            batch.fee_info.clone(),
            BatchProofBundle {
                batch_proof: None,
                wallet_transition_proofs: vec![None; batch.proofs.wallet_transition_proofs.len()],
            },
        );
        let post_verifier = InMemoryBatchVerifier::new(InMemoryDAStore::new(), wallets, config);
        let _result_post =
            post_verifier.replay_batch(post_mismatch.pre_commitment_root, &post_mismatch);

        Ok(())
    }
}
