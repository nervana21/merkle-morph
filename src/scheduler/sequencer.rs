// SPDX-License-Identifier: CC0-1.0

//! Sequencer abstraction: deterministic orchestrator that builds batches.
//!
//! This defines the scheduler/sequencer surface: ingest updates, determine
//! schedulability, order non-conflicting updates, apply them to global state,
//! produce proofs, publish DA, and prepare anchors. Implementations remain
//! swappable (single-threaded, sharded, optimistic, etc.).

use std::collections::BTreeMap;

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{Network, TxOut};

use crate::errors::GlobalError;
use crate::global::commitment::types::GlobalRoot;
use crate::scheduler::executor::{Executor, InMemoryExecutor};
use crate::types::{P2A_DEFAULT_NETWORK, P2A_DEFAULT_VALUE_SATS};
use crate::{
    build_p2a_txout, derive_default_p2a_internal_key, prove_wallet_transition, Batch, Result,
    WalletCommitment, WalletId, WalletState, WalletTransition,
};

/// Identifier for an ingested transition.
pub type TransitionId = u64;

/// Outcome of simulating an update against current state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SimulationResult {
    /// Wallets this update would affect.
    pub affected_wallets: Vec<WalletId>,
    /// Expected post-global root if applied in isolation (for admission checks).
    pub tentative_root: Option<GlobalRoot>,
    /// Whether the update is admissible given current head state.
    pub admissible: bool,
}

/// Access set describes which wallets/channels/prefixes an update touches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessSet {
    /// Wallets touched by the update.
    pub wallets: Vec<WalletId>,
    /// Optional opaque prefixes for finer-grained locking (e.g., SMT prefix bytes).
    pub prefixes: Vec<Vec<u8>>,
}

impl AccessSet {
    /// Construct an access set from wallets only.
    pub fn from_wallets(wallets: Vec<WalletId>) -> Self { Self { wallets, prefixes: Vec::new() } }
}

/// Envelope for an incoming update plus scheduling metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateEnvelope {
    /// Wallet transition payload.
    pub transition: WalletTransition,
    /// Declared access set for conflict detection.
    pub access_set: AccessSet,
    /// Optional fee or priority metadata.
    pub fee_rate: Option<u64>,
    /// Submission order hint (monotonic per sequencer instance).
    pub submit_order: u64,
}

/// Ordered, conflict-resolved update selected for a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedUpdate {
    /// Identifier assigned at ingestion.
    pub id: TransitionId,
    /// Original envelope.
    pub envelope: UpdateEnvelope,
}

/// Canonical scheduling policy interface.
pub trait SchedulingRules {
    /// Returns true if `candidate` conflicts with any `active` access set.
    fn conflicts(&self, candidate: &AccessSet, active: &[AccessSet]) -> bool;

    /// Deterministically order admitted updates into a batch.
    fn order(&self, candidates: Vec<UpdateEnvelope>) -> Vec<UpdateEnvelope>;

    /// Optional batch size limit; None means unbounded.
    fn max_batch_items(&self) -> Option<usize> { None }
}

/// Sequencer interface for building batches.
pub trait Sequencer {
    /// Ingest a new update; returns a transition id.
    fn ingest(&mut self, envelope: UpdateEnvelope) -> Result<TransitionId>;

    /// Check if an update would be schedulable given current pending/active sets.
    fn schedulable(&self, envelope: &UpdateEnvelope) -> bool;

    /// Simulate an update against the current head state to aid admission.
    fn simulate(&self, envelope: &UpdateEnvelope) -> Result<SimulationResult>;

    /// Build the next batch from pending updates according to scheduling rules.
    fn build_next_batch(&mut self) -> Result<Batch>;

    /// Build the next batch and publish it to the data availability store.
    ///
    /// This method builds a batch and automatically publishes it to the provided DA store,
    /// updating the batch's `da_hash` field with the published hash.
    fn build_next_batch_with_da(
        &mut self,
        da: &dyn crate::scheduler::da::DAStore,
    ) -> Result<Batch> {
        let mut batch = self.build_next_batch()?;
        let blob = batch.serialize_body();
        batch.da_hash = da.publish(&blob)?;
        Ok(batch)
    }

    /// Build the next batch and attach wallet/global proofs using the provided ZKP config.
    fn build_next_batch_with_proofs(
        &mut self,
        config: &crate::zkp::types::StarkConfig,
    ) -> Result<Batch>;

    /// Build the next batch with proofs and publish it to the data availability store.
    ///
    /// This method builds a batch with proofs and automatically publishes it to the provided DA store,
    /// updating the batch's `da_hash` field with the published hash.
    fn build_next_batch_with_proofs_and_da(
        &mut self,
        config: &crate::zkp::types::StarkConfig,
        da: &dyn crate::scheduler::da::DAStore,
    ) -> Result<Batch> {
        let mut batch = self.build_next_batch_with_proofs(config)?;
        let blob = batch.serialize_body();
        batch.da_hash = da.publish(&blob)?;
        Ok(batch)
    }

    /// Produce a P2A taproot anchor output from a batch.
    fn anchor_payload(&self, batch: &Batch) -> Result<TxOut>;

    /// Expose the current global root and sequence number.
    fn head(&self) -> (GlobalRoot, u32);
}

/// Simple fee/submit-order-based scheduling rules over access sets.
#[derive(Clone, Debug, Default)]
pub struct BasicSchedulingRules {
    /// Maximum transitions per batch.
    pub max_batch_items: usize,
}

impl BasicSchedulingRules {
    /// Construct scheduling rules with a maximum batch size.
    pub fn new(max_batch_items: usize) -> Self { Self { max_batch_items } }
}

impl SchedulingRules for BasicSchedulingRules {
    fn conflicts(&self, candidate: &AccessSet, active: &[AccessSet]) -> bool {
        active.iter().any(|a| {
            a.wallets.iter().any(|w| candidate.wallets.contains(w))
                || a.prefixes.iter().any(|p| candidate.prefixes.contains(p))
        })
    }

    fn order(&self, mut candidates: Vec<UpdateEnvelope>) -> Vec<UpdateEnvelope> {
        // Order by fee_rate desc, then submit_order asc, then lexical of transition bytes.
        candidates.sort_by(|a, b| {
            let fee_a = a.fee_rate.unwrap_or(0);
            let fee_b = b.fee_rate.unwrap_or(0);
            fee_b
                .cmp(&fee_a)
                .then_with(|| a.submit_order.cmp(&b.submit_order))
                .then_with(|| format!("{:?}", a.transition).cmp(&format!("{:?}", b.transition)))
        });
        candidates
    }

    fn max_batch_items(&self) -> Option<usize> { Some(self.max_batch_items) }
}

/// In-memory sequencer implementation using wallet/channel state (not UTXOs).
///
/// The sequencer uses an `Executor` to manage wallet state and apply transitions.
/// By default, it uses `InMemoryExecutor`, but any executor implementation can be used.
pub struct InMemorySequencer<R: SchedulingRules, E: Executor = InMemoryExecutor> {
    rules: R,
    pending: Vec<(TransitionId, UpdateEnvelope)>,
    next_id: TransitionId,
    executor: E,
    global_root: GlobalRoot,
    local_batch_num: u32,
    anchor_internal_key: XOnlyPublicKey,
    anchor_network: Network,
}

impl<R: SchedulingRules> InMemorySequencer<R, InMemoryExecutor> {
    /// Create a new sequencer with an initial wallet map and head.
    ///
    /// This constructor uses `InMemoryExecutor` by default.
    pub fn new(rules: R, wallets: BTreeMap<WalletId, crate::wallet::state::WalletState>) -> Self {
        let executor = InMemoryExecutor::new(wallets);
        let global_root =
            executor.compute_global_root().expect("global root computation should succeed");
        let anchor_internal_key_bitcoin =
            derive_default_p2a_internal_key().expect("default P2A internal key must be valid");
        let anchor_internal_key_bytes = anchor_internal_key_bitcoin.serialize();
        let anchor_internal_key =
            bitcoin::secp256k1::XOnlyPublicKey::from_byte_array(anchor_internal_key_bytes)
                .expect("32-byte array should always be a valid XOnlyPublicKey");
        Self {
            rules,
            pending: Vec::new(),
            next_id: 0,
            executor,
            global_root,
            local_batch_num: 0,
            anchor_internal_key,
            anchor_network: P2A_DEFAULT_NETWORK,
        }
    }
}

impl<R: SchedulingRules, E: Executor> InMemorySequencer<R, E> {
    /// Create a new sequencer with a custom executor.
    ///
    /// This allows using different executor implementations (e.g., database-backed,
    /// distributed) while maintaining the same sequencer interface.
    pub fn with_executor(rules: R, executor: E) -> Result<Self> {
        let global_root = executor.compute_global_root()?;
        let anchor_internal_key_bitcoin =
            derive_default_p2a_internal_key().expect("default P2A internal key must be valid");
        let anchor_internal_key_bytes = anchor_internal_key_bitcoin.serialize();
        let anchor_internal_key =
            bitcoin::secp256k1::XOnlyPublicKey::from_byte_array(anchor_internal_key_bytes)
                .map_err(|e| {
                    GlobalError::InvalidParameters(format!(
                        "Failed to convert anchor internal key: {e}"
                    ))
                })?;
        Ok(Self {
            rules,
            pending: Vec::new(),
            next_id: 0,
            executor,
            global_root,
            local_batch_num: 0,
            anchor_internal_key,
            anchor_network: P2A_DEFAULT_NETWORK,
        })
    }

    fn single_wallet_id(envelope: &UpdateEnvelope) -> Result<WalletId> {
        match envelope.access_set.wallets.as_slice() {
            [wallet_id] => Ok(*wallet_id),
            [] => Err(crate::Error::Global(GlobalError::InvalidParameters(
                "access_set must contain exactly one wallet id for a transition".into(),
            ))),
            _ => Err(crate::Error::Global(GlobalError::InvalidParameters(
                "multi-wallet access sets are unsupported for a single wallet transition".into(),
            ))),
        }
    }

    fn select_batch(&self) -> Vec<(TransitionId, UpdateEnvelope)> {
        // Work over owned (id, env) tuples to avoid re-scans.
        let mut owned: Vec<(TransitionId, UpdateEnvelope)> = self.pending.clone();
        owned.sort_by(|(_, a), (_, b)| {
            let fee_a = a.fee_rate.unwrap_or(0);
            let fee_b = b.fee_rate.unwrap_or(0);
            fee_b
                .cmp(&fee_a)
                .then_with(|| a.submit_order.cmp(&b.submit_order))
                .then_with(|| format!("{:?}", a.transition).cmp(&format!("{:?}", b.transition)))
        });
        let mut selected = Vec::new();
        let mut active_sets: Vec<AccessSet> = Vec::new();
        for (id, env) in owned.into_iter() {
            if self.rules.conflicts(&env.access_set, &active_sets) {
                continue;
            }
            active_sets.push(env.access_set.clone());
            selected.push((id, env));
            if let Some(limit) = self.rules.max_batch_items() {
                if limit > 0 && selected.len() >= limit {
                    break;
                }
            }
        }
        selected
    }
}

impl<R: SchedulingRules, E: Executor> Sequencer for InMemorySequencer<R, E> {
    fn ingest(&mut self, envelope: UpdateEnvelope) -> Result<TransitionId> {
        let id = self.next_id;
        self.next_id += 1;
        self.pending.push((id, envelope));
        Ok(id)
    }

    fn schedulable(&self, envelope: &UpdateEnvelope) -> bool {
        let active: Vec<AccessSet> =
            self.pending.iter().map(|(_, e)| e.access_set.clone()).collect();
        !self.rules.conflicts(&envelope.access_set, &active)
    }

    fn simulate(&self, envelope: &UpdateEnvelope) -> Result<SimulationResult> {
        let wallet_id = Self::single_wallet_id(envelope)?;
        // Create a temporary in-memory executor for simulation by snapshotting current state
        // This works with any executor type by using get_all_wallets() to create a snapshot
        let wallets = self.executor.get_all_wallets()?;
        let mut sim_executor = InMemoryExecutor::new(wallets);
        let _ = sim_executor.apply_wallet_transition(wallet_id, &envelope.transition)?;
        let tentative_root = sim_executor.compute_global_root()?;
        Ok(SimulationResult {
            affected_wallets: vec![wallet_id],
            tentative_root: Some(tentative_root),
            admissible: true,
        })
    }

    fn build_next_batch(&mut self) -> Result<Batch> {
        let pre_root = self.global_root;
        let selected = self.select_batch();

        let mut ordered_transitions = Vec::new();
        let mut affected_wallets = Vec::new();

        for (_, env) in selected.iter() {
            // Wallet transitions are single-wallet; enforce and fail fast otherwise.
            let wallet_id = Self::single_wallet_id(env)?;
            self.executor.apply_wallet_transition(wallet_id, &env.transition)?;
            ordered_transitions.push(env.transition.clone());
            affected_wallets.push(wallet_id);
        }

        let post_root = self.executor.compute_global_root()?;
        let local_batch_num = self.local_batch_num + 1;

        // remove selected from pending
        let selected_ids: std::collections::HashSet<_> =
            selected.iter().map(|(id, _)| *id).collect();
        self.pending.retain(|(id, _)| !selected_ids.contains(id));

        // commit state
        self.global_root = post_root;
        self.local_batch_num = local_batch_num;

        let fee_info = crate::scheduler::batch::FeeMetadata { fee_rate: None, payer: None };
        let mut wallet_proofs = Vec::new();
        for _ in 0..ordered_transitions.len() {
            wallet_proofs.push(None);
        }
        let proofs = crate::scheduler::batch::BatchProofBundle {
            batch_proof: None,
            wallet_transition_proofs: wallet_proofs,
        };
        let mut batch = Batch::new(
            ordered_transitions,
            affected_wallets,
            pre_root,
            post_root,
            local_batch_num,
            [0u8; 32],
            fee_info,
            proofs,
        );
        let da_hash = batch.compute_da_hash();
        batch.da_hash = da_hash;
        Ok(batch)
    }

    fn build_next_batch_with_proofs(
        &mut self,
        config: &crate::zkp::types::StarkConfig,
    ) -> Result<Batch> {
        let pre_wallets = self.executor.get_all_wallets()?;
        let mut batch = self.build_next_batch()?;

        let wallet_transition_proofs = Self::generate_wallet_transition_proofs(
            config,
            &pre_wallets,
            &batch.affected_wallets,
            &batch.transitions,
        )?;

        let (mut proofs, post_root_from_proof) = self.generate_proofs_for_batch(config, &batch)?;
        proofs.wallet_transition_proofs = wallet_transition_proofs;

        let proof_pre_root = Self::compute_proof_root(config, &pre_wallets)?;
        batch.pre_commitment_root = proof_pre_root;
        batch.post_commitment_root = post_root_from_proof;
        self.global_root = post_root_from_proof;
        batch.proofs = proofs;
        Ok(batch)
    }

    fn anchor_payload(&self, batch: &Batch) -> Result<TxOut> {
        let anchor_internal_key_bytes = self.anchor_internal_key.serialize();
        let anchor_internal_key_bitcoin = bitcoin::key::XOnlyPublicKey::from_byte_array(
            &anchor_internal_key_bytes,
        )
        .map_err(|e| {
            GlobalError::InvalidParameters(format!("Failed to convert anchor internal key: {e}"))
        })?;
        build_p2a_txout(
            batch.post_commitment_root,
            batch.local_batch_num,
            anchor_internal_key_bitcoin,
            P2A_DEFAULT_VALUE_SATS,
            self.anchor_network,
        )
        .map_err(|e| {
            GlobalError::InvalidParameters(format!("Failed to build P2A txout: {e}")).into()
        })
    }

    fn head(&self) -> (GlobalRoot, u32) { (self.global_root, self.local_batch_num) }
}

impl<R: SchedulingRules, E: Executor> InMemorySequencer<R, E> {
    fn generate_proofs_for_batch(
        &self,
        config: &crate::zkp::types::StarkConfig,
        _batch: &Batch,
    ) -> Result<(crate::scheduler::batch::BatchProofBundle, GlobalRoot)> {
        let wallets = self.executor.get_all_wallets()?;
        if wallets.is_empty() {
            return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                "cannot generate proofs with no wallets".to_string(),
            )));
        }

        let wallet_commitments: BTreeMap<WalletId, WalletCommitment> =
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
        let subtree = crate::global::commitment::compute_subtree_root(
            config,
            &wallet_commitments,
            min_id,
            max_id,
        )?;
        let post_root =
            crate::global::commitment::compose_to_global_root(std::slice::from_ref(&subtree))?;
        let batch_proof = crate::zkp::global::prove_global_root_composition(
            config,
            std::slice::from_ref(&subtree),
        )?;

        Ok((
            crate::scheduler::batch::BatchProofBundle {
                batch_proof: Some(batch_proof),
                wallet_transition_proofs: vec![],
            },
            post_root,
        ))
    }

    fn compute_proof_root(
        config: &crate::zkp::types::StarkConfig,
        wallets: &BTreeMap<WalletId, crate::wallet::state::WalletState>,
    ) -> Result<GlobalRoot> {
        if wallets.is_empty() {
            return Ok([0u8; 32]);
        }

        let wallet_commitments: BTreeMap<WalletId, WalletCommitment> =
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
        let subtree = crate::global::commitment::compute_subtree_root(
            config,
            &wallet_commitments,
            min_id,
            max_id,
        )?;
        crate::global::commitment::compose_to_global_root(std::slice::from_ref(&subtree))
    }

    /// Generate wallet transition proofs for all transitions in a batch.
    ///
    /// Groups transitions by wallet and generates one proof per wallet for all its transitions.
    /// Returns a vector of proofs, one per transition in the batch order.
    fn generate_wallet_transition_proofs(
        config: &crate::zkp::types::StarkConfig,
        pre_wallets: &BTreeMap<WalletId, WalletState>,
        affected_wallets: &[WalletId],
        transitions: &[WalletTransition],
    ) -> Result<Vec<Option<std::sync::Arc<crate::Proof>>>> {
        use std::collections::HashMap;

        let mut wallet_transitions: HashMap<WalletId, Vec<(usize, &WalletTransition)>> =
            HashMap::new();
        for (idx, (wallet_id, transition)) in
            affected_wallets.iter().zip(transitions.iter()).enumerate()
        {
            wallet_transitions.entry(*wallet_id).or_default().push((idx, transition));
        }

        let mut proofs: Vec<Option<std::sync::Arc<crate::Proof>>> = Vec::new();
        for _ in 0..transitions.len() {
            proofs.push(None);
        }

        for (wallet_id, wallet_trans_list) in wallet_transitions.iter() {
            if wallet_trans_list.is_empty() {
                continue;
            }

            let initial_wallet =
                pre_wallets.get(wallet_id).cloned().unwrap_or_else(|| WalletState::new(*wallet_id));

            let mut wallet_states = vec![initial_wallet.clone()];
            let mut wallet_transitions_seq: Vec<&WalletTransition> = Vec::new();
            let mut current_wallet = initial_wallet;

            for (_, transition) in wallet_trans_list.iter() {
                let next_wallet =
                    crate::wallet::transition::apply_operation(current_wallet.clone(), transition)?;
                wallet_states.push(next_wallet.clone());
                wallet_transitions_seq.push(*transition);
                current_wallet = next_wallet;
            }

            let wallet_states_refs: Vec<&WalletState> = wallet_states.iter().collect();
            let transitions_refs: Vec<&WalletTransition> = wallet_transitions_seq;

            match prove_wallet_transition(config, &wallet_states_refs, &transitions_refs) {
                Ok(proof) => {
                    let proof_arc = std::sync::Arc::new(proof);
                    for (idx, _) in wallet_trans_list.iter() {
                        proofs[*idx] = Some(proof_arc.clone());
                    }
                }
                Err(e) => {
                    return Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                        format!(
                            "failed to generate wallet transition proof for wallet {:?}: {:?}",
                            wallet_id, e
                        ),
                    )));
                }
            }
        }

        Ok(proofs)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::script::ScriptPubKeyBuf;

    use super::*;
    use crate::btx::script::{detect_script_type, ScriptType};
    use crate::scheduler::da::DAStore;
    use crate::scheduler::executor::Executor;
    use crate::scheduler::Sequencer;
    use crate::types::DaHash;
    use crate::zkp::types::create_config;

    struct FailingExecutor;

    impl Executor for FailingExecutor {
        fn get_wallet(&self, _wallet_id: WalletId) -> Result<Option<WalletState>> { Ok(None) }

        fn get_all_wallets(&self) -> Result<BTreeMap<WalletId, WalletState>> { Ok(BTreeMap::new()) }

        fn apply_wallet_transition(
            &mut self,
            _wallet_id: WalletId,
            _transition: &WalletTransition,
        ) -> Result<crate::types::WalletCommitment> {
            Ok([0u8; 32])
        }

        fn compute_global_root(&self) -> Result<GlobalRoot> {
            Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                "test error".to_string(),
            )))
        }
    }

    struct FailingDAStore;

    impl DAStore for FailingDAStore {
        fn publish(&self, _batch_blob: &[u8]) -> Result<DaHash> {
            Err(crate::Error::Global(crate::errors::GlobalError::Internal(
                "test error".to_string(),
            )))
        }

        fn get(&self, _da_hash: &DaHash) -> Result<Option<Vec<u8>>> { Ok(None) }
    }

    #[test]
    fn test_from_wallets() {
        let wallets = vec![[1u8; 32]];

        let access_set = AccessSet::from_wallets(wallets.clone());

        assert_eq!(access_set.wallets, wallets);
        assert!(access_set.prefixes.is_empty());
    }

    #[test]
    fn test_new() {
        let rules = BasicSchedulingRules::new(3);

        assert_eq!(rules.max_batch_items, 3);
    }

    #[test]
    fn test_in_memory_sequencer_new() {
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let executor = InMemoryExecutor::new(wallets.clone());
        let expected_root = executor.compute_global_root().expect("should compute root");

        let sequencer = InMemorySequencer::new(BasicSchedulingRules::new(1), wallets);

        let (head_root, local_batch_num) = Sequencer::head(&sequencer);
        assert_eq!(head_root, expected_root);
        assert_eq!(local_batch_num, 0);
    }

    #[test]
    fn test_with_executor() {
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let executor = InMemoryExecutor::new(wallets);
        let expected_root = executor.compute_global_root().expect("should compute root");

        let sequencer = InMemorySequencer::with_executor(BasicSchedulingRules::new(1), executor)
            .expect("should create sequencer");

        let (head_root, local_batch_num) = Sequencer::head(&sequencer);
        assert_eq!(head_root, expected_root);
        assert_eq!(local_batch_num, 0);
        let failing_executor = FailingExecutor;

        assert!(InMemorySequencer::with_executor(BasicSchedulingRules::new(1), failing_executor)
            .is_err());
    }

    #[test]
    fn test_conflicts() {
        let rules = BasicSchedulingRules::new(1);
        let candidate = AccessSet::from_wallets(vec![[1u8; 32]]);
        let active = vec![AccessSet::from_wallets(vec![[2u8; 32]])];

        assert!(!rules.conflicts(&candidate, &active));

        let active_with_conflict = vec![AccessSet::from_wallets(vec![[1u8; 32]])];

        assert!(rules.conflicts(&candidate, &active_with_conflict));

        let candidate_with_prefix = AccessSet { wallets: vec![], prefixes: vec![vec![1u8]] };
        let active_with_prefix = vec![AccessSet { wallets: vec![], prefixes: vec![vec![1u8]] }];

        assert!(rules.conflicts(&candidate_with_prefix, &active_with_prefix));
    }

    #[test]
    fn test_order() {
        let rules = BasicSchedulingRules::new(10);
        let candidates = vec![
            UpdateEnvelope {
                transition: WalletTransition::InsertChannel {
                    channel_id: [1u8; 32],
                    channel_commitment: [1u8; 32],
                },
                access_set: AccessSet::from_wallets(vec![[1u8; 32]]),
                fee_rate: Some(10),
                submit_order: 2,
            },
            UpdateEnvelope {
                transition: WalletTransition::InsertChannel {
                    channel_id: [2u8; 32],
                    channel_commitment: [2u8; 32],
                },
                access_set: AccessSet::from_wallets(vec![[2u8; 32]]),
                fee_rate: Some(20),
                submit_order: 1,
            },
            UpdateEnvelope {
                transition: WalletTransition::InsertChannel {
                    channel_id: [3u8; 32],
                    channel_commitment: [3u8; 32],
                },
                access_set: AccessSet::from_wallets(vec![[3u8; 32]]),
                fee_rate: Some(20),
                submit_order: 1,
            },
            UpdateEnvelope {
                transition: WalletTransition::InsertChannel {
                    channel_id: [4u8; 32],
                    channel_commitment: [4u8; 32],
                },
                access_set: AccessSet::from_wallets(vec![[4u8; 32]]),
                fee_rate: None,
                submit_order: 0,
            },
        ];

        let ordered = rules.order(candidates.clone());

        assert_eq!(ordered[0].fee_rate, Some(20));
        assert_eq!(ordered[1].fee_rate, Some(20));
        assert_eq!(ordered[2].fee_rate, Some(10));
        assert_eq!(ordered[3].fee_rate, None);
    }

    #[test]
    fn test_max_batch_items() {
        let rules = BasicSchedulingRules::new(5);

        assert_eq!(rules.max_batch_items(), Some(5));
    }

    #[test]
    fn test_ingest() -> Result<()> {
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let mut sequencer = InMemorySequencer::new(BasicSchedulingRules::new(1), wallets);
        let envelope = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [2u8; 32],
                channel_commitment: [3u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: None,
            submit_order: 0,
        };

        let id = sequencer.ingest(envelope)?;

        assert_eq!(id, 0);
        Ok(())
    }

    #[test]
    fn test_schedulable() {
        let wallet_id = [1u8; 32];
        let other_wallet = [2u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let mut sequencer = InMemorySequencer::new(BasicSchedulingRules::new(1), wallets);
        let envelope1 = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [3u8; 32],
                channel_commitment: [4u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: None,
            submit_order: 0,
        };
        sequencer.ingest(envelope1).expect("should ingest");
        let envelope2 = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [5u8; 32],
                channel_commitment: [6u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![other_wallet]),
            fee_rate: None,
            submit_order: 1,
        };

        assert!(sequencer.schedulable(&envelope2));

        let envelope3 = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [7u8; 32],
                channel_commitment: [8u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: None,
            submit_order: 2,
        };

        assert!(!sequencer.schedulable(&envelope3));
    }

    #[test]
    fn test_simulate() -> Result<()> {
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let sequencer = InMemorySequencer::new(BasicSchedulingRules::new(1), wallets);
        let envelope = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [2u8; 32],
                channel_commitment: [3u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: None,
            submit_order: 0,
        };

        let result = sequencer.simulate(&envelope)?;

        assert_eq!(result.affected_wallets, vec![wallet_id]);
        assert!(result.tentative_root.is_some());
        assert!(result.admissible);
        let empty_envelope = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [4u8; 32],
                channel_commitment: [5u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![]),
            fee_rate: None,
            submit_order: 0,
        };

        assert!(sequencer.simulate(&empty_envelope).is_err());

        let multi_wallet_envelope = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [6u8; 32],
                channel_commitment: [7u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![[8u8; 32], [9u8; 32]]),
            fee_rate: None,
            submit_order: 0,
        };

        assert!(sequencer.simulate(&multi_wallet_envelope).is_err());

        Ok(())
    }

    #[test]
    fn test_build_next_batch() -> Result<()> {
        let wallet_id = [1u8; 32];
        let other_wallet = [2u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        wallets.insert(other_wallet, crate::wallet::state::WalletState::new(other_wallet));
        let mut sequencer = InMemorySequencer::new(BasicSchedulingRules::new(2), wallets);
        let envelope1 = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [3u8; 32],
                channel_commitment: [4u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: Some(10),
            submit_order: 0,
        };
        sequencer.ingest(envelope1)?;
        let envelope2 = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [5u8; 32],
                channel_commitment: [6u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![other_wallet]),
            fee_rate: Some(20),
            submit_order: 1,
        };
        sequencer.ingest(envelope2)?;
        let envelope3 = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [7u8; 32],
                channel_commitment: [8u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: Some(5),
            submit_order: 2,
        };
        sequencer.ingest(envelope3)?;

        let batch = sequencer.build_next_batch()?;

        assert_eq!(batch.transitions.len(), 2);
        assert_eq!(batch.local_batch_num, 1);

        let empty_sequencer = InMemorySequencer::new(BasicSchedulingRules::new(1), BTreeMap::new());
        let mut empty_sequencer_mut = empty_sequencer;

        let empty_batch = empty_sequencer_mut.build_next_batch()?;

        assert_eq!(empty_batch.transitions.len(), 0);
        Ok(())
    }

    #[test]
    fn test_build_next_batch_with_da() -> Result<()> {
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let mut sequencer = InMemorySequencer::new(BasicSchedulingRules::new(1), wallets);
        let envelope = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [2u8; 32],
                channel_commitment: [3u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: None,
            submit_order: 0,
        };
        sequencer.ingest(envelope)?;
        let da = crate::scheduler::da::InMemoryDAStore::new();

        let batch = sequencer.build_next_batch_with_da(&da)?;

        assert_eq!(batch.transitions.len(), 1);
        assert_ne!(batch.da_hash, [0u8; 32]);
        let failing_da = FailingDAStore;
        let mut wallets2 = BTreeMap::new();
        wallets2.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let mut sequencer2 = InMemorySequencer::new(BasicSchedulingRules::new(1), wallets2);
        sequencer2.ingest(UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [4u8; 32],
                channel_commitment: [5u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: None,
            submit_order: 0,
        })?;

        assert!(sequencer2.build_next_batch_with_da(&failing_da).is_err());

        Ok(())
    }

    #[test]
    fn test_build_next_batch_with_proofs() -> Result<()> {
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let mut sequencer = InMemorySequencer::new(BasicSchedulingRules::new(1), wallets);
        let envelope = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [2u8; 32],
                channel_commitment: [3u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: None,
            submit_order: 0,
        };
        sequencer.ingest(envelope)?;
        let config = create_config()?;

        let batch = sequencer.build_next_batch_with_proofs(&config)?;

        assert_eq!(batch.transitions.len(), 1);
        assert!(batch.proofs.batch_proof.is_some());
        let mut empty_sequencer =
            InMemorySequencer::new(BasicSchedulingRules::new(1), BTreeMap::new());

        assert!(empty_sequencer.build_next_batch_with_proofs(&config).is_err());

        Ok(())
    }

    #[test]
    fn test_build_next_batch_with_proofs_and_da() -> Result<()> {
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let mut sequencer = InMemorySequencer::new(BasicSchedulingRules::new(1), wallets);
        let envelope = UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [2u8; 32],
                channel_commitment: [3u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: None,
            submit_order: 0,
        };
        sequencer.ingest(envelope)?;
        let config = create_config()?;
        let da = crate::scheduler::da::InMemoryDAStore::new();

        let batch = sequencer.build_next_batch_with_proofs_and_da(&config, &da)?;

        assert_eq!(batch.transitions.len(), 1);
        assert!(batch.proofs.batch_proof.is_some());
        assert_ne!(batch.da_hash, [0u8; 32]);

        let failing_da = FailingDAStore;
        let mut wallets2 = BTreeMap::new();
        wallets2.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let mut sequencer2 = InMemorySequencer::new(BasicSchedulingRules::new(1), wallets2);
        sequencer2.ingest(UpdateEnvelope {
            transition: WalletTransition::InsertChannel {
                channel_id: [4u8; 32],
                channel_commitment: [5u8; 32],
            },
            access_set: AccessSet::from_wallets(vec![wallet_id]),
            fee_rate: None,
            submit_order: 0,
        })?;

        assert!(sequencer2.build_next_batch_with_proofs_and_da(&config, &failing_da).is_err());

        Ok(())
    }

    #[test]
    fn test_anchor_payload() -> Result<()> {
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let sequencer = InMemorySequencer::new(BasicSchedulingRules::new(1), wallets);
        let mut batch = Batch::new(
            vec![],
            vec![],
            [0u8; 32],
            [1u8; 32],
            1,
            [0u8; 32],
            crate::scheduler::batch::FeeMetadata { fee_rate: None, payer: None },
            crate::scheduler::batch::BatchProofBundle {
                batch_proof: None,
                wallet_transition_proofs: vec![],
            },
        );
        batch.da_hash = batch.compute_da_hash();

        let payload = sequencer.anchor_payload(&batch)?;

        assert_eq!(payload.amount.to_sat(), P2A_DEFAULT_VALUE_SATS);
        let script_pubkey_buf =
            ScriptPubKeyBuf::from_bytes(payload.script_pubkey.as_bytes().to_vec());
        assert_eq!(detect_script_type(&script_pubkey_buf), ScriptType::P2TR);
        Ok(())
    }

    #[test]
    fn test_head() {
        let wallet_id = [1u8; 32];
        let mut wallets = BTreeMap::new();
        wallets.insert(wallet_id, crate::wallet::state::WalletState::new(wallet_id));
        let sequencer = InMemorySequencer::new(BasicSchedulingRules::new(1), wallets);

        let (root, local_batch_num) = sequencer.head();

        assert_eq!(local_batch_num, 0);
        assert_ne!(root, [0u8; 32]);
    }
}
