// SPDX-License-Identifier: CC0-1.0

//! Batch data model for global state evolution.
//!
//! A Batch is the canonical, replayable unit of state evolution. It binds ordered
//! wallet/channel updates to pre/post commitment roots, a strictly increasing
//! local batch number, data-availability commitments, and proof artifacts. This file defines
//! the data structures only; orchestration lives in `sequencer`.

use std::sync::Arc;

use crate::global::commitment::types::GlobalRoot;
use crate::types::DaHash;
use crate::{poseidon2_hash_bytes, Proof, WalletId, WalletTransition};

/// Minimal fee metadata structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeMetadata {
    /// Optional fee rate or bid, caller-defined units.
    pub fee_rate: Option<u64>,
    /// Optional payer identifier (wallet/channel).
    pub payer: Option<WalletId>,
}

/// Bundled proof associated with a batch.
pub struct BatchProofBundle {
    /// Proof attesting to the batch's post-state commitment.
    pub batch_proof: Option<Proof>,
    /// Proofs for wallet transitions, one per transition in order.
    /// Uses `Arc` instead of `Rc` to enable thread-safe sharing and parallel processing.
    pub wallet_transition_proofs: Vec<Option<Arc<Proof>>>,
}

/// A canonical, replayable batch of ordered updates and resulting roots.
pub struct Batch {
    /// Ordered wallet transitions included in the batch.
    pub transitions: Vec<WalletTransition>,
    /// Wallets affected by the transitions.
    pub affected_wallets: Vec<WalletId>,
    /// Commitment root before applying this batch.
    /// In non-partitioned mode, this is the global commitment root.
    /// In partitioned mode, this is the partition-local commitment root.
    pub pre_commitment_root: GlobalRoot,
    /// Commitment root after applying this batch.
    /// In non-partitioned mode, this is the global commitment root.
    /// In partitioned mode, this is the partition-local commitment root.
    pub post_commitment_root: GlobalRoot,
    /// Strictly increasing local batch number for ordering batches within a partition.
    pub local_batch_num: u32,
    /// Data-availability hash of the serialized batch body.
    pub da_hash: DaHash,
    /// Fee-related metadata for ordering or settlement.
    pub fee_info: FeeMetadata,
    /// Associated proofs (wallet + global composition).
    pub proofs: BatchProofBundle,
}

impl Batch {
    /// Create a new batch with explicit fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transitions: Vec<WalletTransition>,
        affected_wallets: Vec<WalletId>,
        pre_commitment_root: GlobalRoot,
        post_commitment_root: GlobalRoot,
        local_batch_num: u32,
        da_hash: DaHash,
        fee_info: FeeMetadata,
        proofs: BatchProofBundle,
    ) -> Self {
        Self {
            transitions,
            affected_wallets,
            pre_commitment_root,
            post_commitment_root,
            local_batch_num,
            da_hash,
            fee_info,
            proofs,
        }
    }

    /// Deterministically serialize the batch body (transitions + wallets) for DA hashing.
    pub fn serialize_body(&self) -> Vec<u8> {
        serialize_body(&self.transitions, &self.affected_wallets, self.local_batch_num)
    }

    /// Compute a DA hash over the serialized body using Poseidon2.
    pub fn compute_da_hash(&self) -> DaHash { poseidon2_hash_bytes(&self.serialize_body()) }
}

/// Serialize transitions and affected wallets deterministically.
pub fn serialize_body(
    transitions: &[WalletTransition],
    affected_wallets: &[WalletId],
    local_batch_num: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&local_batch_num.to_le_bytes());
    buf.extend_from_slice(&(affected_wallets.len() as u32).to_le_bytes());
    for w in affected_wallets {
        buf.extend_from_slice(w);
    }
    buf.extend_from_slice(&(transitions.len() as u32).to_le_bytes());
    for t in transitions {
        match t {
            WalletTransition::InsertChannel { channel_id, channel_commitment } => {
                buf.push(0);
                buf.extend_from_slice(channel_id);
                buf.extend_from_slice(channel_commitment);
            }
            WalletTransition::RemoveChannel { channel_id } => {
                buf.push(1);
                buf.extend_from_slice(channel_id);
            }
        }
    }
    buf
}

/// Deserialize a batch body produced by `serialize_body`.
pub fn deserialize_body(bytes: &[u8]) -> Option<(u32, Vec<WalletId>, Vec<WalletTransition>)> {
    let mut cursor = 0usize;
    if bytes.len() < 4 {
        return None;
    }
    let mut local_batch_num_bytes = [0u8; 4];
    local_batch_num_bytes.copy_from_slice(&bytes[cursor..cursor + 4]);
    cursor += 4;
    let local_batch_num = u32::from_le_bytes(local_batch_num_bytes);

    if bytes.len() < cursor + 4 {
        return None;
    }
    let mut wl_count_bytes = [0u8; 4];
    wl_count_bytes.copy_from_slice(&bytes[cursor..cursor + 4]);
    cursor += 4;
    let wl_count = u32::from_le_bytes(wl_count_bytes) as usize;

    if bytes.len() < cursor + wl_count * 32 {
        return None;
    }
    let mut wallets = Vec::with_capacity(wl_count);
    for _ in 0..wl_count {
        let mut w = [0u8; 32];
        w.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        wallets.push(w);
    }

    if bytes.len() < cursor + 4 {
        return None;
    }
    let mut tx_count_bytes = [0u8; 4];
    tx_count_bytes.copy_from_slice(&bytes[cursor..cursor + 4]);
    cursor += 4;
    let tx_count = u32::from_le_bytes(tx_count_bytes) as usize;

    let mut transitions = Vec::with_capacity(tx_count);
    for _ in 0..tx_count {
        if cursor >= bytes.len() {
            return None;
        }
        let tag = bytes[cursor];
        cursor += 1;
        match tag {
            0 => {
                if bytes.len() < cursor + 64 {
                    return None;
                }
                let mut ch = [0u8; 32];
                ch.copy_from_slice(&bytes[cursor..cursor + 32]);
                cursor += 32;
                let mut com = [0u8; 32];
                com.copy_from_slice(&bytes[cursor..cursor + 32]);
                cursor += 32;
                transitions.push(WalletTransition::InsertChannel {
                    channel_id: ch,
                    channel_commitment: com,
                });
            }
            1 => {
                if bytes.len() < cursor + 32 {
                    return None;
                }
                let mut ch = [0u8; 32];
                ch.copy_from_slice(&bytes[cursor..cursor + 32]);
                cursor += 32;
                transitions.push(WalletTransition::RemoveChannel { channel_id: ch });
            }
            _ => return None,
        }
    }

    Some((local_batch_num, wallets, transitions))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_transitions() -> Vec<WalletTransition> {
        vec![
            WalletTransition::InsertChannel {
                channel_id: [1u8; 32],
                channel_commitment: [2u8; 32],
            },
            WalletTransition::RemoveChannel { channel_id: [3u8; 32] },
        ]
    }

    fn sample_wallets() -> Vec<WalletId> { vec![[4u8; 32], [5u8; 32]] }

    fn sample_batch() -> Batch {
        Batch::new(
            sample_transitions(),
            sample_wallets(),
            [6u8; 32],
            [7u8; 32],
            9,
            [8u8; 32],
            FeeMetadata { fee_rate: Some(1), payer: Some([9u8; 32]) },
            BatchProofBundle { batch_proof: None, wallet_transition_proofs: vec![] },
        )
    }

    #[test]
    fn test_new() {
        let transitions = sample_transitions();
        let wallets = sample_wallets();
        let pre_root = [10u8; 32];
        let post_root = [11u8; 32];
        let local_batch_num = 3;
        let da_hash = [12u8; 32];
        let fee_info = FeeMetadata { fee_rate: Some(5), payer: Some([13u8; 32]) };

        let batch = Batch::new(
            transitions.clone(),
            wallets.clone(),
            pre_root,
            post_root,
            local_batch_num,
            da_hash,
            fee_info.clone(),
            BatchProofBundle { batch_proof: None, wallet_transition_proofs: vec![] },
        );

        assert_eq!(batch.transitions, transitions);
        assert_eq!(batch.affected_wallets, wallets);
        assert_eq!(batch.pre_commitment_root, pre_root);
        assert_eq!(batch.post_commitment_root, post_root);
        assert_eq!(batch.local_batch_num, local_batch_num);
        assert_eq!(batch.da_hash, da_hash);
        assert_eq!(batch.fee_info, fee_info);
        assert!(batch.proofs.batch_proof.is_none());
    }

    #[test]
    fn test_batch_serialize_body() {
        let batch = sample_batch();
        let expected =
            serialize_body(&batch.transitions, &batch.affected_wallets, batch.local_batch_num);

        assert_eq!(batch.serialize_body(), expected);
    }

    #[test]
    fn test_compute_da_hash() {
        let batch = sample_batch();
        let expected = poseidon2_hash_bytes(&serialize_body(
            &batch.transitions,
            &batch.affected_wallets,
            batch.local_batch_num,
        ));

        assert_eq!(batch.compute_da_hash(), expected);
    }

    #[test]
    fn test_serialize_body() {
        let transitions = vec![
            WalletTransition::InsertChannel {
                channel_id: [21u8; 32],
                channel_commitment: [22u8; 32],
            },
            WalletTransition::RemoveChannel { channel_id: [23u8; 32] },
        ];
        let wallets = vec![[24u8; 32], [25u8; 32]];
        let local_batch_num = 26u32;

        let (insert_id, insert_commitment) = match &transitions[0] {
            WalletTransition::InsertChannel { channel_id, channel_commitment } =>
                (channel_id, channel_commitment),
            _ => unreachable!(),
        };
        let remove_id = match &transitions[1] {
            WalletTransition::RemoveChannel { channel_id } => channel_id,
            _ => unreachable!(),
        };

        let mut expected = Vec::new();
        expected.extend_from_slice(&local_batch_num.to_le_bytes());
        expected.extend_from_slice(&(wallets.len() as u32).to_le_bytes());
        expected.extend_from_slice(&wallets[0]);
        expected.extend_from_slice(&wallets[1]);
        expected.extend_from_slice(&(transitions.len() as u32).to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(insert_id);
        expected.extend_from_slice(insert_commitment);
        expected.push(1);
        expected.extend_from_slice(remove_id);

        assert_eq!(serialize_body(&transitions, &wallets, local_batch_num), expected);
    }

    #[test]
    fn test_deserialize_body() {
        let too_short = vec![0u8; 3];
        assert!(deserialize_body(&too_short).is_none());

        let only_local_batch_num = 5u32.to_le_bytes().to_vec();
        assert!(deserialize_body(&only_local_batch_num).is_none());

        let mut missing_wallet_bytes = Vec::new();
        missing_wallet_bytes.extend_from_slice(&7u32.to_le_bytes());
        missing_wallet_bytes.extend_from_slice(&1u32.to_le_bytes());
        assert!(deserialize_body(&missing_wallet_bytes).is_none());

        let mut missing_tx_count = Vec::new();
        missing_tx_count.extend_from_slice(&2u32.to_le_bytes());
        missing_tx_count.extend_from_slice(&0u32.to_le_bytes());
        assert!(deserialize_body(&missing_tx_count).is_none());

        let mut missing_tag = Vec::new();
        missing_tag.extend_from_slice(&3u32.to_le_bytes());
        missing_tag.extend_from_slice(&0u32.to_le_bytes());
        missing_tag.extend_from_slice(&1u32.to_le_bytes());
        assert!(deserialize_body(&missing_tag).is_none());

        let mut tag_zero_incomplete = missing_tag.clone();
        tag_zero_incomplete.push(0);
        assert!(deserialize_body(&tag_zero_incomplete).is_none());

        let mut tag_one_incomplete = missing_tag.clone();
        tag_one_incomplete.push(1);
        assert!(deserialize_body(&tag_one_incomplete).is_none());

        let mut unknown_tag = missing_tag.clone();
        unknown_tag.push(2);
        assert!(deserialize_body(&unknown_tag).is_none());

        let wallet = [31u8; 32];
        let mut success = Vec::new();
        success.extend_from_slice(&9u32.to_le_bytes());
        success.extend_from_slice(&1u32.to_le_bytes());
        success.extend_from_slice(&wallet);
        success.extend_from_slice(&0u32.to_le_bytes());

        let deserialized = deserialize_body(&success).expect("valid body should deserialize");

        assert_eq!(deserialized.0, 9);
        assert_eq!(deserialized.1, vec![wallet]);
        assert!(deserialized.2.is_empty());
    }
}
