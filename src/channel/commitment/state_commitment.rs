//! State commitment computation
//!
//! This module provides functions for computing commitments from channel states.

use bitcoin::secp256k1::XOnlyPublicKey;

use crate::channel::state::{Closed, CooperativeClosing, ForceClosingPending, Open};
use crate::types::{Bytes32, ChannelCommitment, ChannelId, CHANNEL_DOMAIN_TAG};
use crate::zkp::{poseidon2_hash_bytes, poseidon2_hash_fixed};

/// Computes a commitment for an Open state
///
/// The commitment is computed using a two-stage hash:
/// 1. Stage 1: `poseidon2(CHANNEL_DOMAIN_TAG || channel_id || state_hash)` -> 32 bytes
/// 2. Stage 2: `poseidon2(stage1_result || nonce)` -> 32 bytes
///
/// where `state_hash = poseidon2(sender_balance || receiver_balance || sender_pubkey || receiver_pubkey || metadata || is_closed)`
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `state` - Open state
///
/// # Returns
/// Channel commitment
pub fn compute_open_commitment(channel_id: ChannelId, state: &Open) -> ChannelCommitment {
    let state_hash = compute_open_state_hash(state);
    compute_channel_commitment(channel_id, state_hash, state.nonce)
}

/// Computes the hash of an Open state
///
/// The state hash is computed using Poseidon2 hashing with domain separation.
/// The state hash includes sender_balance, receiver_balance, sender_pubkey, receiver_pubkey,
/// and metadata. The is_closed flag is always false for Open states.
///
/// # Arguments
/// * `state` - Open state
///
/// # Returns
/// State hash
///
/// # Examples
///
/// ```rust
/// use merkle_morph::channel::commitment::state_commitment::compute_open_state_hash;
/// use merkle_morph::channel::state::Open;
/// use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
///
/// let secp = Secp256k1::new();
/// let sender_sk = SecretKey::from_slice(&[1u8; 32]).expect("32-byte array should always be a valid SecretKey");
/// let receiver_sk = SecretKey::from_slice(&[2u8; 32]).expect("32-byte array should always be a valid SecretKey");
/// let sender_pubkey = XOnlyPublicKey::from_keypair(&sender_sk.keypair(&secp)).0;
/// let receiver_pubkey = XOnlyPublicKey::from_keypair(&receiver_sk.keypair(&secp)).0;
/// let state = Open::new(sender_pubkey, receiver_pubkey, 0);
/// let state_hash = compute_open_state_hash(&state);
/// assert_eq!(state_hash.len(), 32);
/// ```
pub fn compute_open_state_hash(state: &Open) -> Bytes32 {
    let is_closed_u64 = 0u64; // Open state is never closed
    let mut sender_pubkey_le = state.sender_pubkey.serialize();
    sender_pubkey_le.reverse();
    let mut receiver_pubkey_le = state.receiver_pubkey.serialize();
    receiver_pubkey_le.reverse();
    poseidon2_hash_fixed(&[
        &state.sender_balance.to_le_bytes(),
        &state.receiver_balance.to_le_bytes(),
        &sender_pubkey_le,
        &receiver_pubkey_le,
        &state.metadata,
        &is_closed_u64.to_le_bytes(),
    ])
}

/// Computes a commitment for a CooperativeClosing state
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `state` - CooperativeClosing state
///
/// # Returns
/// Channel commitment
pub fn compute_cooperative_closing_commitment(
    channel_id: ChannelId,
    state: &CooperativeClosing,
) -> ChannelCommitment {
    let state_hash = compute_closing_state_hash(
        state.sender_balance,
        state.receiver_balance,
        &state.sender_pubkey,
        &state.receiver_pubkey,
        true, // is_closed = true for closing states
    );
    compute_channel_commitment(channel_id, state_hash, state.nonce)
}

/// Computes a commitment for a ForceClosingPending state
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `state` - ForceClosingPending state
///
/// # Returns
/// Channel commitment
pub fn compute_force_closing_pending_commitment(
    channel_id: ChannelId,
    state: &ForceClosingPending,
) -> ChannelCommitment {
    let state_hash = compute_closing_state_hash(
        state.sender_balance,
        state.receiver_balance,
        &state.sender_pubkey,
        &state.receiver_pubkey,
        true, // is_closed = true for closing states
    );
    compute_channel_commitment(channel_id, state_hash, state.nonce)
}

/// Computes a commitment for a Closed state
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `state` - Closed state
///
/// # Returns
/// Channel commitment
pub fn compute_closed_commitment(channel_id: ChannelId, state: &Closed) -> ChannelCommitment {
    let state_hash = compute_closing_state_hash(
        state.sender_balance,
        state.receiver_balance,
        &state.sender_pubkey,
        &state.receiver_pubkey,
        true, // is_closed = true
    );
    compute_channel_commitment(channel_id, state_hash, state.nonce)
}

/// Computes the hash of a closing state
///
/// Helper function for computing state hash for closing states.
fn compute_closing_state_hash(
    sender_balance: u64,
    receiver_balance: u64,
    sender_pubkey: &XOnlyPublicKey,
    receiver_pubkey: &XOnlyPublicKey,
    is_closed: bool,
) -> Bytes32 {
    let is_closed_u64 = if is_closed { 1u64 } else { 0u64 };
    let mut sender_pubkey_le = sender_pubkey.serialize();
    sender_pubkey_le.reverse();
    let mut receiver_pubkey_le = receiver_pubkey.serialize();
    receiver_pubkey_le.reverse();
    poseidon2_hash_fixed(&[
        &sender_balance.to_le_bytes(),
        &receiver_balance.to_le_bytes(),
        &sender_pubkey_le,
        &receiver_pubkey_le,
        &[], // No metadata for closing states
        &is_closed_u64.to_le_bytes(),
    ])
}

/// Computes the channel-specific commitment from `channel_id`, `state_hash`,
/// and `nonce` using Poseidon2.
///
/// The `state_hash` represents the hash of the state data (balances, pubkeys, metadata, is_closed).
/// The `state_hash` excludes `channel_id` and `nonce`. The final channel commitment is a
/// hashed combination of all three components, but first appended with the
/// domain separation tag `CHANNEL_DOMAIN_TAG`.
///
/// Uses a two-stage hash to preserve all data:
/// 1. Stage 1: `poseidon2(CHANNEL_DOMAIN_TAG || channel_id || state_hash)` -> 32 bytes
/// 2. Stage 2: `poseidon2(stage1_result || nonce)` -> 32 bytes
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `state_hash` - Hash of state data
/// * `nonce` - Current nonce value
///
/// # Returns
/// Channel commitment
///
/// # Examples
///
/// ```rust
/// use merkle_morph::channel::commitment::state_commitment::compute_channel_commitment;
///
/// let channel_id = [0u8; 32];
/// let state_hash = [0u8; 32];
/// let nonce = 0;
///
/// let commitment = compute_channel_commitment(channel_id, state_hash, nonce);
///
/// // Same inputs produce same output
/// let commitment2 = compute_channel_commitment(channel_id, state_hash, nonce);
/// assert_eq!(commitment, commitment2);
///
/// // Different nonce produces different commitment
/// let commitment3 = compute_channel_commitment(channel_id, state_hash, 1);
/// assert_ne!(commitment, commitment3);
/// ```
pub fn compute_channel_commitment(
    channel_id: ChannelId,
    state_hash: Bytes32,
    nonce: u32,
) -> ChannelCommitment {
    // Stage 1: Hash domain_tag || channel_id || state_hash (72 bytes -> 32 bytes)
    let mut stage1_input = Vec::new();
    stage1_input.extend_from_slice(CHANNEL_DOMAIN_TAG);
    stage1_input.extend_from_slice(&channel_id);
    stage1_input.extend_from_slice(&state_hash);
    let stage1_hash = poseidon2_hash_bytes(&stage1_input);

    // Stage 2: Hash stage1_result || nonce (40 bytes -> 32 bytes)
    let mut stage2_input = Vec::new();
    stage2_input.extend_from_slice(&stage1_hash);
    stage2_input.extend_from_slice(&nonce.to_le_bytes());
    poseidon2_hash_bytes(&stage2_input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::state::{
        Closed, CooperativeClosing, ForceClosingPending, ForceClosingPendingParams, Open,
    };
    use crate::channel::test_utils::*;

    #[test]
    fn test_compute_open_commitment() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let channel_id = [0u8; 32];
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            0,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        let commitment = compute_open_commitment(channel_id, &state);

        #[rustfmt::skip]
        assert_eq!(
            commitment,
            [
                0x95, 0xe2, 0x0e, 0x48, 0x90, 0x2f, 0xef, 0x59,
                0x31, 0xc0, 0x88, 0x32, 0xc4, 0x68, 0xfa, 0x3a,
                0x1d, 0x41, 0x19, 0x29, 0xa5, 0xca, 0x5c, 0x52,
                0x59, 0xd9, 0xbe, 0x47, 0xd6, 0xa8, 0xa5, 0x08,
            ]
        );
    }

    #[test]
    fn test_compute_open_state_hash() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let (sender_revocation_secret, receiver_revocation_secret) = revocation_secrets();
        let state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            0,
            sender_revocation_secret,
            receiver_revocation_secret,
        );

        let state_hash = compute_open_state_hash(&state);

        #[rustfmt::skip]
        assert_eq!(
            state_hash,
            [
                0x5a, 0x59, 0xdf, 0x5b, 0x81, 0xb5, 0xef, 0x37,
                0xc5, 0x49, 0x74, 0x60, 0x99, 0x18, 0x41, 0x21,
                0x5d, 0x54, 0xe9, 0x4f, 0x67, 0x0f, 0x04, 0x68,
                0xcc, 0xbc, 0x65, 0x68, 0xc7, 0x7b, 0x71, 0x44,
            ]
        );
    }

    #[test]
    fn test_compute_cooperative_closing_commitment() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let channel_id = [0u8; 32];
        let state = CooperativeClosing::new(crate::channel::state::CooperativeClosingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 0,
            sender_balance: 0,
            receiver_balance: 0,
            total_fee: 0,
            sender_contribution: 0,
            receiver_contribution: 0,
            nonce: 0,
        });

        let commitment = compute_cooperative_closing_commitment(channel_id, &state);

        #[rustfmt::skip]
        assert_eq!(
            commitment,
            [
                0x6b, 0x1e, 0xf3, 0x2c, 0x34, 0xcf, 0x3f, 0x4d,
                0x18, 0x94, 0x21, 0x73, 0x30, 0x5f, 0x3f, 0x15,
                0xc4, 0x6b, 0x60, 0x73, 0x7c, 0xa0, 0x96, 0x0a,
                0xa1, 0xcb, 0x54, 0x6a, 0x9a, 0xc9, 0x54, 0x08,
            ]
        );
    }

    #[test]
    fn test_compute_force_closing_pending_commitment() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let channel_id = [0u8; 32];
        let state = ForceClosingPending::new(ForceClosingPendingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 0,
            sender_balance: 0,
            receiver_balance: 0,
            total_fee: 0,
            nonce: 0,
            timeout_blocks: 0,
        });

        let commitment = compute_force_closing_pending_commitment(channel_id, &state);

        #[rustfmt::skip]
        assert_eq!(
            commitment,
            [
                0x6b, 0x1e, 0xf3, 0x2c, 0x34, 0xcf, 0x3f, 0x4d,
                0x18, 0x94, 0x21, 0x73, 0x30, 0x5f, 0x3f, 0x15,
                0xc4, 0x6b, 0x60, 0x73, 0x7c, 0xa0, 0x96, 0x0a,
                0xa1, 0xcb, 0x54, 0x6a, 0x9a, 0xc9, 0x54, 0x08,
            ]
        );
    }

    #[test]
    fn test_compute_closed_commitment() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let channel_id = [0u8; 32];
        let state = Closed::new(sender_pubkey, receiver_pubkey, 0, 0, 0, 0);

        let commitment = compute_closed_commitment(channel_id, &state);

        #[rustfmt::skip]
        assert_eq!(
            commitment,
            [
                0x6b, 0x1e, 0xf3, 0x2c, 0x34, 0xcf, 0x3f, 0x4d,
                0x18, 0x94, 0x21, 0x73, 0x30, 0x5f, 0x3f, 0x15,
                0xc4, 0x6b, 0x60, 0x73, 0x7c, 0xa0, 0x96, 0x0a,
                0xa1, 0xcb, 0x54, 0x6a, 0x9a, 0xc9, 0x54, 0x08,
            ]
        );
    }

    #[test]
    fn test_compute_channel_commitment() {
        let channel_id = [0u8; 32];
        let state_hash = [0u8; 32];
        let nonce = 0u32;

        let commitment = compute_channel_commitment(channel_id, state_hash, nonce);

        #[rustfmt::skip]
        assert_eq!(
            commitment,
            [
                0xbd, 0xd7, 0x66, 0x3f, 0x7b, 0x20, 0x95, 0x5d,
                0xf5, 0x4d, 0xed, 0x27, 0x47, 0x62, 0x40, 0x4c,
                0xd1, 0xe7, 0xc9, 0x01, 0x36, 0x7a, 0x8f, 0x2a,
                0xb6, 0xa3, 0x1d, 0x36, 0x8b, 0x69, 0x29, 0x26,
            ]
        );
    }
}
