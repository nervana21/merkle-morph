// SPDX-License-Identifier: CC0-1.0

//! Channel proof generation
//!
//! This module provides functions for generating zero-knowledge proofs
//! for channel state transitions.

use bitcoin::secp256k1::SecretKey;
use p3_matrix::Matrix;
use p3_uni_stark::prove;

use crate::channel::commitment::state_commitment::{
    compute_closed_commitment, compute_cooperative_closing_commitment,
    compute_force_closing_pending_commitment, compute_open_commitment,
};
use crate::channel::state::{Closed, CooperativeClosing, ForceClosingPending, Open};
use crate::types::ChannelId;
use crate::zkp::channel::air::ChannelTransitionAir;
use crate::zkp::channel::poseidon2_air::column_offsets;
use crate::zkp::channel::trace::{
    build_channel_trace, build_cooperative_close_trace, build_force_close_trace,
    build_recover_trace,
};
use crate::zkp::types::{bytes32_to_fields, Proof, StarkConfig, Val};
use crate::zkp::verifier_common::build_public_values_from_id_commitment_and_pubkey;
use crate::{Result, TransferAmount};

/// Generate a zero-knowledge proof for a channel state transition
///
/// This function proves that a channel state transition is correctly computed.
/// The proof demonstrates that the channel commitment is correctly computed from
/// the channel state using Poseidon2 hashing. The proof verifies balance
/// conservation, nonce increments, commitment integrity, and sender authentication.
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `old_state` - Previous channel state
/// * `amount` - Transfer amount that caused the transition
/// * `new_state` - New channel state after transition
/// * `sender_sk` - Sender's private key for computing authentication hash
/// * `config` - Proof system configuration (`StarkConfig`)
///
/// # Returns
/// A zero-knowledge proof for the channel state transition
pub fn prove_channel_transition(
    channel_id: ChannelId,
    old_state: &Open,
    amount: &TransferAmount,
    new_state: &Open,
    sender_sk: &SecretKey,
    config: &StarkConfig,
) -> Result<Proof> {
    let trace = build_channel_trace(channel_id, old_state, amount, new_state, sender_sk)?;

    // Validate state transition: enforce balance conservation and nonce increment
    // This ensures invalid transitions are rejected before proof generation
    if new_state.sender_balance != old_state.sender_balance.saturating_sub(**amount) {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }
    if new_state.receiver_balance != old_state.receiver_balance.saturating_add(**amount) {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }
    if new_state.nonce != old_state.nonce.saturating_add(1) {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    let expected_commitment = compute_open_commitment(channel_id, new_state);
    let air = ChannelTransitionAir::new();

    // Extract commitment from trace to verify it matches expected
    let commitment_fields: Vec<Val> = {
        let new_state_row = trace.row_slice(1).expect("Trace must have at least 2 rows");
        let commitment_start = column_offsets::commitment_start();
        let commitment_end = column_offsets::commitment_end();
        (commitment_start..commitment_end).map(|i| new_state_row[i]).collect()
    };

    // Verify commitment matches expected
    let expected_fields = bytes32_to_fields(expected_commitment);
    if commitment_fields != expected_fields {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    // Build public values including sender_pubkey
    let public_values = build_public_values_from_id_commitment_and_pubkey(
        channel_id,
        expected_commitment,
        old_state.sender_pubkey,
    );

    // Generate proof
    // Wrap prove in catch_unwind to handle constraint violations gracefully
    let proof_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove(config, &air, trace, &public_values)
    }));

    match proof_result {
        Ok(proof) => Ok(proof),
        Err(_) => Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed)),
    }
}

/// Generate a zero-knowledge proof for a force close transition (Open → ForceClosingPending)
///
/// This function proves that a force close transition is correctly computed.
/// The proof demonstrates that the channel commitment is correctly computed from
/// the channel state using Poseidon2 hashing. The proof verifies fee deduction,
/// balance calculations, nonce increment, and commitment integrity.
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `old_state` - Previous Open state
/// * `closing_fee` - Closing fee that was deducted
/// * `new_state` - New ForceClosingPending state after transition
/// * `config` - Proof system configuration (`StarkConfig`)
///
/// # Returns
/// A zero-knowledge proof for the force close transition
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `old_state` - Previous Open state
/// * `closing_fee` - Closing fee that was deducted
/// * `new_state` - New ForceClosingPending state after transition
/// * `config` - Proof system configuration
/// * `sender_sk` - Optional sender's private key. If provided (sender-initiated force close),
///   auth_hash is computed to prove sender authorization. If None (receiver-initiated),
///   auth_hash is set to zero and authentication is handled at the Bitcoin transaction layer.
pub fn prove_force_close_transition(
    channel_id: ChannelId,
    old_state: &Open,
    closing_fee: u64,
    new_state: &ForceClosingPending,
    config: &StarkConfig,
    sender_sk: Option<&SecretKey>,
) -> Result<Proof> {
    let trace = build_force_close_trace(channel_id, old_state, closing_fee, new_state, sender_sk)?;

    // Validate state transition: enforce fee deduction and nonce increment
    if new_state.sender_balance != old_state.sender_balance.saturating_sub(closing_fee) {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }
    if new_state.receiver_balance != old_state.receiver_balance {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }
    if new_state.nonce != old_state.nonce.saturating_add(1) {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    let expected_commitment = compute_force_closing_pending_commitment(channel_id, new_state);
    let air = ChannelTransitionAir::new();

    // Extract commitment from trace to verify it matches expected
    let commitment_fields: Vec<Val> = {
        let new_state_row = trace.row_slice(1).expect("Trace must have at least 2 rows");
        let commitment_start = column_offsets::commitment_start();
        let commitment_end = column_offsets::commitment_end();
        (commitment_start..commitment_end).map(|i| new_state_row[i]).collect()
    };

    // Verify commitment matches expected
    let expected_fields = bytes32_to_fields(expected_commitment);
    if commitment_fields != expected_fields {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    // Build public values including sender_pubkey
    let public_values = build_public_values_from_id_commitment_and_pubkey(
        channel_id,
        expected_commitment,
        old_state.sender_pubkey,
    );

    // Generate proof
    let proof_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove(config, &air, trace, &public_values)
    }));

    match proof_result {
        Ok(proof) => Ok(proof),
        Err(_) => Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed)),
    }
}

/// Generate a zero-knowledge proof for a cooperative close transition (Open → CooperativeClosing)
///
/// This function proves that a cooperative close transition is correctly computed.
/// The proof demonstrates that the channel commitment is correctly computed from
/// the channel state using Poseidon2 hashing. The proof verifies fee contributions,
/// balance calculations, nonce increment, and commitment integrity.
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `old_state` - Previous Open state
/// * `closing_fee` - Total closing fee
/// * `new_state` - New CooperativeClosing state after transition
/// * `config` - Proof system configuration (`StarkConfig`)
///
/// # Returns
/// A zero-knowledge proof for the cooperative close transition
pub fn prove_cooperative_close_transition(
    channel_id: ChannelId,
    old_state: &Open,
    closing_fee: u64,
    new_state: &CooperativeClosing,
    config: &StarkConfig,
) -> Result<Proof> {
    let trace = build_cooperative_close_trace(channel_id, old_state, closing_fee, new_state)?;

    // Validate state transition: enforce fee contributions and nonce increment
    let expected_sender_balance =
        old_state.sender_balance.saturating_sub(new_state.sender_contribution);
    let expected_receiver_balance =
        old_state.receiver_balance.saturating_sub(new_state.receiver_contribution);

    if new_state.sender_balance != expected_sender_balance {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }
    if new_state.receiver_balance != expected_receiver_balance {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    let expected_nonce = old_state.nonce.saturating_add(1);
    if new_state.nonce != expected_nonce {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    let expected_commitment = compute_cooperative_closing_commitment(channel_id, new_state);
    let air = ChannelTransitionAir::new();

    // Extract commitment from trace to verify it matches expected
    let commitment_fields: Vec<Val> = {
        let new_state_row = trace.row_slice(1).expect("Trace must have at least 2 rows");
        let commitment_start = column_offsets::commitment_start();
        let commitment_end = column_offsets::commitment_end();
        (commitment_start..commitment_end).map(|i| new_state_row[i]).collect()
    };

    // Verify commitment matches expected
    let expected_fields = bytes32_to_fields(expected_commitment);
    if commitment_fields != expected_fields {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    // Build public values including sender_pubkey
    let public_values = build_public_values_from_id_commitment_and_pubkey(
        channel_id,
        expected_commitment,
        old_state.sender_pubkey,
    );

    // Generate proof
    let proof_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove(config, &air, trace, &public_values)
    }));

    match proof_result {
        Ok(proof) => Ok(proof),
        Err(_) => Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed)),
    }
}

/// Generate a zero-knowledge proof for a recover transition (ForceClosingPending → Closed)
///
/// This function proves that a recover transition is correctly computed.
/// The proof demonstrates that the channel commitment is correctly computed from
/// the channel state using Poseidon2 hashing. The proof verifies recovery balance
/// allocation and commitment integrity.
///
/// # Arguments
/// * `channel_id` - Channel identifier
/// * `old_state` - Previous ForceClosingPending state
/// * `new_state` - New Closed state after transition
/// * `config` - Proof system configuration (`StarkConfig`)
///
/// # Returns
/// A zero-knowledge proof for the recover transition
pub fn prove_recover_transition(
    channel_id: ChannelId,
    old_state: &ForceClosingPending,
    new_state: &Closed,
    config: &StarkConfig,
) -> Result<Proof> {
    let trace = build_recover_trace(channel_id, old_state, new_state)?;

    // Validate state transition: enforce recovery balance allocation
    // In recovery, receiver gets all funds, sender gets 0
    if new_state.sender_balance != 0 {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }
    if new_state.receiver_balance != old_state.total_capacity {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }
    // Nonce remains the same in recovery
    if new_state.nonce != old_state.nonce {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    let expected_commitment = compute_closed_commitment(channel_id, new_state);
    let air = ChannelTransitionAir::new();

    // Extract commitment from trace to verify it matches expected
    let commitment_fields: Vec<Val> = {
        let new_state_row = trace.row_slice(1).expect("Trace must have at least 2 rows");
        let commitment_start = column_offsets::commitment_start();
        let commitment_end = column_offsets::commitment_end();
        (commitment_start..commitment_end).map(|i| new_state_row[i]).collect()
    };

    // Verify commitment matches expected
    let expected_fields = bytes32_to_fields(expected_commitment);
    if commitment_fields != expected_fields {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    // Build public values including sender_pubkey
    let public_values = build_public_values_from_id_commitment_and_pubkey(
        channel_id,
        expected_commitment,
        old_state.sender_pubkey,
    );

    // Generate proof
    let proof_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove(config, &air, trace, &public_values)
    }));

    match proof_result {
        Ok(proof) => Ok(proof),
        Err(_) => Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed)),
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::SecretKey;

    use super::*;
    use crate::channel::state::Open;
    use crate::channel::test_utils::test_keys;
    use crate::channel::transition::transfer::apply_transfer_state_only;
    use crate::zkp::types::create_config;
    use crate::TransferAmount;

    #[test]
    fn test_prove_channel_transition() {
        let sender_sk = SecretKey::from_secret_bytes([1u8; 32]).expect("valid secret key");
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let config = create_config().expect("valid config");
        let channel_id = [0u8; 32];
        let sender_revocation_secret =
            SecretKey::from_secret_bytes([3u8; 32]).expect("valid secret key");
        let receiver_revocation_secret =
            SecretKey::from_secret_bytes([4u8; 32]).expect("valid secret key");
        let old_state = Open::new(
            sender_pubkey,
            receiver_pubkey,
            100,
            sender_revocation_secret,
            receiver_revocation_secret,
        );
        let amount = TransferAmount::new(30).expect("valid transfer amount");
        let new_state =
            apply_transfer_state_only(&old_state, &amount).expect("valid state transition");

        // Create an invalid state with incorrect balance (doesn't match the transfer amount)
        let mut invalid_state = new_state.clone();
        invalid_state.sender_balance = old_state.sender_balance; // Should be reduced by amount

        assert!(prove_channel_transition(
            channel_id, &old_state, &amount, &new_state, &sender_sk, &config,
        )
        .is_ok());

        assert!(prove_channel_transition(
            channel_id,
            &old_state,
            &amount,
            &invalid_state,
            &sender_sk,
            &config,
        )
        .is_err());
    }
}
