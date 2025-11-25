//! Channel proof generation
//!
//! This module provides functions for generating zero-knowledge proofs
//! for channel state transitions.

use bitcoin::secp256k1::SecretKey;
use p3_matrix::Matrix;
use p3_uni_stark::prove;

use crate::channel::commitment::state_commitment::compute_open_commitment;
use crate::channel::state::Open;
use crate::channel::TransferAmount;
use crate::types::ChannelId;
use crate::zkp::channel::air::ChannelTransitionAir;
use crate::zkp::channel::poseidon2_air::column_offsets;
use crate::zkp::channel::trace::build_channel_trace;
use crate::zkp::types::{bytes32_to_fields, Proof, StarkConfig, Val};
use crate::zkp::verifier_common::build_public_values_from_id_commitment_and_pubkey;
use crate::Result;

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
    let trace = build_channel_trace(channel_id, old_state, new_state, amount, sender_sk)?;
    let expected_commitment = compute_open_commitment(channel_id, new_state);
    let air = ChannelTransitionAir::new();

    // Extract commitment from trace to verify it matches expected
    let commitment_fields: Vec<Val> = {
        let new_state_row = trace.row_slice(1).expect("Trace must have at least 2 rows");
        (column_offsets::COMMITMENT_START..column_offsets::COMMITMENT_END)
            .map(|i| new_state_row[i])
            .collect()
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
    let proof = prove(config, &air, trace, &public_values);
    Ok(proof)
}
#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::SecretKey;

    use super::*;
    use crate::channel::state::Open;
    use crate::channel::test_utils::test_keys;
    use crate::channel::transition::transfer::apply_transfer_state_only;
    use crate::channel::TransferAmount;
    use crate::zkp::types::create_config;

    #[test]
    fn test_prove_channel_transition() {
        let sender_sk = SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let config = create_config().expect("valid config");
        let channel_id = [0u8; 32];
        let sender_revocation_secret = SecretKey::from_slice(&[3u8; 32]).expect("valid secret key");
        let receiver_revocation_secret =
            SecretKey::from_slice(&[4u8; 32]).expect("valid secret key");
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
        let mut invalid_state = new_state.clone();
        invalid_state.metadata = vec![9u8; 256];

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
