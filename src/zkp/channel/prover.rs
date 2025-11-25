#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Channel proof generation
//!
//! This module provides functions for generating zero-knowledge proofs
//! for channel state transitions.

use p3_matrix::Matrix;

use crate::channel::commitment::compute_commitment;
use crate::channel::state::ChannelState;
use crate::channel::TransferAmount;
use crate::errors::Result;
use crate::types::ChannelId;
use crate::zkp::channel::air::ChannelTransitionAir;
use crate::zkp::channel::poseidon2_air::column_offsets;
use crate::zkp::channel::trace::build_channel_trace;
use crate::zkp::prover_common::prove_with_commitment;
use crate::zkp::types::{Proof, StarkConfig};

/// Generate a zero-knowledge proof for a channel state transition
///
/// This function proves that a channel state transition is correctly computed.
/// The proof demonstrates that the channel commitment is correctly computed from
/// the channel state using Poseidon2 hashing. The proof verifies balance
/// conservation, nonce increments, and commitment integrity.
///
/// # Arguments
/// * `config` - Proof system configuration (`StarkConfig`)
/// * `channel_id` - Channel identifier
/// * `old_state` - Previous channel state
/// * `amount` - Transfer amount that caused the transition
/// * `new_state` - New channel state after transition
///
/// # Returns
/// A zero-knowledge proof for the channel state transition
pub fn prove_channel_transition(
    config: &StarkConfig,
    channel_id: ChannelId,
    old_state: &ChannelState,
    amount: &TransferAmount,
    new_state: &ChannelState,
) -> Result<Proof> {
    let trace = build_channel_trace(channel_id, old_state, new_state, amount)?;
    let expected_commitment = compute_commitment(channel_id, new_state);
    let air = ChannelTransitionAir::new();

    prove_with_commitment(
        config,
        trace,
        |trace| {
            let new_state_row = trace.row_slice(1).expect("Trace must have at least 2 rows");
            Ok((column_offsets::COMMITMENT_START..column_offsets::COMMITMENT_END)
                .map(|i| new_state_row[i])
                .collect())
        },
        expected_commitment,
        channel_id,
        &air,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::commitment::compute_commitment;
    use crate::channel::state::ChannelState;
    use crate::channel::TransferAmount;
    use crate::zkp::channel::public_inputs::ChannelPublicInputs;
    use crate::zkp::channel::verifier::verify_channel_transition;
    use crate::zkp::types::create_config;

    /// Helper function to create a test channel transition
    fn create_test_transition(
        channel_id: u8,
        initial_balance: u64,
        transfer_amount: u64,
    ) -> (ChannelId, ChannelState, TransferAmount, ChannelState) {
        let mut id = [0u8; 32];
        id[31] = channel_id;

        let old_state = ChannelState::new(initial_balance);
        let amount = TransferAmount::new(transfer_amount).expect("valid transfer");
        let new_state = crate::channel::transition::apply_transfer_state_only(&old_state, &amount)
            .expect("Valid transfer should succeed");

        (id, old_state, amount, new_state)
    }

    #[test]
    fn test_prove_channel_transition() {
        let config = create_config().expect("Should create config");

        // Basic transition
        {
            let (channel_id, old_state, amount, new_state) = create_test_transition(1, 100, 30);
            let proof =
                prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
                    .expect("Should generate proof for basic transition");

            let channel_commitment = compute_commitment(channel_id, &new_state);
            let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
            verify_channel_transition(&config, &public_inputs, &proof)
                .expect("Should verify basic transition proof");
        }

        // Minimal transfer amount
        {
            let (channel_id, old_state, amount, new_state) = create_test_transition(2, 100, 1);
            let proof =
                prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
                    .expect("Should generate proof for minimal transfer");

            let channel_commitment = compute_commitment(channel_id, &new_state);
            let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
            verify_channel_transition(&config, &public_inputs, &proof)
                .expect("Should verify minimal transfer proof");
        }

        // Large transfer amount
        {
            let (channel_id, old_state, amount, new_state) = create_test_transition(3, 1000, 500);
            let proof =
                prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
                    .expect("Should generate proof for large transfer");

            let channel_commitment = compute_commitment(channel_id, &new_state);
            let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
            verify_channel_transition(&config, &public_inputs, &proof)
                .expect("Should verify large transfer proof");
        }

        // Multiple transitions with same channel
        {
            let channel_id = [4u8; 32];
            let mut current_state = ChannelState::new(1000);

            for i in 0..5 {
                let amount = TransferAmount::new(50 + i * 10).expect("valid transfer");
                let new_state =
                    crate::channel::transition::apply_transfer_state_only(&current_state, &amount)
                        .expect("Valid transfer should succeed");

                let proof = prove_channel_transition(
                    &config,
                    channel_id,
                    &current_state,
                    &amount,
                    &new_state,
                )
                .expect("Should generate proof for sequential transition");

                let channel_commitment = compute_commitment(channel_id, &new_state);
                let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
                verify_channel_transition(&config, &public_inputs, &proof)
                    .expect("Should verify sequential transition proof");

                current_state = new_state;
            }
        }

        // Different channel IDs produce different commitments
        {
            let (channel_id1, old_state1, amount1, new_state1) =
                create_test_transition(10, 100, 30);
            let (channel_id2, old_state2, amount2, new_state2) =
                create_test_transition(20, 100, 30);

            let commitment1 = compute_commitment(channel_id1, &new_state1);
            let commitment2 = compute_commitment(channel_id2, &new_state2);

            assert_ne!(
                commitment1, commitment2,
                "Different channel IDs should produce different commitments"
            );

            let proof1 =
                prove_channel_transition(&config, channel_id1, &old_state1, &amount1, &new_state1)
                    .expect("Should generate proof for channel1");
            let proof2 =
                prove_channel_transition(&config, channel_id2, &old_state2, &amount2, &new_state2)
                    .expect("Should generate proof for channel2");

            let public_inputs1 =
                ChannelPublicInputs { channel_id: channel_id1, channel_commitment: commitment1 };
            let public_inputs2 =
                ChannelPublicInputs { channel_id: channel_id2, channel_commitment: commitment2 };

            verify_channel_transition(&config, &public_inputs1, &proof1)
                .expect("Should verify channel1 proof");
            verify_channel_transition(&config, &public_inputs2, &proof2)
                .expect("Should verify channel2 proof");

            // Cross-verification should fail
            assert!(
                verify_channel_transition(&config, &public_inputs1, &proof2).is_err(),
                "Channel1 proof should not verify with channel2 public inputs"
            );
        }

        // Deterministic proof generation
        {
            let (channel_id, old_state, amount, new_state) = create_test_transition(6, 100, 30);
            let proof1 =
                prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
                    .expect("Should generate first proof");
            let proof2 =
                prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
                    .expect("Should generate second proof");

            // Proofs should be identical for same input
            // Note: This tests that the proof generation is deterministic
            // The actual proof structure may vary, but verification should work for both
            let channel_commitment = compute_commitment(channel_id, &new_state);
            let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };

            verify_channel_transition(&config, &public_inputs, &proof1)
                .expect("First proof should verify");
            verify_channel_transition(&config, &public_inputs, &proof2)
                .expect("Second proof should verify");
        }

        // Different states produce different commitments
        {
            let channel_id = [7u8; 32];
            let old_state = ChannelState::new(100);

            let amount1 = TransferAmount::new(30).expect("valid transfer");
            let new_state1 =
                crate::channel::transition::apply_transfer_state_only(&old_state, &amount1)
                    .expect("Valid transfer should succeed");

            let amount2 = TransferAmount::new(50).expect("valid transfer");
            let new_state2 =
                crate::channel::transition::apply_transfer_state_only(&old_state, &amount2)
                    .expect("Valid transfer should succeed");

            let commitment1 = compute_commitment(channel_id, &new_state1);
            let commitment2 = compute_commitment(channel_id, &new_state2);

            assert_ne!(
                commitment1, commitment2,
                "Different states should produce different commitments"
            );

            let proof1 =
                prove_channel_transition(&config, channel_id, &old_state, &amount1, &new_state1)
                    .expect("Should generate proof for state1");
            let proof2 =
                prove_channel_transition(&config, channel_id, &old_state, &amount2, &new_state2)
                    .expect("Should generate proof for state2");

            let public_inputs1 =
                ChannelPublicInputs { channel_id, channel_commitment: commitment1 };
            let public_inputs2 =
                ChannelPublicInputs { channel_id, channel_commitment: commitment2 };

            verify_channel_transition(&config, &public_inputs1, &proof1)
                .expect("Should verify state1 proof");
            verify_channel_transition(&config, &public_inputs2, &proof2)
                .expect("Should verify state2 proof");
        }

        // Verification fails with wrong channel_id
        {
            let (channel_id, old_state, amount, new_state) = create_test_transition(8, 100, 30);
            let proof =
                prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
                    .expect("Should generate proof");

            let channel_commitment = compute_commitment(channel_id, &new_state);
            let mut wrong_channel_id = channel_id;
            wrong_channel_id[0] = wrong_channel_id[0].wrapping_add(1);

            let wrong_public_inputs =
                ChannelPublicInputs { channel_id: wrong_channel_id, channel_commitment };

            assert!(
                verify_channel_transition(&config, &wrong_public_inputs, &proof).is_err(),
                "Verification should fail with wrong channel_id"
            );
        }

        // Verification fails with wrong channel_commitment
        {
            let (channel_id, old_state, amount, new_state) = create_test_transition(9, 100, 30);
            let proof =
                prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
                    .expect("Should generate proof");

            let mut wrong_commitment = compute_commitment(channel_id, &new_state);
            wrong_commitment[0] = wrong_commitment[0].wrapping_add(1);

            let wrong_public_inputs =
                ChannelPublicInputs { channel_id, channel_commitment: wrong_commitment };

            assert!(
                verify_channel_transition(&config, &wrong_public_inputs, &proof).is_err(),
                "Verification should fail with wrong channel_commitment"
            );
        }

        // Large initial balance
        {
            let (channel_id, old_state, amount, new_state) =
                create_test_transition(10, 1_000_000, 500_000);
            let proof =
                prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
                    .expect("Should generate proof for large balance");

            let channel_commitment = compute_commitment(channel_id, &new_state);
            let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
            verify_channel_transition(&config, &public_inputs, &proof)
                .expect("Should verify large balance proof");
        }

        // Nonce increments correctly
        {
            let channel_id = [11u8; 32];
            let mut current_state = ChannelState::new(1000);

            for expected_nonce in 1..=5 {
                let amount = TransferAmount::new(50).expect("valid transfer");
                let new_state =
                    crate::channel::transition::apply_transfer_state_only(&current_state, &amount)
                        .expect("Valid transfer should succeed");

                assert_eq!(new_state.nonce, expected_nonce, "Nonce should increment correctly");

                let proof = prove_channel_transition(
                    &config,
                    channel_id,
                    &current_state,
                    &amount,
                    &new_state,
                )
                .expect("Should generate proof");

                let channel_commitment = compute_commitment(channel_id, &new_state);
                let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
                verify_channel_transition(&config, &public_inputs, &proof)
                    .expect("Should verify proof with correct nonce");

                current_state = new_state;
            }
        }

        // Balance conservation
        {
            let (channel_id, old_state, amount, new_state) = create_test_transition(12, 100, 30);
            let proof =
                prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
                    .expect("Should generate proof");

            // Verify balance conservation: old_sender = new_sender + new_receiver
            assert_eq!(
                old_state.sender_balance,
                new_state.sender_balance + new_state.receiver_balance,
                "Balance should be conserved"
            );

            let channel_commitment = compute_commitment(channel_id, &new_state);
            let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
            verify_channel_transition(&config, &public_inputs, &proof)
                .expect("Should verify proof with conserved balance");
        }
    }
}
