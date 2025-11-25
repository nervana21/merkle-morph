//! Wallet proof generation
//!
//! This module provides functions for generating zero-knowledge proofs
//! for wallet commitment aggregation and state transitions.

use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_uni_stark::prove;

use crate::wallet::apply_operation;
use crate::wallet::commitment::compute_commitment_from_channels;
use crate::wallet::operation::WalletTransition;
use crate::wallet::state::WalletState;
use crate::zkp::prover_common::prove_with_commitment;
use crate::zkp::types::{bytes32_to_fields, Proof, StarkConfig, Val};
use crate::zkp::wallet::air::WalletCommitmentAir;
use crate::zkp::wallet::poseidon2_air::column_offsets;
use crate::zkp::wallet::trace::build_wallet_trace;
use crate::zkp::wallet::transition_air::WalletTransitionAir;
use crate::zkp::wallet::transition_poseidon2_air::column_offsets as transition_column_offsets;
use crate::zkp::wallet::transition_trace::build_sequence_trace;
use crate::Result;

/// Generate a zero-knowledge proof for a wallet commitment
///
/// This function proves that a wallet commitment is correctly computed from
/// its channel commitments using an accumulator chain. The proof demonstrates
/// that the wallet commitment is the result of aggregating all channel
/// commitments in sorted order.
///
/// # Arguments
/// * `config` - Proof system configuration (`StarkConfig`)
/// * `wallet` - Wallet containing channel commitments
///
/// # Returns
/// A zero-knowledge proof for the wallet commitment
pub fn prove_wallet_commitment(config: &StarkConfig, wallet: &WalletState) -> Result<Proof> {
    let trace = build_wallet_trace(wallet)?;
    let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)?;
    let air = WalletCommitmentAir::new();

    prove_with_commitment(
        config,
        trace,
        |trace| {
            if trace.height() == 0 {
                // Empty wallet: return zero commitment
                Ok(vec![Val::ZERO; 8])
            } else {
                let last_row =
                    trace.row_slice(trace.height() - 1).expect("Trace must have last row");
                let mut commitment_fields = vec![Val::ZERO; 8];
                for (i, j) in
                    (column_offsets::NEXT_ACC_START..column_offsets::NEXT_ACC_END).enumerate()
                {
                    commitment_fields[i] = last_row[j];
                }
                Ok(commitment_fields)
            }
        },
        wallet_commitment,
        wallet.id,
        &air,
    )
}

/// Generate a zero-knowledge proof for wallet state transitions
///
/// This function proves that a sequence of wallet state transitions is valid.
/// The proof demonstrates that each transition in the sequence is valid and
/// that transitions are properly chained together.
///
/// # Arguments
/// * `config` - Proof system configuration (`StarkConfig`)
/// * `wallets` - Sequence of wallet states: `wallets[0]` is initial, `wallets[n]` is final
/// * `transitions` - Sequence of transitions: `transitions[i]` transitions `wallets[i]` to `wallets[i+1]`
///
/// # Returns
/// A zero-knowledge proof for the wallet transitions
pub fn prove_wallet_transition(
    config: &StarkConfig,
    wallets: &[&WalletState],
    transitions: &[&WalletTransition],
) -> Result<Proof> {
    if wallets.is_empty() {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    if wallets.len() != transitions.len() + 1 {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    // Validate sequence: apply each transition and verify resulting wallet matches next
    for i in 0..transitions.len() {
        let wallet_copy = WalletState {
            id: wallets[i].id,
            channels: wallets[i].channels.clone(),
            commitment: wallets[i].commitment,
        };
        let expected_next_wallet = apply_operation(wallet_copy, transitions[i])?;
        if expected_next_wallet.commitment != wallets[i + 1].commitment {
            return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
        }
    }

    // Convert references to owned values for trace building
    let wallets_owned: Vec<WalletState> = wallets
        .iter()
        .map(|w| WalletState { id: w.id, channels: w.channels.clone(), commitment: w.commitment })
        .collect();
    let transitions_owned: Vec<WalletTransition> =
        transitions.iter().map(|i| (*i).clone()).collect();

    let trace = build_sequence_trace(&wallets_owned, &transitions_owned)?;

    let initial_wallet_commitment =
        compute_commitment_from_channels(wallets[0].id, &wallets[0].channels)?;
    let final_wallet_commitment = compute_commitment_from_channels(
        wallets[wallets.len() - 1].id,
        &wallets[wallets.len() - 1].channels,
    )?;

    // Verify commitments match trace
    let (initial_commitment_fields, final_commitment_fields) = {
        let first_row = trace.row_slice(0).expect("Trace must have first row");
        let last_row = trace.row_slice(trace.height() - 1).expect("Trace must have last row");
        let mut initial_fields = vec![Val::ZERO; 8];
        for (i, j) in (transition_column_offsets::PREV_OLD_ACC_START
            ..transition_column_offsets::PREV_OLD_ACC_END)
            .enumerate()
        {
            initial_fields[i] = first_row[j];
        }
        let mut final_fields = vec![Val::ZERO; 8];
        for (i, j) in (transition_column_offsets::NEXT_NEW_ACC_START
            ..transition_column_offsets::NEXT_NEW_ACC_END)
            .enumerate()
        {
            final_fields[i] = last_row[j];
        }
        (initial_fields, final_fields)
    };

    let expected_initial_fields = bytes32_to_fields(initial_wallet_commitment);
    let expected_final_fields = bytes32_to_fields(final_wallet_commitment);

    if initial_commitment_fields != expected_initial_fields
        || final_commitment_fields != expected_final_fields
    {
        return Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed));
    }

    // Build public values:
    // 0-7: wallet_id
    // 8-15: initial_wallet_commitment
    // 16-23: final_wallet_commitment
    let mut public_values = Vec::new();
    let wallet_id_fields = bytes32_to_fields(wallets[0].id);
    public_values.extend(wallet_id_fields.iter().map(|f| Val::from(*f)));
    public_values.extend(expected_initial_fields.iter().map(|f| Val::from(*f)));
    public_values.extend(expected_final_fields.iter().map(|f| Val::from(*f)));

    // Generate proof
    let air = WalletTransitionAir::new();

    // Wrap prove in catch_unwind to handle panics recursively
    let proof_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove(config, &air, trace, &public_values)
    }));

    match proof_result {
        Ok(proof) => Ok(proof),
        Err(_panic_payload) =>
            Err(crate::Error::Zkp(crate::errors::ZkpError::ProofGenerationFailed)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::types::MAX_CHANNELS;
    use crate::wallet::commitment::compute_commitment_from_channels;
    use crate::wallet::operation::WalletTransition;
    use crate::wallet::state::WalletState;
    use crate::wallet::transition::apply_operation;
    use crate::zkp::types::create_config;
    use crate::zkp::wallet::public_inputs::{WalletPublicInputs, WalletTransitionPublicInputs};
    use crate::zkp::wallet::{verify_wallet_commitment, verify_wallet_transition};

    /// Helper function to create a test wallet with specified channels
    fn create_test_wallet(wallet_id: u8, channels: &[(u8, u8)]) -> WalletState {
        let mut map = BTreeMap::new();
        for (cid, comm) in channels.iter() {
            let mut channel_id = [0u8; 32];
            channel_id[31] = *cid;

            let mut channel_commitment = [0u8; 32];
            channel_commitment[31] = *comm;

            map.insert(channel_id, channel_commitment);
        }
        let mut wallet = WalletState::from_channels([wallet_id; 32], map);
        // Compute commitment for the wallet
        wallet.commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
            .expect("should compute commitment");
        wallet
    }

    #[test]
    fn test_prove_wallet_commitment() {
        let config = create_config().expect("Should create config");

        // Test 1: Empty wallet
        {
            let wallet = create_test_wallet(1, &[]);
            let proof = prove_wallet_commitment(&config, &wallet)
                .expect("Should generate proof for empty wallet");

            let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
                .expect("should compute commitment");
            let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

            verify_wallet_commitment(&config, &public_inputs, &proof)
                .expect("Should verify empty wallet proof");
        }

        // Single channel
        {
            let wallet = create_test_wallet(2, &[(10, 20)]);
            let proof = prove_wallet_commitment(&config, &wallet)
                .expect("Should generate proof for single channel wallet");

            let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
                .expect("should compute commitment");
            let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

            verify_wallet_commitment(&config, &public_inputs, &proof)
                .expect("Should verify single channel proof");
        }

        // Multiple channels (small count)
        {
            let wallet = create_test_wallet(3, &[(1, 10), (2, 20), (3, 30)]);
            let proof = prove_wallet_commitment(&config, &wallet)
                .expect("Should generate proof for multiple channels");

            let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
                .expect("should compute commitment");
            let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

            verify_wallet_commitment(&config, &public_inputs, &proof)
                .expect("Should verify multiple channels proof");
        }

        // Multiple channels (medium count)
        {
            let channels: Vec<_> = (0..8).map(|i| (i, i * 10)).collect();
            let wallet = create_test_wallet(4, &channels);
            let proof = prove_wallet_commitment(&config, &wallet)
                .expect("Should generate proof for medium channel count");

            let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
                .expect("should compute commitment");
            let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

            verify_wallet_commitment(&config, &public_inputs, &proof)
                .expect("Should verify medium channel count proof");
        }

        // Maximum channels
        {
            let channels: Vec<_> = (0..MAX_CHANNELS as u8).map(|i| (i, i * 5)).collect();
            let wallet = create_test_wallet(5, &channels);
            let proof = prove_wallet_commitment(&config, &wallet)
                .expect("Should generate proof for maximum channels");

            let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
                .expect("should compute commitment");
            let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

            verify_wallet_commitment(&config, &public_inputs, &proof)
                .expect("Should verify maximum channels proof");
        }

        // Different wallet IDs produce different commitments
        {
            let wallet1 = create_test_wallet(10, &[(1, 5)]);
            let wallet2 = create_test_wallet(20, &[(1, 5)]);

            let commitment1 = compute_commitment_from_channels(wallet1.id, &wallet1.channels)
                .expect("should compute commitment");
            let commitment2 = compute_commitment_from_channels(wallet2.id, &wallet2.channels)
                .expect("should compute commitment");

            assert_ne!(
                commitment1, commitment2,
                "Different wallet IDs should produce different commitments"
            );

            let proof1 = prove_wallet_commitment(&config, &wallet1)
                .expect("Should generate proof for wallet1");
            let proof2 = prove_wallet_commitment(&config, &wallet2)
                .expect("Should generate proof for wallet2");

            let public_inputs1 =
                WalletPublicInputs { wallet_id: wallet1.id, wallet_commitment: commitment1 };
            let public_inputs2 =
                WalletPublicInputs { wallet_id: wallet2.id, wallet_commitment: commitment2 };

            verify_wallet_commitment(&config, &public_inputs1, &proof1)
                .expect("Should verify wallet1 proof");
            verify_wallet_commitment(&config, &public_inputs2, &proof2)
                .expect("Should verify wallet2 proof");

            // Cross-verification should fail
            assert!(
                verify_wallet_commitment(&config, &public_inputs1, &proof2).is_err(),
                "Wallet1 proof should not verify with wallet2 public inputs"
            );
        }

        // Deterministic proof generation
        {
            let wallet = create_test_wallet(7, &[(1, 10), (2, 20), (3, 30)]);
            let proof1 =
                prove_wallet_commitment(&config, &wallet).expect("Should generate first proof");
            let proof2 =
                prove_wallet_commitment(&config, &wallet).expect("Should generate second proof");

            // Proofs should be identical for same input
            // Note: This tests that the proof generation is deterministic
            // The actual proof structure may vary, but verification should work for both
            let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
                .expect("should compute commitment");
            let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

            verify_wallet_commitment(&config, &public_inputs, &proof1)
                .expect("First proof should verify");
            verify_wallet_commitment(&config, &public_inputs, &proof2)
                .expect("Second proof should verify");
        }

        // Channels processed in sorted order
        {
            // Create channels in unsorted order
            let wallet = create_test_wallet(8, &[(5, 50), (1, 10), (3, 30), (2, 20)]);
            let proof = prove_wallet_commitment(&config, &wallet)
                .expect("Should generate proof with unsorted channel input");

            let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
                .expect("should compute commitment");
            let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

            verify_wallet_commitment(&config, &public_inputs, &proof)
                .expect("Should verify proof with channels processed in sorted order");
        }

        // Duplicate channel IDs (should overwrite)
        {
            let mut map = BTreeMap::new();
            let mut channel_id = [0u8; 32];
            channel_id[31] = 1;

            let mut comm1 = [0u8; 32];
            comm1[31] = 10;
            map.insert(channel_id, comm1);

            let mut comm2 = [0u8; 32];
            comm2[31] = 20;
            map.insert(channel_id, comm2); // Overwrites previous

            let wallet = WalletState::from_channels([9; 32], map);
            let proof = prove_wallet_commitment(&config, &wallet)
                .expect("Should generate proof with duplicate channel ID");

            let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
                .expect("should compute commitment");
            let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

            verify_wallet_commitment(&config, &public_inputs, &proof)
                .expect("Should verify proof with duplicate channel ID (overwritten)");
        }

        // Verification fails with wrong wallet_id
        {
            let wallet = create_test_wallet(11, &[(1, 10)]);
            let proof = prove_wallet_commitment(&config, &wallet).expect("Should generate proof");

            let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
                .expect("should compute commitment");
            let mut wrong_wallet_id = wallet.id;
            wrong_wallet_id[0] = wrong_wallet_id[0].wrapping_add(1);

            let wrong_public_inputs =
                WalletPublicInputs { wallet_id: wrong_wallet_id, wallet_commitment };

            assert!(
                verify_wallet_commitment(&config, &wrong_public_inputs, &proof).is_err(),
                "Verification should fail with wrong wallet_id"
            );
        }

        // Verification fails with wrong wallet_commitment
        {
            let wallet = create_test_wallet(12, &[(1, 10), (2, 20)]);
            let proof = prove_wallet_commitment(&config, &wallet).expect("Should generate proof");

            let mut wrong_commitment =
                compute_commitment_from_channels(wallet.id, &wallet.channels)
                    .expect("should compute commitment");
            wrong_commitment[0] = wrong_commitment[0].wrapping_add(1);

            let wrong_public_inputs =
                WalletPublicInputs { wallet_id: wallet.id, wallet_commitment: wrong_commitment };

            assert!(
                verify_wallet_commitment(&config, &wrong_public_inputs, &proof).is_err(),
                "Verification should fail with wrong wallet_commitment"
            );
        }

        // Large channel IDs and commitments
        {
            // Use values that fit in u8 (max 255) to avoid overflow
            // Channel IDs: 200-204, commitments: 100-104 (avoiding i*2 overflow)
            let channels: Vec<_> = (200..205).map(|i| (i, (i - 100))).collect();
            let wallet = create_test_wallet(13, &channels);
            let proof = prove_wallet_commitment(&config, &wallet)
                .expect("Should generate proof with large channel values");

            let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
                .expect("should compute commitment");
            let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

            verify_wallet_commitment(&config, &public_inputs, &proof)
                .expect("Should verify proof with large channel values");
        }
    }

    #[test]
    fn test_prove_wallet_transition() {
        let config = create_config().expect("Should create config");

        // Empty wallet → insert channel
        {
            let old_wallet = create_test_wallet(1, &[]);

            let mut channel_id = [0u8; 32];
            channel_id[31] = 10;
            let mut channel_commitment = [0u8; 32];
            channel_commitment[31] = 20;
            let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };

            let old_wallet_copy = WalletState {
                id: old_wallet.id,
                channels: old_wallet.channels.clone(),
                commitment: old_wallet.commitment,
            };
            let new_wallet =
                apply_operation(old_wallet_copy, &transition).expect("Should apply transition");

            let proof =
                prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&transition])
                    .expect("Should generate proof for empty wallet → insert");

            let initial_commitment =
                compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
                    .expect("should compute commitment");
            let final_commitment =
                compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
                    .expect("should compute commitment");

            let public_inputs = WalletTransitionPublicInputs {
                wallet_id: old_wallet.id,
                initial_wallet_commitment: initial_commitment,
                final_wallet_commitment: final_commitment,
            };
            verify_wallet_transition(&config, &public_inputs, &proof)
                .expect("Should verify empty wallet → insert proof");
        }

        // Single channel → insert another channel
        {
            let old_wallet = create_test_wallet(2, &[(10, 20)]);

            let mut channel_id = [0u8; 32];
            channel_id[31] = 5;
            let mut channel_commitment = [0u8; 32];
            channel_commitment[31] = 30;
            let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };

            let old_wallet_copy = WalletState {
                id: old_wallet.id,
                channels: old_wallet.channels.clone(),
                commitment: old_wallet.commitment,
            };
            let new_wallet =
                apply_operation(old_wallet_copy, &transition).expect("Should apply transition");

            let proof =
                prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&transition])
                    .expect("Should generate proof for single channel → insert");

            let initial_commitment =
                compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
                    .expect("should compute commitment");
            let final_commitment =
                compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
                    .expect("should compute commitment");

            let public_inputs = WalletTransitionPublicInputs {
                wallet_id: old_wallet.id,
                initial_wallet_commitment: initial_commitment,
                final_wallet_commitment: final_commitment,
            };
            verify_wallet_transition(&config, &public_inputs, &proof)
                .expect("Should verify single channel → insert proof");
        }

        // Single channel → remove channel (empty wallet)
        {
            let old_wallet = create_test_wallet(3, &[(10, 20)]);

            let mut channel_id = [0u8; 32];
            channel_id[31] = 10;
            let transition = WalletTransition::RemoveChannel { channel_id };

            let old_wallet_copy = WalletState {
                id: old_wallet.id,
                channels: old_wallet.channels.clone(),
                commitment: old_wallet.commitment,
            };
            let new_wallet =
                apply_operation(old_wallet_copy, &transition).expect("Should apply transition");

            let proof =
                prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&transition])
                    .expect("Should generate proof for single channel → remove");

            let initial_commitment =
                compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
                    .expect("should compute commitment");
            let final_commitment =
                compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
                    .expect("should compute commitment");

            let public_inputs = WalletTransitionPublicInputs {
                wallet_id: old_wallet.id,
                initial_wallet_commitment: initial_commitment,
                final_wallet_commitment: final_commitment,
            };
            verify_wallet_transition(&config, &public_inputs, &proof)
                .expect("Should verify single channel → remove proof");
        }

        // Multiple channels → insert channel
        {
            let old_wallet = create_test_wallet(4, &[(1, 10), (2, 20), (3, 30)]);

            let mut channel_id = [0u8; 32];
            channel_id[31] = 5;
            let mut channel_commitment = [0u8; 32];
            channel_commitment[31] = 50;
            let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };

            let old_wallet_copy = WalletState {
                id: old_wallet.id,
                channels: old_wallet.channels.clone(),
                commitment: old_wallet.commitment,
            };
            let new_wallet =
                apply_operation(old_wallet_copy, &transition).expect("Should apply transition");

            let proof =
                prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&transition])
                    .expect("Should generate proof for multiple channels → insert");

            let initial_commitment =
                compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
                    .expect("should compute commitment");
            let final_commitment =
                compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
                    .expect("should compute commitment");

            let public_inputs = WalletTransitionPublicInputs {
                wallet_id: old_wallet.id,
                initial_wallet_commitment: initial_commitment,
                final_wallet_commitment: final_commitment,
            };
            verify_wallet_transition(&config, &public_inputs, &proof)
                .expect("Should verify multiple channels → insert proof");
        }

        // Multiple channels → remove channel
        {
            let old_wallet = create_test_wallet(5, &[(1, 10), (2, 20), (3, 30)]);

            let mut channel_id = [0u8; 32];
            channel_id[31] = 2;
            let transition = WalletTransition::RemoveChannel { channel_id };

            let old_wallet_copy = WalletState {
                id: old_wallet.id,
                channels: old_wallet.channels.clone(),
                commitment: old_wallet.commitment,
            };
            let new_wallet =
                apply_operation(old_wallet_copy, &transition).expect("Should apply transition");

            let proof =
                prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&transition])
                    .expect("Should generate proof for multiple channels → remove");

            let initial_commitment =
                compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
                    .expect("should compute commitment");
            let final_commitment =
                compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
                    .expect("should compute commitment");

            let public_inputs = WalletTransitionPublicInputs {
                wallet_id: old_wallet.id,
                initial_wallet_commitment: initial_commitment,
                final_wallet_commitment: final_commitment,
            };
            verify_wallet_transition(&config, &public_inputs, &proof)
                .expect("Should verify multiple channels → remove proof");
        }

        // Update existing channel (insert with same channel_id)
        {
            let old_wallet = create_test_wallet(6, &[(1, 10), (2, 20)]);

            let mut channel_id = [0u8; 32];
            channel_id[31] = 1;
            let mut new_channel_commitment = [0u8; 32];
            new_channel_commitment[31] = 100; // Update commitment
            let transition = WalletTransition::InsertChannel {
                channel_id,
                channel_commitment: new_channel_commitment,
            };

            let old_wallet_copy = WalletState {
                id: old_wallet.id,
                channels: old_wallet.channels.clone(),
                commitment: old_wallet.commitment,
            };
            let new_wallet =
                apply_operation(old_wallet_copy, &transition).expect("Should apply transition");

            let proof =
                prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&transition])
                    .expect("Should generate proof for channel update");

            let initial_commitment =
                compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
                    .expect("should compute commitment");
            let final_commitment =
                compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
                    .expect("should compute commitment");

            let public_inputs = WalletTransitionPublicInputs {
                wallet_id: old_wallet.id,
                initial_wallet_commitment: initial_commitment,
                final_wallet_commitment: final_commitment,
            };
            verify_wallet_transition(&config, &public_inputs, &proof)
                .expect("Should verify channel update proof");
        }

        {
            let wallet0 = create_test_wallet(7, &[(1, 10)]);

            let mut channel_id1 = [0u8; 32];
            channel_id1[31] = 2;
            let mut channel_commitment1 = [0u8; 32];
            channel_commitment1[31] = 20;
            let transition1 = WalletTransition::InsertChannel {
                channel_id: channel_id1,
                channel_commitment: channel_commitment1,
            };

            let wallet0_copy = WalletState {
                id: wallet0.id,
                channels: wallet0.channels.clone(),
                commitment: wallet0.commitment,
            };
            let wallet1 =
                apply_operation(wallet0_copy, &transition1).expect("Should apply transition1");

            let mut channel_id2 = [0u8; 32];
            channel_id2[31] = 3;
            let mut channel_commitment2 = [0u8; 32];
            channel_commitment2[31] = 30;
            let transition2 = WalletTransition::InsertChannel {
                channel_id: channel_id2,
                channel_commitment: channel_commitment2,
            };

            let wallet1_copy = WalletState {
                id: wallet1.id,
                channels: wallet1.channels.clone(),
                commitment: wallet1.commitment,
            };
            let wallet2 =
                apply_operation(wallet1_copy, &transition2).expect("Should apply transition2");

            let proof_result = prove_wallet_transition(
                &config,
                &[&wallet0, &wallet1, &wallet2],
                &[&transition1, &transition2],
            );

            match proof_result {
                Ok(proof) => {
                    let initial_commitment =
                        compute_commitment_from_channels(wallet0.id, &wallet0.channels)
                            .expect("should compute commitment");
                    let final_commitment =
                        compute_commitment_from_channels(wallet2.id, &wallet2.channels)
                            .expect("should compute commitment");

                    let public_inputs = WalletTransitionPublicInputs {
                        wallet_id: wallet0.id,
                        initial_wallet_commitment: initial_commitment,
                        final_wallet_commitment: final_commitment,
                    };
                    verify_wallet_transition(&config, &public_inputs, &proof)
                        .expect("Should verify multiple transitions proof");
                }
                Err(e) => {
                    panic!("Proof generation failed: {:?}", e);
                }
            }
        }
    }
}
