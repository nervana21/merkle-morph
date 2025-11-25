#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Channel transition AIR for proving channel state transitions
//!
//! This module defines the AIR (Algebraic Intermediate Representation) for
//! proving unidirectional channel state transitions. The AIR verifies that
//! channel state transitions are valid by enforcing balance conservation,
//! nonce increments, and commitment integrity using Poseidon2 hashing.

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;

use crate::zkp::channel::poseidon2_air::{
    column_offsets, create_poseidon2_air, ChannelPoseidon2Air,
};
use crate::zkp::poseidon2_common::{
    eval_poseidon2_air_at_offset, eval_poseidon2_air_multiple_permutations, poseidon2_output_offset,
};

/// Number of columns in the channel transition trace
///
/// - Columns 0-12: Channel state (sender_balance, receiver_balance, nonce, is_closed, amount, commitment[8])
/// - Columns 13 + state_hash_offset: Poseidon2 AIR columns for state_hash = poseidon2(sender_balance || receiver_balance || metadata || is_closed)
/// - Columns 13 + commitment_offset: Poseidon2 AIR columns for commitment (two-stage hash):
///   stage1 = poseidon2(CHANNEL_DOMAIN_TAG || channel_id || state_hash),
///   commitment = poseidon2(stage1 || nonce)
///
/// Note: We compute this at runtime since total_cols() calls poseidon2_air_num_cols() which uses size_of
fn num_cols() -> usize { column_offsets::total_cols() }

/// AIR for proving unidirectional channel state transitions.
///
/// This AIR verifies that channel state transitions are valid by enforcing:
/// - Balance conservation: sender balance decreases and receiver balance increases by the transfer amount
/// - Nonce increments correctly for each transfer
/// - Commitment integrity: state commitments are correctly computed using Poseidon2 hashing
/// - State consistency: padding rows maintain unchanged state
///
/// The AIR operates on a 2-row trace (old state → new state) and validates transitions
/// while keeping sensitive values like transfer amounts private in the witness.
pub(super) struct ChannelTransitionAir {
    /// Poseidon2 AIR instance for commitment verification
    poseidon2_air: ChannelPoseidon2Air,
}

impl ChannelTransitionAir {
    /// Create a new channel transition AIR
    pub(super) fn new() -> Self { Self { poseidon2_air: create_poseidon2_air() } }

    /// Evaluate Poseidon2 AIR constraints when AB::F == Val (BabyBear).
    ///
    /// This method uses a trait bound that ensures ChannelPoseidon2Air implements Air
    /// for the sliced builder, which only works when AB::F == Val.
    ///
    /// For state_hash, we evaluate multiple permutations (up to MAX_STATE_HASH_PERMUTATIONS).
    fn eval_poseidon2_air<AB: AirBuilderWithPublicValues>(&self, builder: &mut AB)
    where
        AB::F: PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
        // This bound ensures AB::F == Val by requiring Poseidon2Air to work with the builder
        for<'a> ChannelPoseidon2Air:
            p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
    {
        // Evaluate state_hash Poseidon2 AIR for each permutation
        let state_hash_offset = column_offsets::STATE_HASH_OFFSET;
        eval_poseidon2_air_multiple_permutations(
            &self.poseidon2_air,
            builder,
            state_hash_offset,
            column_offsets::MAX_STATE_HASH_PERMUTATIONS,
        );

        // Evaluate commitment Poseidon2 AIR
        let commitment_offset = column_offsets::commitment_offset();
        eval_poseidon2_air_at_offset(&self.poseidon2_air, builder, commitment_offset);
    }
}

impl<F: PrimeField64> BaseAir<F> for ChannelTransitionAir {
    fn width(&self) -> usize { num_cols() }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for ChannelTransitionAir
where
    AB::F: PrimeField64,
    AB::F: core::marker::Send + core::marker::Sync,
    AB::F: core::marker::Sized,
    // Constrain AB::F to be BabyBear (MontyField31<BabyBearParameters>)
    // This is required for Poseidon2Air evaluation. We express this by requiring
    // that ChannelPoseidon2Air implements Air for the sliced builder, which only
    // works when AB::F == Val (BabyBear).
    for<'a> ChannelPoseidon2Air:
        p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
{
    /// Evaluate the channel transition AIR
    ///
    /// # Arguments
    ///
    /// * `builder`: The air builder
    ///
    /// # Panics
    ///
    /// Panics if the trace has less than 2 rows.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("Trace must have at least 1 row");
        let next = main.row_slice(1).expect("Trace must have at least 2 rows");

        let sender_balance_old = local[column_offsets::SENDER_BALANCE];
        let receiver_balance_old = local[column_offsets::RECEIVER_BALANCE];
        let nonce_old = local[column_offsets::NONCE];
        let amount_old = local[column_offsets::AMOUNT];
        let is_closed_old = local[column_offsets::IS_CLOSED];
        let commitment_old: Vec<AB::Expr> = (column_offsets::COMMITMENT_START
            ..column_offsets::COMMITMENT_END)
            .map(|i| local[i].into())
            .collect();

        let sender_balance_new = next[column_offsets::SENDER_BALANCE];
        let receiver_balance_new = next[column_offsets::RECEIVER_BALANCE];
        let nonce_new = next[column_offsets::NONCE];
        let amount_new = next[column_offsets::AMOUNT];
        let is_closed_new = next[column_offsets::IS_CLOSED];
        let commitment_new: Vec<AB::Expr> = (column_offsets::COMMITMENT_START
            ..column_offsets::COMMITMENT_END)
            .map(|i| next[i].into())
            .collect();

        let amount_field = amount_new;

        // Extract public commitment from public values (indices 8-15) early due to borrow checker:
        // builder.public_values() returns a reference, which we can't hold while using builder mutably
        // in the loop below. Converting to owned Expr values here avoids the conflict.
        let public_values = builder.public_values();
        let public_commitment: Vec<AB::Expr> = (8..16).map(|i| public_values[i].into()).collect();

        let nonce_diff = nonce_new - nonce_old;
        let mut when_transition = builder.when_transition();
        // Enforce that nonce_diff is either 0 (padding row) or 1 (real transition)
        // This constraint: nonce_diff * (nonce_diff - 1) = 0 ensures nonce_diff ∈ {0, 1}
        when_transition.assert_zero(nonce_diff.clone() * (nonce_diff.clone() - AB::Expr::ONE));

        // Create selector variables: is_real_transition = 1 when nonce_diff = 1, else 0
        // is_padding = 1 when nonce_diff = 0, else 0
        // These allow us to conditionally apply different constraints based on row type
        let is_real_transition = nonce_diff.clone();
        let is_padding = AB::Expr::ONE - nonce_diff;

        let delta_sender = AB::Expr::ZERO - amount_field;
        let delta_receiver = amount_field;

        let real_sender = sender_balance_new - sender_balance_old - delta_sender;
        let real_receiver = receiver_balance_new - receiver_balance_old - delta_receiver;
        let real_nonce = nonce_new - nonce_old - AB::Expr::ONE;

        let padding_sender = sender_balance_new - sender_balance_old;
        let padding_receiver = receiver_balance_new - receiver_balance_old;
        let padding_nonce = nonce_new - nonce_old;
        let padding_amount = amount_new - amount_old;
        let padding_is_closed = is_closed_new - is_closed_old;

        let commitment_start = column_offsets::commitment_offset();
        let output_offset = poseidon2_output_offset();
        let computed_commitment: Vec<AB::Expr> = (0..8)
            .map(|i| {
                let col_idx = commitment_start + output_offset + i;
                next[col_idx].into()
            })
            .collect();

        for (computed, public) in commitment_new.iter().zip(public_commitment.iter()) {
            let constraint = is_real_transition.clone() * (computed.clone() - public.clone());
            when_transition.assert_zero(constraint);
        }

        for (computed, expected) in computed_commitment.iter().zip(commitment_new.iter()) {
            let constraint = is_real_transition.clone() * (computed.clone() - expected.clone());
            when_transition.assert_zero(constraint);
        }

        // Apply constraints conditionally: for real transitions, enforce balance/nonce changes;
        // for padding rows, enforce no changes. The selector pattern ensures:
        // - When is_real_transition=1: only real_* constraints are active (padding_* terms = 0)
        // - When is_padding=1: only padding_* constraints are active (real_* terms = 0)
        let sender_constraint = is_real_transition.clone() * real_sender.clone()
            + is_padding.clone() * padding_sender.clone();
        let receiver_constraint = is_real_transition.clone() * real_receiver.clone()
            + is_padding.clone() * padding_receiver.clone();
        let nonce_constraint = is_real_transition.clone() * real_nonce.clone()
            + is_padding.clone() * padding_nonce.clone();

        when_transition.assert_zero(sender_constraint);
        when_transition.assert_zero(receiver_constraint);
        when_transition.assert_zero(nonce_constraint);

        when_transition.assert_zero(
            is_real_transition.clone() * (amount_new - amount_old)
                + is_padding.clone() * padding_amount,
        );

        when_transition.assert_zero(is_padding.clone() * padding_is_closed);

        for i in 0..8 {
            let commitment_old_field = commitment_old[i].clone();
            let commitment_new_field = commitment_new[i].clone();
            let commitment_diff = commitment_new_field - commitment_old_field;
            when_transition.assert_zero(is_padding.clone() * commitment_diff);
        }

        self.eval_poseidon2_air(builder);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::state::ChannelState;
    use crate::channel::TransferAmount;
    use crate::zkp::channel::public_inputs::ChannelPublicInputs;
    use crate::zkp::channel::{prove_channel_transition, verify_channel_transition};
    use crate::zkp::types::{create_config, u64_to_field, Val};

    /// Test balance delta calculation logic for unidirectional channels
    ///
    /// This test verifies that the balance delta formula is correct:
    /// delta_sender = -amount
    /// delta_receiver = +amount
    #[test]
    fn test_balance_delta_calculation_unidirectional() {
        // Test case: sender sends 30 to receiver
        let amount = 30u64;
        let amount_field = u64_to_field(amount);

        // In a unidirectional channel, sender always loses amount, receiver always gains amount
        let delta_sender = Val::ZERO - amount_field; // -amount
        let delta_receiver = amount_field; // +amount

        // Verify the constraint: balance_new - balance_old - delta = 0
        // For sender: (old - amount) - old - (-amount) = -amount + amount = 0
        let sender_balance_old = u64_to_field(100);
        let sender_balance_new = u64_to_field(70);
        let constraint_sender = sender_balance_new - sender_balance_old - delta_sender;
        assert_eq!(constraint_sender, Val::ZERO, "Constraint should be zero for sender");

        // For receiver: (old + amount) - old - amount = amount - amount = 0
        let receiver_balance_old = u64_to_field(0);
        let receiver_balance_new = amount_field;
        let constraint_receiver = receiver_balance_new - receiver_balance_old - delta_receiver;
        assert_eq!(constraint_receiver, Val::ZERO, "Constraint should be zero for receiver");
    }

    /// Test that eval() function correctly enforces constraints for valid transitions
    ///
    /// This test exercises the eval() function indirectly through the proving system.
    /// The eval() function is called by p3_uni_stark::prove() when generating proofs.
    ///
    /// ## Where eval() is called:
    /// 1. **During proof generation**: `p3_uni_stark::prove()` calls `air.eval()` internally
    ///    to evaluate constraints on the trace (see `src/zkp/channel/prover.rs:60`)
    /// 2. **During proof verification**: `p3_uni_stark::verify()` also calls `air.eval()`
    ///    to verify constraints (see `src/zkp/channel/verifier.rs:50`)
    ///
    /// The test verifies that:
    /// 1. Valid transitions (correct balance changes, nonce increment) pass eval constraints
    /// 2. The proof can be generated and verified successfully
    ///
    /// NOTE: These tests verify that eval() correctly enforces constraints.
    /// Poseidon2 AIR constraints are now evaluated using ColumnSliceBuilder,
    /// providing full verification of the hash computations.
    #[test]
    fn test_eval_valid_transition() {
        let config = create_config().expect("Should create config");
        let channel_id = [0u8; 32];

        // Valid transition: sender sends 30 to receiver
        let old_state = ChannelState::new(100);
        let amount = TransferAmount::new(30).expect("valid transfer");
        // Use apply_transfer_state_only to get the correct new_state with incremented nonce
        let new_state = crate::channel::transition::apply_transfer_state_only(&old_state, &amount)
            .expect("Valid transfer should succeed");

        // Generate proof (this calls eval() internally)
        let proof = prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
            .expect("Valid transition should generate proof");

        // Extract commitment from trace (matching what the prover uses)
        // NOTE: This may differ from compute_commitment() due to Poseidon2 AIR trace differences
        use p3_matrix::Matrix;

        use crate::zkp::channel::trace::build_channel_trace;
        let trace = build_channel_trace(channel_id, &old_state, &new_state, &amount)
            .expect("Should build trace");
        let commitment_fields: Vec<u32> = {
            let new_state_row = trace.row_slice(1).expect("Trace must have at least 2 rows");
            (column_offsets::COMMITMENT_START..column_offsets::COMMITMENT_END)
                .map(|i| p3_field::PrimeField32::as_canonical_u32(&new_state_row[i]))
                .collect()
        };
        let mut channel_commitment = [0u8; 32];
        for (i, &val) in commitment_fields.iter().enumerate() {
            channel_commitment[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
        }

        // Verify proof (this also calls eval() internally to verify constraints)
        let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
        verify_channel_transition(&config, &public_inputs, &proof)
            .expect("Valid proof should verify");
    }

    /// Test that eval() function correctly handles padding rows
    ///
    /// Padding rows are used to pad the trace to a power of 2 for FRI.
    /// The eval() function should enforce that padding rows have:
    /// - Same balances (no change)
    /// - Same nonce (no increment)
    /// - Same commitment (no change)
    ///
    #[test]
    fn test_eval_padding_rows() {
        let config = create_config().expect("Should create config");
        let channel_id = [0u8; 32];

        // Valid transition with padding rows
        let old_state = ChannelState::new(100);
        let amount = TransferAmount::new(30).expect("valid transfer");
        // Use apply_transfer_state_only to get the correct new_state with incremented nonce
        let new_state = crate::channel::transition::apply_transfer_state_only(&old_state, &amount)
            .expect("Valid transfer should succeed");

        // Generate proof (trace will be padded to power of 2, eval() should handle padding correctly)
        let proof = prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
            .expect("Valid transition with padding should generate proof");

        // Extract commitment using compute_commitment (now matches trace since constants are synchronized)
        use crate::channel::commitment::compute_commitment;
        let channel_commitment = compute_commitment(channel_id, &new_state);

        // Verify proof (eval() should verify padding rows are correct)
        let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
        verify_channel_transition(&config, &public_inputs, &proof)
            .expect("Proof with padding rows should verify");
    }

    /// Test AIR creation and width
    #[test]
    fn test_air_creation() {
        use crate::zkp::types::Val;

        let air = ChannelTransitionAir::new();
        let width = <ChannelTransitionAir as BaseAir<Val>>::width(&air);

        // Width should be positive and match expected structure
        assert!(width > 0, "AIR should have positive width");

        // Width should account for base columns (13) + Poseidon2 columns for state_hash (4 permutations)
        // + Poseidon2 columns for commitment (1 permutation)
        let expected_min_width = 13; // Conservative lower bound
        assert!(width >= expected_min_width, "AIR width should be at least {}", expected_min_width);
    }

    /// Test AIR with multiple transitions
    #[test]
    fn test_air_multiple_transitions() {
        let config = create_config().expect("Should create config");
        let channel_id = [0u8; 32];
        let mut current_state = ChannelState::new(1000);

        // Apply multiple transfers
        for i in 0..3 {
            let amount = TransferAmount::new(50 + i * 10).expect("valid transfer");
            let new_state =
                crate::channel::transition::apply_transfer_state_only(&current_state, &amount)
                    .expect("Valid transfer should succeed");

            let proof =
                prove_channel_transition(&config, channel_id, &current_state, &amount, &new_state)
                    .expect("Should generate proof");

            use crate::channel::commitment::compute_commitment;
            let channel_commitment = compute_commitment(channel_id, &new_state);
            let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
            verify_channel_transition(&config, &public_inputs, &proof)
                .expect("Should verify proof");

            current_state = new_state;
        }
    }

    /// Test AIR with different channel IDs
    #[test]
    fn test_air_different_channel_ids() {
        let config = create_config().expect("Should create config");

        for i in 0..3 {
            let channel_id = {
                let mut id = [0u8; 32];
                id[0] = i;
                id
            };

            let old_state = ChannelState::new(100);
            let amount = TransferAmount::new(30).expect("valid transfer");
            let new_state =
                crate::channel::transition::apply_transfer_state_only(&old_state, &amount)
                    .expect("Valid transfer should succeed");

            let proof =
                prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
                    .expect("Should generate proof");

            use crate::channel::commitment::compute_commitment;
            let channel_commitment = compute_commitment(channel_id, &new_state);
            let public_inputs = ChannelPublicInputs { channel_id, channel_commitment };
            verify_channel_transition(&config, &public_inputs, &proof)
                .expect("Should verify proof");
        }
    }

    /// Test AIR verification fails with wrong commitment
    #[test]
    fn test_air_verify_fails_wrong_commitment() {
        use crate::channel::commitment::compute_commitment;

        let config = create_config().expect("Should create config");
        let channel_id = [0u8; 32];

        let old_state = ChannelState::new(100);
        let amount = TransferAmount::new(30).expect("valid transfer");
        let new_state = crate::channel::transition::apply_transfer_state_only(&old_state, &amount)
            .expect("Valid transfer should succeed");

        let proof = prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
            .expect("Should generate proof");

        // Try to verify with wrong commitment
        let mut wrong_commitment = compute_commitment(channel_id, &new_state);
        wrong_commitment[0] = wrong_commitment[0].wrapping_add(1);
        let public_inputs =
            ChannelPublicInputs { channel_id, channel_commitment: wrong_commitment };

        // Verification should fail
        assert!(
            verify_channel_transition(&config, &public_inputs, &proof).is_err(),
            "Verification should fail with wrong commitment"
        );
    }

    /// Test AIR verification fails with wrong channel_id
    #[test]
    fn test_air_verify_fails_wrong_channel_id() {
        let config = create_config().expect("Should create config");
        let channel_id = [0u8; 32];

        let old_state = ChannelState::new(100);
        let amount = TransferAmount::new(30).expect("valid transfer");
        let new_state = crate::channel::transition::apply_transfer_state_only(&old_state, &amount)
            .expect("Valid transfer should succeed");

        let proof = prove_channel_transition(&config, channel_id, &old_state, &amount, &new_state)
            .expect("Should generate proof");

        // Try to verify with wrong channel_id
        let mut wrong_channel_id = channel_id;
        wrong_channel_id[0] = wrong_channel_id[0].wrapping_add(1);
        use crate::channel::commitment::compute_commitment;
        let channel_commitment = compute_commitment(channel_id, &new_state);
        let public_inputs =
            ChannelPublicInputs { channel_id: wrong_channel_id, channel_commitment };

        // Verification should fail
        assert!(
            verify_channel_transition(&config, &public_inputs, &proof).is_err(),
            "Verification should fail with wrong channel_id"
        );
    }
}
