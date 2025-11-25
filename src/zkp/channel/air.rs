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
/// - Columns 13 + state_hash_offset: Poseidon2 AIR columns for state_hash = poseidon2(sender_balance || receiver_balance || sender_pubkey || receiver_pubkey || metadata || is_closed)
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
        let auth_hash_new: Vec<AB::Expr> = (column_offsets::AUTH_HASH_START
            ..column_offsets::AUTH_HASH_END)
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

        // Verify auth_hash consistency: padding rows should maintain unchanged auth_hash
        // For real transitions, auth_hash binds the commitment to sender's private key
        let auth_hash_old: Vec<AB::Expr> = (column_offsets::AUTH_HASH_START
            ..column_offsets::AUTH_HASH_END)
            .map(|i| local[i].into())
            .collect();

        // For padding rows, auth_hash should remain unchanged
        for i in 0..8 {
            let auth_hash_old_field = auth_hash_old[i].clone();
            let auth_hash_new_field = auth_hash_new[i].clone();
            let auth_hash_diff = auth_hash_new_field - auth_hash_old_field;
            when_transition.assert_zero(is_padding.clone() * auth_hash_diff);
        }

        // Note: sender_pubkey is extracted from public values (indices 16-23) above and is
        // committed in the proof via public values. The actual cryptographic verification
        // that auth_hash corresponds to sender_pubkey is done outside the ZKP by the receiver.
        // The pubkey is available here for use in constraints if needed in the future.

        self.eval_poseidon2_air(builder);
    }
}
