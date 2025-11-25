//! Wallet transition Algebraic Intermediate Representation (AIR)
//! for proving wallet state transitions
//!
//! This module defines the AIR for proving wallet state transitions.
//! The AIR verifies that wallet state transitions are valid by
//! enforcing accumulator chain integrity, commitment correctness,
//! and state consistency using Poseidon2 hashing.

use p3_air::{Air, AirBuilderWithPublicValues, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;

use crate::zkp::poseidon2_common::{
    eval_poseidon2_air_multiple_permutations, poseidon2_air_num_cols, poseidon2_output_offset,
    POSEIDON2_OUTPUT_SIZE,
};
use crate::zkp::wallet::transition_poseidon2_air::column_offsets::{
    new_accumulator_poseidon2_start, total_cols, wallet_init_poseidon2_start,
    ACCUMULATOR_PERMUTATIONS, CHANNEL_COMMITMENT_END, CHANNEL_COMMITMENT_START, CHANNEL_ID_END,
    CHANNEL_ID_START, IS_IN_NEW_COL, IS_IN_OLD_COL, NEXT_NEW_ACC_END, NEXT_NEW_ACC_START,
    NEXT_OLD_ACC_END, NEXT_OLD_ACC_START, OLD_ACCUMULATOR_POSEIDON2_START, PREV_NEW_ACC_END,
    PREV_NEW_ACC_START, PREV_OLD_ACC_END, PREV_OLD_ACC_START, WALLET_INIT_PERMUTATIONS,
};
use crate::zkp::wallet::transition_poseidon2_air::{
    create_poseidon2_air, WalletTransitionPoseidon2Air,
};

// Public value indices for wallet transition proofs
// Public values layout: 0-7: wallet_id, 8-15: initial_commitment, 16-23: final_commitment
const PUBLIC_INITIAL_COMMITMENT_START: usize = POSEIDON2_OUTPUT_SIZE;
const PUBLIC_FINAL_COMMITMENT_START: usize = POSEIDON2_OUTPUT_SIZE * 2;

fn num_cols() -> usize { total_cols() }

pub(super) struct WalletTransitionAir {
    poseidon2_air: WalletTransitionPoseidon2Air,
}

impl WalletTransitionAir {
    /// Create a new wallet transition AIR
    pub(super) fn new() -> Self { Self { poseidon2_air: create_poseidon2_air() } }

    /// Evaluate Poseidon2 AIR constraints for wallet_id hash computation.
    ///
    /// This function evaluates the Poseidon2 AIR constraints for the wallet_id
    /// initialization trace (2 permutations). It ensures the wallet_id hash trace
    /// is correctly computed according to the Poseidon2 specification.
    ///
    /// **Note:** This function only evaluates Poseidon2 AIR constraints. It does
    /// NOT enforce accumulator initialization constraints. Those are handled
    /// separately in `eval()` because the initial accumulator value depends on
    /// whether the wallet is empty (wallet_id hash) or has existing channels
    /// (old wallet's full commitment).
    ///
    /// # Arguments
    /// * `builder`: The air builder
    fn eval_wallet_id_poseidon2_air<AB: AirBuilderWithPublicValues>(&self, builder: &mut AB)
    where
        AB::F: PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
        AB::Expr: From<AB::F>,
        for<'a> WalletTransitionPoseidon2Air:
            p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
    {
        // Evaluate Poseidon2 AIR for wallet_id initialization
        let wallet_init_offset = wallet_init_poseidon2_start();
        eval_poseidon2_air_multiple_permutations(
            &self.poseidon2_air,
            builder,
            wallet_init_offset,
            WALLET_INIT_PERMUTATIONS,
        );
    }

    /// Verify final accumulator matches wallet commitment on the last row
    fn verify_wallet_commitment<AB: AirBuilderWithPublicValues>(
        &self,
        builder: &mut AB,
        final_accumulator: &[AB::Expr],
        commitment_public: &[AB::Expr],
    ) where
        AB::F: PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
    {
        let is_last_row = builder.is_last_row();

        // Only enforce constraint on last row: is_last_row * (acc - commitment) == 0
        // For non-last rows, this constraint is trivially satisfied (multiplied by 0)
        for (acc, commitment) in final_accumulator.iter().zip(commitment_public.iter()) {
            let diff = acc.clone() - commitment.clone();
            builder.assert_zero(is_last_row.clone() * diff);
        }
    }
}

/// Implements the BaseAir trait for the wallet transition AIR
impl<F: PrimeField64> BaseAir<F> for WalletTransitionAir {
    fn width(&self) -> usize { num_cols() }
}

/// Implements the Air trait for the wallet transition AIR
impl<AB: AirBuilderWithPublicValues> Air<AB> for WalletTransitionAir
where
    AB::F: PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
    AB::Expr: From<AB::F>,
    // Constrain AB::F to be BabyBear (MontyField31<BabyBearParameters>)
    // This is required for Poseidon2Air evaluation. We express this by requiring
    // that WalletTransitionPoseidon2Air implements Air for the sliced builder, which only
    // works when AB::F == Val (BabyBear).
    for<'a> WalletTransitionPoseidon2Air:
        p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
{
    /// Evaluate the wallet transition AIR
    ///
    /// # Arguments
    ///
    /// * `builder`: The air builder
    ///
    /// # Panics
    ///
    /// Panics if the trace has no rows.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        // Extract public commitment from public values (indices 8-15 for initial, 16-23 for final)
        // early due to borrow checker: builder.public_values() returns a reference, which we
        // can't hold while using builder mutably in the loop below. Converting to owned Expr
        // values here avoids the conflict.
        let public_values = builder.public_values();
        let initial_commitment_public: Vec<AB::Expr> = (PUBLIC_INITIAL_COMMITMENT_START
            ..PUBLIC_INITIAL_COMMITMENT_START + POSEIDON2_OUTPUT_SIZE)
            .map(|i| public_values[i].into())
            .collect();
        let final_commitment_public: Vec<AB::Expr> = (PUBLIC_FINAL_COMMITMENT_START
            ..PUBLIC_FINAL_COMMITMENT_START + POSEIDON2_OUTPUT_SIZE)
            .map(|i| public_values[i].into())
            .collect();

        let poseidon2_cols = poseidon2_air_num_cols();
        let output_offset = poseidon2_output_offset();

        let local = main.row_slice(0).expect("Trace must have current row");
        let next_slice = if main.height() > 1 {
            main.row_slice(1).expect("Trace must have next row if height > 1")
        } else {
            main.row_slice(0).expect("Trace must have current row")
        };

        // Extract boolean selectors: flags indicating if channel exists in old/new wallet
        let is_in_old: AB::Expr = local[IS_IN_OLD_COL].into();
        let is_in_new: AB::Expr = local[IS_IN_NEW_COL].into();

        // Enforce booleanity: is_in_old * (is_in_old - 1) == 0 ensures is_in_old ∈ {0, 1}
        builder.assert_zero(is_in_old.clone() * (is_in_old.clone() - AB::Expr::ONE));
        builder.assert_zero(is_in_new.clone() * (is_in_new.clone() - AB::Expr::ONE));

        // Extract values from current row
        let prev_old_acc: Vec<AB::Expr> =
            (PREV_OLD_ACC_START..PREV_OLD_ACC_END).map(|i| local[i].into()).collect();
        let prev_new_acc: Vec<AB::Expr> =
            (PREV_NEW_ACC_START..PREV_NEW_ACC_END).map(|i| local[i].into()).collect();
        let channel_id: Vec<AB::Expr> =
            (CHANNEL_ID_START..CHANNEL_ID_END).map(|i| local[i].into()).collect();
        let channel_commitment: Vec<AB::Expr> =
            (CHANNEL_COMMITMENT_START..CHANNEL_COMMITMENT_END).map(|i| local[i].into()).collect();
        let next_old_acc: Vec<AB::Expr> =
            (NEXT_OLD_ACC_START..NEXT_OLD_ACC_END).map(|i| local[i].into()).collect();
        let next_new_acc: Vec<AB::Expr> =
            (NEXT_NEW_ACC_START..NEXT_NEW_ACC_END).map(|i| local[i].into()).collect();

        // Zeroing for inactive rows (when both flags are 0)
        // This ensures inactive rows have zero channel_id and channel_commitment
        let is_inactive = (AB::Expr::ONE - is_in_old.clone()) * (AB::Expr::ONE - is_in_new.clone());
        for j in 0..POSEIDON2_OUTPUT_SIZE {
            builder.assert_zero(is_inactive.clone() * channel_id[j].clone());
            builder.assert_zero(is_inactive.clone() * channel_commitment[j].clone());
        }

        // Evaluate Poseidon2 AIR for old accumulator computation (if channel is in old wallet)
        let local_for_poseidon = main.row_slice(0).expect("Trace must have current row");
        let old_accumulator_offset = OLD_ACCUMULATOR_POSEIDON2_START;
        eval_poseidon2_air_multiple_permutations(
            &self.poseidon2_air,
            builder,
            old_accumulator_offset,
            ACCUMULATOR_PERMUTATIONS,
        );

        // Evaluate Poseidon2 AIR for new accumulator computation (if channel is in new wallet)
        let new_accumulator_offset = new_accumulator_poseidon2_start();
        eval_poseidon2_air_multiple_permutations(
            &self.poseidon2_air,
            builder,
            new_accumulator_offset,
            ACCUMULATOR_PERMUTATIONS,
        );

        // Extract computed new accumulator from last permutation output
        // This ensures trace generation matches the hash computation implementation
        let last_new_perm_offset =
            new_accumulator_offset + (ACCUMULATOR_PERMUTATIONS - 1) * poseidon2_cols;
        let computed_new_accumulator: Vec<AB::Expr> = (0..POSEIDON2_OUTPUT_SIZE)
            .map(|j| {
                let col_idx = last_new_perm_offset + output_offset + j;
                local_for_poseidon[col_idx].into()
            })
            .collect();

        // Accumulator transition:
        // next_old_acc == prev_old_acc
        // next_new_acc == is_in_new * computed_new_acc + (1 - is_in_new) * prev_new_acc
        for j in 0..POSEIDON2_OUTPUT_SIZE {
            builder.assert_zero(next_old_acc[j].clone() - prev_old_acc[j].clone());

            let new_active_part: AB::Expr = is_in_new.clone() * computed_new_accumulator[j].clone();
            let new_inactive_part: AB::Expr =
                (AB::Expr::ONE - is_in_new.clone()) * prev_new_acc[j].clone();
            let new_comb = new_active_part + new_inactive_part;
            builder.assert_zero(next_new_acc[j].clone() - new_comb);
        }

        // Accumulator continuity:
        // next_new_acc[current] == prev_new_acc[next] on transition rows
        if main.height() > 1 {
            let is_transition = builder.is_transition();
            let _next_prev_old_acc: Vec<AB::Expr> =
                (PREV_OLD_ACC_START..PREV_OLD_ACC_END).map(|i| next_slice[i].into()).collect();
            let next_prev_new_acc: Vec<AB::Expr> =
                (PREV_NEW_ACC_START..PREV_NEW_ACC_END).map(|i| next_slice[i].into()).collect();

            for j in 0..POSEIDON2_OUTPUT_SIZE {
                let diff_new = next_new_acc[j].clone() - next_prev_new_acc[j].clone();
                builder.assert_zero(is_transition.clone() * diff_new);
            }
        }

        self.eval_wallet_id_poseidon2_air(builder);

        let local = main.row_slice(0).expect("Trace must have current row");
        let is_first_row = builder.is_first_row();

        let wallet_init_offset = wallet_init_poseidon2_start();
        let last_wallet_init_perm_offset =
            wallet_init_offset + (WALLET_INIT_PERMUTATIONS - 1) * poseidon2_cols;
        let computed_wallet_init: Vec<AB::Expr> = (0..POSEIDON2_OUTPUT_SIZE)
            .map(|j| {
                let col_idx = last_wallet_init_perm_offset + output_offset + j;
                local[col_idx].into()
            })
            .collect();

        for j in 0..POSEIDON2_OUTPUT_SIZE {
            let diff_old = prev_old_acc[j].clone() - initial_commitment_public[j].clone();
            builder.assert_zero(is_first_row.clone() * diff_old);

            let diff_old_0 = prev_old_acc[0].clone() - initial_commitment_public[0].clone();
            let selector = is_first_row.clone() * (AB::Expr::ONE - diff_old_0.clone() * diff_old_0);
            let diff_new = prev_new_acc[j].clone() - computed_wallet_init[j].clone();
            builder.assert_zero(selector.clone() * diff_new);
        }

        // Verify final commitment matches public value on last row
        let final_new_accumulator: Vec<AB::Expr> =
            (NEXT_NEW_ACC_START..NEXT_NEW_ACC_END).map(|i| local[i].into()).collect();
        self.verify_wallet_commitment(builder, &final_new_accumulator, &final_commitment_public);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use p3_air::BaseAir;

    use super::WalletTransitionAir;
    use crate::wallet::commitment::compute_commitment_from_channels;
    use crate::wallet::operation::WalletTransition;
    use crate::wallet::state::WalletState;
    use crate::wallet::transition::apply_operation;

    /// Helper function to create a simple test wallet
    fn create_test_wallet(wallet_id: u8, num_channels: usize) -> WalletState {
        let mut channels = BTreeMap::new();
        for i in 0..num_channels {
            let mut channel_id = [0u8; 32];
            channel_id[31] = i as u8 + 1;

            let mut channel_commitment = [0u8; 32];
            channel_commitment[31] = (i as u8 + 10) * 2;

            channels.insert(channel_id, channel_commitment);
        }
        WalletState::from_channels([wallet_id; 32], channels)
    }

    #[test]
    fn test_eval() {
        use p3_matrix::Matrix;

        use crate::types::{MAX_CHANNELS, WALLET_INIT_DOMAIN};
        use crate::zkp::poseidon2_hash_fixed;
        use crate::zkp::types::{create_config, Val};
        use crate::zkp::wallet::public_inputs::WalletTransitionPublicInputs;
        use crate::zkp::wallet::transition_trace::build_transition_trace;
        use crate::zkp::wallet::{prove_wallet_transition, verify_wallet_transition};

        // Test AIR creation and basic properties
        let air = WalletTransitionAir::new();
        let width = <WalletTransitionAir as BaseAir<Val>>::width(&air);
        assert!(width >= 24);

        let config = create_config().expect("Should create config");

        // Test trace building
        let old_wallet = create_test_wallet(1, 1);
        let channel_id = [10u8; 32];
        let channel_commitment = [20u8; 32];
        let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };
        let old_wallet_copy = WalletState {
            id: old_wallet.id,
            channels: old_wallet.channels.clone(),
            commitment: old_wallet.commitment,
        };
        let new_wallet =
            apply_operation(old_wallet_copy, &transition).expect("Should apply transition");
        let trace = build_transition_trace(&old_wallet, &new_wallet).expect("Should build trace");
        assert_eq!(trace.width(), width);
        assert!(trace.height() > 0);

        // Test empty wallet commitment
        let empty_wallet = create_test_wallet(3, 0);
        let empty_commitment =
            compute_commitment_from_channels(empty_wallet.id, &empty_wallet.channels)
                .expect("should compute commitment");
        let expected = poseidon2_hash_fixed(&[WALLET_INIT_DOMAIN, &empty_wallet.id[..]]);
        assert_eq!(empty_commitment, expected);

        // Test prove/verify: insert into empty wallet
        let old_wallet = create_test_wallet(1, 0);
        let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };
        let old_wallet_copy = WalletState {
            id: old_wallet.id,
            channels: old_wallet.channels.clone(),
            commitment: old_wallet.commitment,
        };
        let new_wallet =
            apply_operation(old_wallet_copy, &transition).expect("Should apply transition");
        let proof = prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&transition])
            .expect("Should generate proof");
        let old_commitment = compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
            .expect("should compute commitment");
        let new_commitment = compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
            .expect("should compute commitment");
        let public_inputs = WalletTransitionPublicInputs {
            wallet_id: old_wallet.id,
            initial_wallet_commitment: old_commitment,
            final_wallet_commitment: new_commitment,
        };
        verify_wallet_transition(&config, &public_inputs, &proof)
            .expect("Should verify valid proof");

        // Test prove/verify: remove channel
        let old_wallet = create_test_wallet(1, 1);
        let mut remove_channel_id = [0u8; 32];
        remove_channel_id[31] = 1;
        let transition = WalletTransition::RemoveChannel { channel_id: remove_channel_id };
        let old_wallet_copy = WalletState {
            id: old_wallet.id,
            channels: old_wallet.channels.clone(),
            commitment: old_wallet.commitment,
        };
        let new_wallet =
            apply_operation(old_wallet_copy, &transition).expect("Should apply transition");
        let proof = prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&transition])
            .expect("Should generate proof");
        let old_commitment = compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
            .expect("should compute commitment");
        let new_commitment = compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
            .expect("should compute commitment");
        let public_inputs = WalletTransitionPublicInputs {
            wallet_id: old_wallet.id,
            initial_wallet_commitment: old_commitment,
            final_wallet_commitment: new_commitment,
        };
        verify_wallet_transition(&config, &public_inputs, &proof)
            .expect("Should verify valid proof");

        // Test prove/verify: multiple channels
        let old_wallet = create_test_wallet(2, 2);
        let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };
        let old_wallet_copy = WalletState {
            id: old_wallet.id,
            channels: old_wallet.channels.clone(),
            commitment: old_wallet.commitment,
        };
        let new_wallet =
            apply_operation(old_wallet_copy, &transition).expect("Should apply transition");
        let proof = prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&transition])
            .expect("Should generate proof");
        let old_commitment = compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
            .expect("should compute commitment");
        let new_commitment = compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
            .expect("should compute commitment");
        let public_inputs = WalletTransitionPublicInputs {
            wallet_id: old_wallet.id,
            initial_wallet_commitment: old_commitment,
            final_wallet_commitment: new_commitment,
        };
        verify_wallet_transition(&config, &public_inputs, &proof)
            .expect("Should verify valid proof");

        // Test prove/verify: max channels
        let old_wallet = create_test_wallet(4, MAX_CHANNELS - 1);
        let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };
        let old_wallet_copy = WalletState {
            id: old_wallet.id,
            channels: old_wallet.channels.clone(),
            commitment: old_wallet.commitment,
        };
        let new_wallet =
            apply_operation(old_wallet_copy, &transition).expect("Should apply transition");
        let proof = prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&transition])
            .expect("Should generate proof");
        let old_commitment = compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
            .expect("should compute commitment");
        let new_commitment = compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
            .expect("should compute commitment");
        let public_inputs = WalletTransitionPublicInputs {
            wallet_id: old_wallet.id,
            initial_wallet_commitment: old_commitment,
            final_wallet_commitment: new_commitment,
        };
        verify_wallet_transition(&config, &public_inputs, &proof)
            .expect("Should verify valid proof");

        // Test verification failures
        let old_wallet = create_test_wallet(1, 1);
        let transition = WalletTransition::InsertChannel { channel_id, channel_commitment };
        let old_wallet_copy = WalletState {
            id: old_wallet.id,
            channels: old_wallet.channels.clone(),
            commitment: old_wallet.commitment,
        };
        let new_wallet =
            apply_operation(old_wallet_copy, &transition).expect("Should apply transition");
        let proof = prove_wallet_transition(&config, &[&old_wallet, &new_wallet], &[&transition])
            .expect("Should generate proof");

        // Wrong wallet_id
        let mut wrong_wallet_id = old_wallet.id;
        wrong_wallet_id[0] = wrong_wallet_id[0].wrapping_add(1);
        let old_commitment = compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
            .expect("should compute commitment");
        let new_commitment = compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
            .expect("should compute commitment");
        let public_inputs = WalletTransitionPublicInputs {
            wallet_id: wrong_wallet_id,
            initial_wallet_commitment: old_commitment,
            final_wallet_commitment: new_commitment,
        };
        assert!(verify_wallet_transition(&config, &public_inputs, &proof).is_err());

        // Wrong old commitment
        let mut wrong_old_commitment =
            compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
                .expect("should compute commitment");
        wrong_old_commitment[0] = wrong_old_commitment[0].wrapping_add(1);
        let new_commitment = compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
            .expect("should compute commitment");
        let public_inputs = WalletTransitionPublicInputs {
            wallet_id: old_wallet.id,
            initial_wallet_commitment: wrong_old_commitment,
            final_wallet_commitment: new_commitment,
        };
        assert!(verify_wallet_transition(&config, &public_inputs, &proof).is_err());

        // Wrong new commitment
        let mut wrong_new_commitment =
            compute_commitment_from_channels(new_wallet.id, &new_wallet.channels)
                .expect("should compute commitment");
        wrong_new_commitment[0] = wrong_new_commitment[0].wrapping_add(1);
        let old_commitment = compute_commitment_from_channels(old_wallet.id, &old_wallet.channels)
            .expect("should compute commitment");
        let public_inputs = WalletTransitionPublicInputs {
            wallet_id: old_wallet.id,
            initial_wallet_commitment: old_commitment,
            final_wallet_commitment: wrong_new_commitment,
        };
        assert!(verify_wallet_transition(&config, &public_inputs, &proof).is_err());
    }
}
