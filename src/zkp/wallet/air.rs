//! Wallet commitment AIR for proving wallet commitment aggregation
//!
//! This module defines the AIR (Algebraic Intermediate Representation) for
//! proving that wallet commitments correctly aggregate channel commitments.

use p3_air::{Air, AirBuilderWithPublicValues, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;

use crate::zkp::poseidon2_common::{
    eval_poseidon2_air_multiple_permutations, poseidon2_air_num_cols, poseidon2_output_offset,
};
use crate::zkp::wallet::poseidon2_air::{column_offsets, create_poseidon2_air, WalletPoseidon2Air};

fn num_cols() -> usize { column_offsets::total_cols() }

pub(super) struct WalletCommitmentAir {
    poseidon2_air: WalletPoseidon2Air,
}

impl WalletCommitmentAir {
    /// Create a new wallet commitment AIR
    pub(super) fn new() -> Self { Self { poseidon2_air: create_poseidon2_air() } }

    /// Verify wallet_id initialization trace is computed correctly.
    ///
    /// This function evaluates the Poseidon2 AIR for wallet_id hashing to ensure
    /// the wallet_id is correctly hashed. Enforces that prev_acc equals
    /// Poseidon2([WALLET_INIT_DOMAIN, wallet_id]) on the first row.
    ///
    /// # Arguments
    /// * `builder`: The air builder
    /// * `prev_acc`: Previous accumulator values
    fn verify_wallet_id<AB: AirBuilderWithPublicValues>(
        &self,
        builder: &mut AB,
        prev_acc: &[AB::Expr],
    ) where
        AB::F: PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
        AB::Expr: From<AB::F>,
        for<'a> WalletPoseidon2Air:
            p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
    {
        let is_first_row = builder.is_first_row();
        let poseidon2_cols = poseidon2_air_num_cols();
        let output_offset = poseidon2_output_offset();

        // Evaluate Poseidon2 AIR for wallet_id initialization (2 permutations)
        let wallet_init_offset = column_offsets::wallet_init_poseidon2_start();
        const WALLET_INIT_PERMUTATIONS: usize = 2;
        eval_poseidon2_air_multiple_permutations(
            &self.poseidon2_air,
            builder,
            wallet_init_offset,
            WALLET_INIT_PERMUTATIONS,
        );

        // Extract computed wallet_id hash from last Poseidon2 trace output
        // This ensures trace generation matches the hash computation implementation
        let main = builder.main();
        let local_for_poseidon = main.row_slice(0).expect("Trace must have current row");
        let last_perm_offset = wallet_init_offset + (WALLET_INIT_PERMUTATIONS - 1) * poseidon2_cols;
        let computed_wallet_init: Vec<AB::Expr> = (0..8)
            .map(|j| {
                let col_idx = last_perm_offset + output_offset + j;
                local_for_poseidon[col_idx].into()
            })
            .collect();

        // Only enforce constraint on first row: is_first_row * (prev_acc - computed_wallet_init) == 0
        // For non-first rows, this constraint is trivially satisfied (multiplied by 0)
        for j in 0..8 {
            let diff = prev_acc[j].clone() - computed_wallet_init[j].clone();
            builder.assert_zero(is_first_row.clone() * diff);
        }
    }

    /// Verify final accumulator matches wallet commitment on the last row
    fn verify_wallet_commitment<AB: AirBuilderWithPublicValues>(
        &self,
        builder: &mut AB,
        final_accumulator: &[AB::Expr],
        wallet_commitment_public: &[AB::Expr],
    ) where
        AB::F: PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
    {
        let is_last_row = builder.is_last_row();

        // Only enforce constraint on last row: is_last_row * (acc - commitment) == 0
        // For non-last rows, this constraint is trivially satisfied (multiplied by 0)
        for (acc, commitment) in final_accumulator.iter().zip(wallet_commitment_public.iter()) {
            let diff = acc.clone() - commitment.clone();
            builder.assert_zero(is_last_row.clone() * diff);
        }
    }
}

/// Implements the BaseAir trait for the wallet commitment AIR
impl<F: PrimeField64> BaseAir<F> for WalletCommitmentAir {
    fn width(&self) -> usize { num_cols() }
}

/// Implements the Air trait for the wallet commitment AIR
impl<AB: AirBuilderWithPublicValues> Air<AB> for WalletCommitmentAir
where
    AB::F: PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
    AB::Expr: From<AB::F>,
    for<'a> WalletPoseidon2Air:
        p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
{
    /// Evaluate the wallet commitment AIR
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        // Extract wallet_commitment from public values (indices 8-15) early due to borrow checker:
        // builder.public_values() returns a reference, which we can't hold while using builder mutably
        // in the loop below. Converting to owned Expr values here avoids the conflict.
        // This ensures the constants match what will be used in trace generation AND hash computation
        let public_values = builder.public_values();
        let wallet_commitment_public: Vec<AB::Expr> =
            (8..16).map(|i| public_values[i].into()).collect();

        let poseidon2_cols = poseidon2_air_num_cols();
        let output_offset = poseidon2_output_offset();
        const ACCUMULATOR_PERMUTATIONS: usize = 3;

        // - row_slice(0) = current row being evaluated
        // - row_slice(1) = next row (if it exists, otherwise same as row 0 for padding)
        let local = main.row_slice(0).expect("Trace must have current row");
        let next_slice = if main.height() > 1 {
            main.row_slice(1).expect("Trace must have next row if height > 1")
        } else {
            // Only one row: reuse row 0 for padding (no next row exists)
            main.row_slice(0).expect("Trace must have current row")
        };

        // Extract is_active boolean selector
        let is_active: AB::Expr = local[column_offsets::IS_ACTIVE_COL].into();

        // Enforce booleanity: is_active * (is_active - 1) == 0
        builder.assert_zero(is_active.clone() * (is_active.clone() - AB::Expr::ONE));

        // Extract values from current row
        let prev_acc: Vec<AB::Expr> = (column_offsets::PREV_ACC_START
            ..column_offsets::PREV_ACC_END)
            .map(|i| local[i].into())
            .collect();
        let channel_id: Vec<AB::Expr> = (column_offsets::CHANNEL_ID_START
            ..column_offsets::CHANNEL_ID_END)
            .map(|i| local[i].into())
            .collect();
        let channel_commitment: Vec<AB::Expr> = (column_offsets::CHANNEL_COMMITMENT_START
            ..column_offsets::CHANNEL_COMMITMENT_END)
            .map(|i| local[i].into())
            .collect();
        let next_acc: Vec<AB::Expr> = (column_offsets::NEXT_ACC_START
            ..column_offsets::NEXT_ACC_END)
            .map(|i| local[i].into())
            .collect();

        // Zeroing for inactive rows (when is_active is 0)
        let is_inactive = AB::Expr::ONE - is_active.clone();
        for j in 0..8 {
            builder.assert_zero(is_inactive.clone() * channel_id[j].clone());
            builder.assert_zero(is_inactive.clone() * channel_commitment[j].clone());
        }

        // Evaluate Poseidon2 AIR for accumulator computation (if channel is active)
        let local_for_poseidon = main.row_slice(0).expect("Trace must have current row");
        let accumulator_offset = column_offsets::ACCUMULATOR_POSEIDON2_START;
        eval_poseidon2_air_multiple_permutations(
            &self.poseidon2_air,
            builder,
            accumulator_offset,
            ACCUMULATOR_PERMUTATIONS,
        );

        // Extract computed accumulator from last permutation output
        // This ensures trace generation matches the hash computation implementation
        let last_perm_offset = accumulator_offset + (ACCUMULATOR_PERMUTATIONS - 1) * poseidon2_cols;
        let computed_accumulator: Vec<AB::Expr> = (0..8)
            .map(|j| {
                let col_idx = last_perm_offset + output_offset + j;
                local_for_poseidon[col_idx].into()
            })
            .collect();

        // Accumulator transition: next_acc[j] == is_active * computed_acc[j] + (1 - is_active) * prev_acc[j]
        // This verifies that within each row, next_acc is computed correctly from prev_acc and channel data
        for j in 0..8 {
            let active_part: AB::Expr = is_active.clone() * computed_accumulator[j].clone();
            let inactive_part: AB::Expr = is_inactive.clone() * prev_acc[j].clone();
            let comb = active_part + inactive_part;
            builder.assert_zero(next_acc[j].clone() - comb);
        }

        // Accumulator continuity: next_acc[current] == prev_acc[next] on transition rows
        if main.height() > 1 {
            let is_transition = builder.is_transition();
            let next_prev_acc: Vec<AB::Expr> = (column_offsets::PREV_ACC_START
                ..column_offsets::PREV_ACC_END)
                .map(|i| next_slice[i].into())
                .collect();

            for j in 0..8 {
                let diff = next_acc[j].clone() - next_prev_acc[j].clone();
                builder.assert_zero(is_transition.clone() * diff);
            }
        }

        self.verify_wallet_id(builder, &prev_acc);

        let local = main.row_slice(0).expect("Trace must have current row");
        let final_accumulator: Vec<AB::Expr> = (column_offsets::NEXT_ACC_START
            ..column_offsets::NEXT_ACC_END)
            .map(|i| local[i].into())
            .collect();

        self.verify_wallet_commitment(builder, &final_accumulator, &wallet_commitment_public);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use p3_air::BaseAir;

    use super::WalletCommitmentAir;
    use crate::wallet::commitment::compute_commitment_from_channels;
    use crate::wallet::state::WalletState;

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
    fn test_wallet_air_empty_wallet_commitment() {
        let wallet = create_test_wallet(3, 0);
        let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
            .expect("should compute commitment");

        // Empty wallet commitment is hash(wallet_id), not zero
        use crate::types::WALLET_INIT_DOMAIN;
        use crate::zkp::poseidon2_hash_fixed;
        let expected = poseidon2_hash_fixed(&[WALLET_INIT_DOMAIN, &wallet.id[..]]);
        assert_eq!(wallet_commitment, expected);
    }

    #[test]
    fn test_wallet_air_creation() {
        use crate::zkp::types::Val;

        let air = WalletCommitmentAir::new();
        let width = <WalletCommitmentAir as BaseAir<Val>>::width(&air);

        // Width should be positive and match expected structure
        assert!(width > 0);

        // Width should account for base columns (33) + Poseidon2 columns for accumulator (3 permutations)
        // + Poseidon2 columns for wallet_id initialization (2 permutations)
        // The actual width is much larger than 24 due to Poseidon2 trace columns
        let expected_min_width = 24; // Conservative lower bound
        assert!(width >= expected_min_width);
    }

    #[test]
    fn test_wallet_air_trace_building() {
        use p3_matrix::Matrix;

        use crate::zkp::types::Val;
        use crate::zkp::wallet::trace::build_wallet_trace;

        let wallet = create_test_wallet(1, 2);
        let trace = build_wallet_trace(&wallet).expect("Should build trace");

        // Trace should have correct width matching AIR
        let air = WalletCommitmentAir::new();
        let air_width = <WalletCommitmentAir as BaseAir<Val>>::width(&air);
        assert_eq!(trace.width(), air_width);

        // Trace should have at least one row
        assert!(trace.height() > 0);
    }

    #[test]
    fn test_wallet_air_full_prove_verify_single_channel() {
        use crate::zkp::types::create_config;
        use crate::zkp::wallet::public_inputs::WalletPublicInputs;
        use crate::zkp::wallet::{prove_wallet_commitment, verify_wallet_commitment};

        let config = create_config().expect("Should create config");
        let wallet = create_test_wallet(1, 1);

        // Generate proof
        let proof = prove_wallet_commitment(&config, &wallet)
            .expect("Should generate proof for wallet with single channel");

        // Verify proof
        let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
            .expect("should compute commitment");
        let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

        verify_wallet_commitment(&config, &public_inputs, &proof)
            .expect("Should verify valid proof");
    }

    #[test]
    fn test_wallet_air_full_prove_verify_multiple_channels() {
        use crate::zkp::types::create_config;
        use crate::zkp::wallet::public_inputs::WalletPublicInputs;
        use crate::zkp::wallet::{prove_wallet_commitment, verify_wallet_commitment};

        let config = create_config().expect("Should create config");
        let wallet = create_test_wallet(2, 3);

        // Generate proof
        let proof = prove_wallet_commitment(&config, &wallet)
            .expect("Should generate proof for wallet with multiple channels");

        // Verify proof
        let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
            .expect("should compute commitment");
        let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

        verify_wallet_commitment(&config, &public_inputs, &proof)
            .expect("Should verify valid proof");
    }

    #[test]
    fn test_wallet_air_full_prove_verify_empty_wallet() {
        use crate::zkp::types::create_config;
        use crate::zkp::wallet::public_inputs::WalletPublicInputs;
        use crate::zkp::wallet::{prove_wallet_commitment, verify_wallet_commitment};

        let config = create_config().expect("Should create config");
        let wallet = create_test_wallet(3, 0);

        // Generate proof
        let proof = prove_wallet_commitment(&config, &wallet)
            .expect("Should generate proof for empty wallet");

        // Verify proof
        let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
            .expect("should compute commitment");
        // Empty wallet commitment is hash(wallet_id), not zero
        use crate::types::WALLET_INIT_DOMAIN;
        use crate::zkp::poseidon2_hash_fixed;
        let expected = poseidon2_hash_fixed(&[WALLET_INIT_DOMAIN, &wallet.id[..]]);
        assert_eq!(
            wallet_commitment, expected,
            "Empty wallet should have commitment = hash(wallet_id)"
        );

        let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

        verify_wallet_commitment(&config, &public_inputs, &proof)
            .expect("Should verify valid proof for empty wallet");
    }

    #[test]
    fn test_wallet_air_full_prove_verify_max_channels() {
        use crate::types::MAX_CHANNELS;
        use crate::zkp::types::create_config;
        use crate::zkp::wallet::public_inputs::WalletPublicInputs;
        use crate::zkp::wallet::{prove_wallet_commitment, verify_wallet_commitment};

        let config = create_config().expect("Should create config");
        let wallet = create_test_wallet(4, MAX_CHANNELS);

        // Generate proof
        let proof = prove_wallet_commitment(&config, &wallet)
            .expect("Should generate proof for wallet with MAX_CHANNELS");

        // Verify proof
        let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
            .expect("should compute commitment");
        let public_inputs = WalletPublicInputs { wallet_id: wallet.id, wallet_commitment };

        verify_wallet_commitment(&config, &public_inputs, &proof)
            .expect("Should verify valid proof for MAX_CHANNELS");
    }

    #[test]
    fn test_wallet_air_verify_fails_wrong_wallet_id() {
        use crate::zkp::types::create_config;
        use crate::zkp::wallet::public_inputs::WalletPublicInputs;
        use crate::zkp::wallet::{prove_wallet_commitment, verify_wallet_commitment};

        let config = create_config().expect("Should create config");
        let wallet = create_test_wallet(1, 1);

        // Generate proof with correct wallet
        let proof = prove_wallet_commitment(&config, &wallet).expect("Should generate proof");

        // Try to verify with wrong wallet_id
        let wallet_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
            .expect("should compute commitment");
        let mut wrong_wallet_id = wallet.id;
        wrong_wallet_id[0] = wrong_wallet_id[0].wrapping_add(1);
        let public_inputs = WalletPublicInputs { wallet_id: wrong_wallet_id, wallet_commitment };

        // Verification should fail
        assert!(
            verify_wallet_commitment(&config, &public_inputs, &proof).is_err(),
            "Verification should fail with wrong wallet_id"
        );
    }

    #[test]
    fn test_wallet_air_verify_fails_wrong_commitment() {
        use crate::zkp::types::create_config;
        use crate::zkp::wallet::public_inputs::WalletPublicInputs;
        use crate::zkp::wallet::{prove_wallet_commitment, verify_wallet_commitment};

        let config = create_config().expect("Should create config");
        let wallet = create_test_wallet(1, 1);

        // Generate proof with correct wallet
        let proof = prove_wallet_commitment(&config, &wallet).expect("Should generate proof");

        // Try to verify with wrong commitment
        let mut wrong_commitment = compute_commitment_from_channels(wallet.id, &wallet.channels)
            .expect("should compute commitment");
        wrong_commitment[0] = wrong_commitment[0].wrapping_add(1);
        let public_inputs =
            WalletPublicInputs { wallet_id: wallet.id, wallet_commitment: wrong_commitment };

        // Verification should fail
        assert!(
            verify_wallet_commitment(&config, &public_inputs, &proof).is_err(),
            "Verification should fail with wrong wallet_commitment"
        );
    }
}
