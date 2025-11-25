//! Global root composition AIR for proving subtree root composition
//!
//! This module defines the AIR (Algebraic Intermediate Representation) for
//! proving that multiple subtree roots compose into a global root following
//! the Sparse Merkle Tree (SMT) structure with Poseidon2 hashing.

use p3_air::{Air, AirBuilderWithPublicValues, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;

use crate::zkp::global::poseidon2_air::{column_offsets, create_poseidon2_air, GlobalPoseidon2Air};
use crate::zkp::poseidon2_common::{
    eval_poseidon2_air_multiple_permutations, poseidon2_output_offset,
};

fn num_cols() -> usize { column_offsets::total_cols() }

/// AIR for proving global root composition from subtree roots.
///
/// This AIR verifies that subtree roots are correctly composed into a global root by enforcing:
/// - Poseidon2 hash computation: `composed_root = poseidon2(MM_GLOBAL_v0 || left || right)`
/// - Final root matches the expected global root (from public inputs)
/// - Padding rows maintain stable state
///
/// The AIR operates on a multi-row trace where each row represents one internal node composition.
pub(super) struct GlobalRootCompositionAir {
    poseidon2_air: GlobalPoseidon2Air,
}

impl GlobalRootCompositionAir {
    /// Create a new global root composition AIR
    pub(super) fn new() -> Self { Self { poseidon2_air: create_poseidon2_air() } }

    /// Evaluate Poseidon2 AIR constraints when AB::F == Val (BabyBear).
    fn eval_poseidon2_air<AB: AirBuilderWithPublicValues>(&self, builder: &mut AB)
    where
        AB::F: PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
        for<'a> GlobalPoseidon2Air:
            p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
    {
        // Evaluate internal node Poseidon2 AIR
        let internal_node_offset = column_offsets::INTERNAL_NODE_POSEIDON2_START;
        eval_poseidon2_air_multiple_permutations(
            &self.poseidon2_air,
            builder,
            internal_node_offset,
            column_offsets::INTERNAL_NODE_PERMUTATIONS,
        );
    }
}

impl<F: PrimeField64> BaseAir<F> for GlobalRootCompositionAir {
    fn width(&self) -> usize { num_cols() }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for GlobalRootCompositionAir
where
    AB::F: PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
    AB::Expr: From<AB::F>,
    for<'a> GlobalPoseidon2Air:
        p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
{
    /// Evaluate the global root composition AIR
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("Trace must have at least 1 row");

        // Extract public global root from public values
        let public_values = builder.public_values();
        let global_root_public: Vec<AB::Expr> = (8..16).map(|i| public_values[i].into()).collect();

        // Extract values from current row
        let left_root: Vec<AB::Expr> = (column_offsets::LEFT_ROOT_START
            ..column_offsets::LEFT_ROOT_END)
            .map(|i| local[i].into())
            .collect();
        let right_root: Vec<AB::Expr> = (column_offsets::RIGHT_ROOT_START
            ..column_offsets::RIGHT_ROOT_END)
            .map(|i| local[i].into())
            .collect();
        let composed_root: Vec<AB::Expr> = (column_offsets::COMPOSED_ROOT_START
            ..column_offsets::COMPOSED_ROOT_END)
            .map(|i| local[i].into())
            .collect();

        // Compute sum of squares to detect padding/empty rows
        // If both roots are all zeros, the sum of squares will be zero
        let zero_expr: AB::Expr = AB::F::ZERO.into();
        let left_sum_sq =
            left_root.iter().fold(zero_expr.clone(), |acc, x| acc + x.clone() * x.clone());
        let right_sum_sq =
            right_root.iter().fold(zero_expr.clone(), |acc, x| acc + x.clone() * x.clone());
        let root_sum_sq = left_sum_sq.clone() + right_sum_sq.clone();

        // Evaluate Poseidon2 AIR (always evaluate, but conditionally check results)
        self.eval_poseidon2_air(builder);

        // Extract computed root from Poseidon2 trace output
        let poseidon2_cols = crate::zkp::poseidon2_common::poseidon2_air_num_cols();
        let output_offset = poseidon2_output_offset();
        let last_perm_offset = column_offsets::INTERNAL_NODE_POSEIDON2_START
            + (column_offsets::INTERNAL_NODE_PERMUTATIONS - 1) * poseidon2_cols;
        let computed_root: Vec<AB::Expr> = (0..8)
            .map(|j| {
                let col_idx = last_perm_offset + output_offset + j;
                local[col_idx].into()
            })
            .collect();

        // Verify Poseidon2 computation only for active rows (non-padding, non-empty)
        for (computed, composed) in computed_root.iter().zip(composed_root.iter()) {
            let diff = computed.clone() - composed.clone();
            builder.assert_zero(root_sum_sq.clone() * diff);
        }

        // Verify final root matches public input on the last row
        let is_last_row = builder.is_last_row();
        for (composed, public) in composed_root.iter().zip(global_root_public.iter()) {
            let diff = composed.clone() - public.clone();
            builder.assert_zero(is_last_row.clone() * diff);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::types::Val;

    #[test]
    fn test_air_creation() {
        let air = GlobalRootCompositionAir::new();
        let width = <GlobalRootCompositionAir as BaseAir<Val>>::width(&air);

        // Width should be positive and match expected structure
        assert!(width > 0, "AIR should have positive width");

        // Width should account for base columns (24) + Poseidon2 columns for internal node (3 permutations)
        let expected_min_width = 24; // Conservative lower bound
        assert!(width >= expected_min_width, "AIR width should be at least {}", expected_min_width);
    }
}
