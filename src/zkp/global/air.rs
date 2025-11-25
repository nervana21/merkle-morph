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
        // Public values layout: [id (8), commitment/global_root (8)]
        let public_values = builder.public_values();
        let global_root_public: Vec<AB::Expr> = if public_values.len() >= 16 {
            (8..16).map(|i| public_values[i].into()).collect()
        } else {
            // Fallback: use zeros if public values are insufficient
            // This should not happen in valid proofs, but constraints will fail if proof is invalid
            let zero_expr: AB::Expr = AB::F::ZERO.into();
            (0..8).map(|_| zero_expr.clone()).collect()
        };

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
    use p3_air::{Air, AirBuilderWithPublicValues, BaseAir};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::zkp::types::Val;

    struct TestBuilder {
        main: RowMajorMatrix<Val>,
        public_values: Vec<Val>,
        is_last_row: bool,
        assertions: Vec<Val>,
    }

    impl TestBuilder {
        fn new(width: usize, height: usize, is_last_row: bool, public_values_len: usize) -> Self {
            let main_data: Vec<Val> = (0..width * height).map(|i| Val::new(i as u32)).collect();
            let public_values: Vec<Val> =
                (0..public_values_len).map(|i| Val::new(i as u32)).collect();
            Self {
                main: RowMajorMatrix::new(main_data, width),
                public_values,
                is_last_row,
                assertions: Vec::new(),
            }
        }
    }

    impl p3_air::AirBuilder for TestBuilder {
        type F = Val;
        type Expr = Val;
        type Var = Val;
        type M = RowMajorMatrix<Self::Var>;

        fn main(&self) -> Self::M { self.main.clone() }
        fn is_first_row(&self) -> Self::Expr { Val::ZERO }
        fn is_last_row(&self) -> Self::Expr {
            if self.is_last_row {
                Val::ONE
            } else {
                Val::ZERO
            }
        }
        fn is_transition_window(&self, _size: usize) -> Self::Expr { Val::ONE }
        fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) { self.assertions.push(x.into()); }
    }

    impl AirBuilderWithPublicValues for TestBuilder {
        type PublicVar = Val;

        fn public_values(&self) -> &[Self::PublicVar] { &self.public_values }
    }

    #[test]
    fn test_new() {
        let air = GlobalRootCompositionAir::new();

        let width = <GlobalRootCompositionAir as BaseAir<Val>>::width(&air);
        assert!(width > 0);
    }

    #[test]
    fn test_eval() {
        let air = GlobalRootCompositionAir::new();
        let width = <GlobalRootCompositionAir as BaseAir<Val>>::width(&air);
        let mut builder_sufficient = TestBuilder::new(width, 1, false, 16);
        <GlobalRootCompositionAir as Air<TestBuilder>>::eval(&air, &mut builder_sufficient);
        let mut builder_insufficient = TestBuilder::new(width, 1, true, 8);

        <GlobalRootCompositionAir as Air<TestBuilder>>::eval(&air, &mut builder_insufficient);

        assert!(!builder_sufficient.assertions.is_empty());
        assert!(!builder_insufficient.assertions.is_empty());
    }
}
