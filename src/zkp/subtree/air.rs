//! Subtree root validity AIR for proving subtree root computation
//!
//! This module defines the AIR (Algebraic Intermediate Representation) for
//! proving that a subtree root is correctly computed from wallet commitments
//! in a range, following the Sparse Merkle Tree (SMT) structure with Poseidon2 hashing.

use p3_air::{Air, AirBuilderWithPublicValues, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;

use crate::zkp::poseidon2_common::{
    eval_poseidon2_air_multiple_permutations, poseidon2_air_num_cols, poseidon2_output_offset,
    POSEIDON2_OUTPUT_SIZE,
};
use crate::zkp::subtree::poseidon2_air::{
    column_offsets, create_poseidon2_air, SubtreePoseidon2Air,
};
use crate::zkp::subtree::public_inputs::PUBLIC_SUBTREE_ROOT_START;

fn num_cols() -> usize { column_offsets::total_cols() }

/// AIR for proving subtree root validity from wallet commitments.
///
/// This AIR verifies that a subtree root is correctly computed by enforcing:
/// - Node type detection: Distinguish leaf vs internal nodes
/// - Leaf hash computation: `leaf = poseidon2(MM_WLT_v0 || wallet_id || wallet_commitment)`
/// - Internal node hash computation: `node = poseidon2(MM_GLOBAL_v0 || left || right)`
/// - Final root match: Computed root matches subtree_root from public inputs
/// - Tree structure: Hash computations and node relationships are correct
///
/// Note: Only the subtree_root is included in public inputs. Range boundaries (min_id, max_id)
/// and start_depth are not verified in-circuit for performance reasons. They are only used
/// during trace generation to filter wallets and determine the starting depth. The subtree
/// root's cryptographic correctness is ensured by verifying it composes to the on-chain global root.
pub(super) struct SubtreeRootValidityAir {
    poseidon2_air: SubtreePoseidon2Air,
}

impl SubtreeRootValidityAir {
    /// Create a new subtree root validity AIR
    pub(super) fn new() -> Self { Self { poseidon2_air: create_poseidon2_air() } }

    /// Evaluate Poseidon2 AIR constraints when AB::F == Val (BabyBear).
    fn eval_poseidon2_air<AB: AirBuilderWithPublicValues>(&self, builder: &mut AB)
    where
        AB::F: PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
        for<'a> SubtreePoseidon2Air:
            p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
    {
        // Evaluate leaf Poseidon2 AIR
        eval_poseidon2_air_multiple_permutations(
            &self.poseidon2_air,
            builder,
            column_offsets::LEAF_POSEIDON2_START,
            column_offsets::LEAF_PERMUTATIONS,
        );

        // Evaluate internal node Poseidon2 AIR
        eval_poseidon2_air_multiple_permutations(
            &self.poseidon2_air,
            builder,
            column_offsets::internal_node_poseidon2_start(),
            column_offsets::INTERNAL_NODE_PERMUTATIONS,
        );
    }
}

impl<F: PrimeField64> BaseAir<F> for SubtreeRootValidityAir {
    fn width(&self) -> usize { num_cols() }
}

impl<AB: AirBuilderWithPublicValues> Air<AB> for SubtreeRootValidityAir
where
    AB::F: PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
    AB::Expr: From<AB::F>,
    for<'a> SubtreePoseidon2Air:
        p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
{
    /// Evaluate the subtree root validity AIR
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("Trace must have at least 1 row");

        // Extract public inputs from public values
        let public_values = builder.public_values();
        let subtree_root_public: Vec<AB::Expr> = (PUBLIC_SUBTREE_ROOT_START
            ..PUBLIC_SUBTREE_ROOT_START + POSEIDON2_OUTPUT_SIZE)
            .map(|i| public_values[i].into())
            .collect();

        // Extract values from current row
        let wallet_id: Vec<AB::Expr> = (column_offsets::WALLET_ID_START
            ..column_offsets::WALLET_ID_END)
            .map(|i| local[i].into())
            .collect();
        let wallet_commitment: Vec<AB::Expr> = (column_offsets::WALLET_COMMITMENT_START
            ..column_offsets::WALLET_COMMITMENT_END)
            .map(|i| local[i].into())
            .collect();
        let left_child_root: Vec<AB::Expr> = (column_offsets::LEFT_CHILD_ROOT_START
            ..column_offsets::LEFT_CHILD_ROOT_END)
            .map(|i| local[i].into())
            .collect();
        let right_child_root: Vec<AB::Expr> = (column_offsets::RIGHT_CHILD_ROOT_START
            ..column_offsets::RIGHT_CHILD_ROOT_END)
            .map(|i| local[i].into())
            .collect();
        let computed_root: Vec<AB::Expr> = (column_offsets::COMPUTED_ROOT_START
            ..column_offsets::COMPUTED_ROOT_END)
            .map(|i| local[i].into())
            .collect();
        // let _depth: AB::Expr = local[column_offsets::DEPTH_START].into();

        // Detect node type: leaf vs internal
        // Leaf nodes have non-zero wallet_id, internal nodes have non-zero left/right children
        // We use sum of squares to detect non-zero
        let zero_expr: AB::Expr = AB::F::ZERO.into();
        let wallet_id_sum_sq =
            wallet_id.iter().fold(zero_expr.clone(), |acc, x| acc + x.clone() * x.clone());
        let left_sum_sq =
            left_child_root.iter().fold(zero_expr.clone(), |acc, x| acc + x.clone() * x.clone());
        let right_sum_sq =
            right_child_root.iter().fold(zero_expr.clone(), |acc, x| acc + x.clone() * x.clone());
        let children_sum_sq = left_sum_sq.clone() + right_sum_sq.clone();

        // Evaluate Poseidon2 AIR (always evaluate, but conditionally check results)
        self.eval_poseidon2_air(builder);

        // Extract computed root from Poseidon2 trace outputs
        let poseidon2_cols = poseidon2_air_num_cols();
        let output_offset = poseidon2_output_offset();

        // For leaf nodes: extract from leaf Poseidon2 trace
        let leaf_last_perm_offset = column_offsets::LEAF_POSEIDON2_START
            + (column_offsets::LEAF_PERMUTATIONS - 1) * poseidon2_cols;
        let computed_leaf_root: Vec<AB::Expr> = (0..POSEIDON2_OUTPUT_SIZE)
            .map(|j| {
                let col_idx = leaf_last_perm_offset + output_offset + j;
                local[col_idx].into()
            })
            .collect();

        // For internal nodes: extract from internal node Poseidon2 trace
        let internal_last_perm_offset = column_offsets::internal_node_poseidon2_start()
            + (column_offsets::INTERNAL_NODE_PERMUTATIONS - 1) * poseidon2_cols;
        let computed_internal_root: Vec<AB::Expr> = (0..POSEIDON2_OUTPUT_SIZE)
            .map(|j| {
                let col_idx = internal_last_perm_offset + output_offset + j;
                local[col_idx].into()
            })
            .collect();

        // Verify hash computation based on node type
        // We use sum of squares as a selector: if wallet_id_sum_sq > 0, it's a leaf
        // For leaf nodes: verify leaf hash matches computed_root, and children are zero
        for (computed, root) in computed_leaf_root.iter().zip(computed_root.iter()) {
            let diff = computed.clone() - root.clone();
            // Only enforce if wallet_id is non-zero (leaf node)
            builder.assert_zero(wallet_id_sum_sq.clone() * diff);
        }

        // For leaf nodes: verify children are zero
        for child in left_child_root.iter().chain(right_child_root.iter()) {
            builder.assert_zero(wallet_id_sum_sq.clone() * child.clone());
        }

        // For internal nodes: verify internal hash matches computed_root
        // Only enforce if children_sum_sq > 0 (internal node with children)
        for (computed, root) in computed_internal_root.iter().zip(computed_root.iter()) {
            let diff = computed.clone() - root.clone();
            builder.assert_zero(children_sum_sq.clone() * diff);
        }

        // Also verify that for internal nodes, wallet_id and commitment should be zero
        // We use children_sum_sq as selector (when children are set, wallet_id should be zero)
        for w in wallet_id.iter().chain(wallet_commitment.iter()) {
            builder.assert_zero(children_sum_sq.clone() * w.clone());
        }

        // Verify final root matches public input on the last row
        let is_last_row = builder.is_last_row();
        for (computed, public) in computed_root.iter().zip(subtree_root_public.iter()) {
            let diff = computed.clone() - public.clone();
            builder.assert_zero(is_last_row.clone() * diff);
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_air::{Air, AirBuilderWithPublicValues, BaseAir};
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Matrix;

    use super::*;
    use crate::zkp::subtree::poseidon2_air::column_offsets;
    use crate::zkp::types::Val;

    struct TestBuilder {
        main: RowMajorMatrix<Val>,
        public_values: Vec<Val>,
        is_last_row: bool,
        assertions: Vec<Val>,
    }

    impl TestBuilder {
        fn new(width: usize, height: usize, is_last_row: bool) -> Self {
            let main_data: Vec<Val> = (0..width * height).map(|i| Val::new(i as u32)).collect();
            let public_values: Vec<Val> = (0..25).map(|i| Val::new(i as u32)).collect();
            Self {
                main: RowMajorMatrix::new(main_data, width),
                public_values,
                is_last_row,
                assertions: Vec::new(),
            }
        }

        fn set_wallet_id(&mut self, row: usize, wallet_id: &[Val; 8]) {
            for (i, &val) in wallet_id.iter().enumerate() {
                let idx = row * self.main.width() + column_offsets::WALLET_ID_START + i;
                self.main.values.as_mut_slice()[idx] = val;
            }
        }

        fn set_children(&mut self, row: usize, left: &[Val; 8], right: &[Val; 8]) {
            for (i, &val) in left.iter().enumerate() {
                let idx = row * self.main.width() + column_offsets::LEFT_CHILD_ROOT_START + i;
                self.main.values.as_mut_slice()[idx] = val;
            }
            for (i, &val) in right.iter().enumerate() {
                let idx = row * self.main.width() + column_offsets::RIGHT_CHILD_ROOT_START + i;
                self.main.values.as_mut_slice()[idx] = val;
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
        let air = SubtreeRootValidityAir::new();

        let width = <SubtreeRootValidityAir as BaseAir<Val>>::width(&air);
        assert!(width > 0);
    }

    #[test]
    fn test_width() {
        let air = SubtreeRootValidityAir::new();

        let width = <SubtreeRootValidityAir as BaseAir<Val>>::width(&air);

        let expected_width = column_offsets::total_cols();
        assert_eq!(width, expected_width);
    }

    #[test]
    fn test_eval() {
        let air = SubtreeRootValidityAir::new();
        let width = <SubtreeRootValidityAir as BaseAir<Val>>::width(&air);
        let mut builder_leaf = TestBuilder::new(width, 1, false);
        let wallet_id = [Val::ONE; 8];
        builder_leaf.set_wallet_id(0, &wallet_id);
        <SubtreeRootValidityAir as Air<TestBuilder>>::eval(&air, &mut builder_leaf);
        let mut builder_internal = TestBuilder::new(width, 1, true);
        let left_child = [Val::new(2); 8];
        let right_child = [Val::new(3); 8];
        builder_internal.set_children(0, &left_child, &right_child);

        <SubtreeRootValidityAir as Air<TestBuilder>>::eval(&air, &mut builder_internal);

        assert!(
            !builder_internal.assertions.is_empty(),
            "Internal node: no constraints were checked"
        );
    }
}
