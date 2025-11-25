//! AirBuilder wrapper for column slicing.
//!
//! This module provides `ColumnSliceBuilder` which wraps an `AirBuilder` and
//! exposes only a subset of columns from the underlying trace. This allows
//! calling sub-AIRs (like Poseidon2Air) on a slice of the full trace.

use p3_air::{AirBuilder, AirBuilderWithPublicValues, ExtensionBuilder, PairBuilder};
use p3_matrix::Matrix;

use crate::zkp::column_slice::ColumnSliceMatrix;

/// A wrapper around an `AirBuilder` that exposes only a subset of columns.
///
/// This allows calling sub-AIRs (like `Poseidon2Air`) on a slice of the full trace.
/// All other builder methods are forwarded to the inner builder unchanged.
pub(crate) struct ColumnSliceBuilder<'a, AB: AirBuilder> {
    /// The underlying builder being wrapped.
    inner: &'a mut AB,
    /// The column offset where the slice begins.
    offset: usize,
    /// The number of columns in the slice.
    width: usize,
}

impl<'a, AB: AirBuilder> ColumnSliceBuilder<'a, AB> {
    /// Create a new column-sliced builder.
    ///
    /// # Arguments
    /// - `inner`: A mutable reference to the underlying builder to wrap.
    /// - `offset`: The column index where the slice begins.
    /// - `width`: The number of columns to expose.
    ///
    /// # Panics
    /// Panics if `offset + width` exceeds the width of the inner builder's main matrix.
    pub(crate) fn new(inner: &'a mut AB, offset: usize, width: usize) -> Self {
        let inner_width = inner.main().width();
        assert!(
            offset + width <= inner_width,
            "Column slice out of bounds: offset {} + width {} > inner width {}",
            offset,
            width,
            inner_width
        );
        Self { inner, offset, width }
    }
}

impl<'a, AB: AirBuilder> AirBuilder for ColumnSliceBuilder<'a, AB> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type M = ColumnSliceMatrix<AB::Var, AB::M>;

    fn main(&self) -> Self::M {
        ColumnSliceMatrix::new(self.inner.main(), self.offset, self.width)
            .expect("Bounds checked in constructor")
    }

    fn is_first_row(&self) -> Self::Expr { self.inner.is_first_row() }

    fn is_last_row(&self) -> Self::Expr { self.inner.is_last_row() }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) { self.inner.assert_zero(x) }
}

impl<'a, AB: PairBuilder> PairBuilder for ColumnSliceBuilder<'a, AB> {
    fn preprocessed(&self) -> Self::M {
        // For preprocessed, we also slice columns if needed.
        // For now, we use the same offset/width as main, but this could be configurable
        // in the future if preprocessed matrices have different layouts.
        let preprocessed_matrix = self.inner.preprocessed();
        let preprocessed_width = preprocessed_matrix.width();
        ColumnSliceMatrix::new(preprocessed_matrix, self.offset, self.width).unwrap_or_else(|| {
            panic!(
                "Preprocessed column slice out of bounds: offset {} + width {} > preprocessed width {}. \
                 Note: Preprocessed matrix may have a different structure than main trace.",
                self.offset, self.width, preprocessed_width
            )
        })
    }
}

impl<'a, AB: ExtensionBuilder> ExtensionBuilder for ColumnSliceBuilder<'a, AB> {
    type EF = AB::EF;
    type ExprEF = AB::ExprEF;
    type VarEF = AB::VarEF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.inner.assert_zero_ext(x)
    }
}

impl<'a, AB: AirBuilderWithPublicValues> AirBuilderWithPublicValues for ColumnSliceBuilder<'a, AB> {
    type PublicVar = AB::PublicVar;

    fn public_values(&self) -> &[Self::PublicVar] { self.inner.public_values() }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::zkp::types::Val;

    #[derive(Clone)]
    struct DummyBuilder {
        main: RowMajorMatrix<Val>,
        preprocessed: RowMajorMatrix<Val>,
    }

    impl DummyBuilder {
        fn new(width: usize, height: usize) -> Self {
            let main_data: Vec<Val> = (0..width * height).map(|i| Val::new(i as u32)).collect();
            let preprocessed_data: Vec<Val> =
                (0..width * height).map(|i| Val::new((i + 100) as u32)).collect();
            Self {
                main: RowMajorMatrix::new(main_data, width),
                preprocessed: RowMajorMatrix::new(preprocessed_data, width),
            }
        }
    }

    impl AirBuilder for DummyBuilder {
        type F = Val;
        type Expr = Val;
        type Var = Val;
        type M = RowMajorMatrix<Self::Var>;

        fn main(&self) -> Self::M { self.main.clone() }
        fn is_first_row(&self) -> Self::Expr { Val::ZERO }
        fn is_last_row(&self) -> Self::Expr { Val::ZERO }
        fn is_transition_window(&self, _size: usize) -> Self::Expr { Val::ONE }
        fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {}
    }

    impl PairBuilder for DummyBuilder {
        fn preprocessed(&self) -> Self::M { self.preprocessed.clone() }
    }

    #[test]
    fn test_column_slice_builder_slices_main_and_preprocessed() {
        let mut inner = DummyBuilder::new(6, 2);
        let builder = ColumnSliceBuilder::new(&mut inner, 1, 3);

        let main = builder.main();
        assert_eq!(main.width(), 3, "Main slice should expose requested width");

        let preprocessed = builder.preprocessed();
        assert_eq!(preprocessed.width(), 3, "Preprocessed slice should match requested width");
    }

    #[test]
    #[should_panic(expected = "Column slice out of bounds")]
    fn test_column_slice_builder_panics_when_out_of_bounds() {
        let mut inner = DummyBuilder::new(4, 1);
        let _ = ColumnSliceBuilder::new(&mut inner, 3, 2);
    }
}
