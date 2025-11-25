//! Column-slicing utilities for extracting Poseidon2 columns from the full trace.
//!
//! This module provides a `ColumnSliceMatrix` wrapper that allows treating a subset
//! of columns from a larger matrix as if it were a standalone matrix. This is used
//! to extract Poseidon2 AIR columns from the channel transition trace.
//!
//! # Safety
//! This module uses unsafe code to implement the `Matrix` trait, which requires
//! unsafe methods. The unsafe operations are safe because we maintain the invariants
//! required by the trait: bounds checking is done in the constructor and public methods.

#![allow(unsafe_code)]

use core::marker::PhantomData;

use p3_matrix::Matrix;

/// A matrix wrapper that exposes a contiguous slice of columns starting at a given offset.
///
/// This allows treating columns `[offset..offset+width]` from an inner matrix as if
/// they were columns `[0..width]` of a standalone matrix. This is useful for
/// extracting Poseidon2 AIR columns from a larger trace.
pub(crate) struct ColumnSliceMatrix<T, Inner> {
    /// The underlying full matrix being wrapped.
    inner: Inner,
    /// The column offset where the slice begins.
    offset: usize,
    /// The number of columns in the slice.
    width: usize,
    /// Marker for the element type `T`, not used at runtime.
    _phantom: PhantomData<T>,
}

impl<T, Inner: Matrix<T>> ColumnSliceMatrix<T, Inner>
where
    T: Send + Sync + Clone,
{
    /// Construct a new column-sliced view of a matrix.
    ///
    /// # Arguments
    /// - `inner`: The full inner matrix to be wrapped.
    /// - `offset`: The column index where the slice begins.
    /// - `width`: The number of columns to expose (must satisfy `offset + width <= inner.width()`).
    ///
    /// Returns `None` if `offset + width` exceeds the width of the inner matrix.
    pub(crate) fn new(inner: Inner, offset: usize, width: usize) -> Option<Self> {
        (offset + width <= inner.width()).then(|| Self {
            inner,
            offset,
            width,
            _phantom: PhantomData,
        })
    }
}

#[allow(unsafe_code)]
impl<T, Inner> Matrix<T> for ColumnSliceMatrix<T, Inner>
where
    T: Send + Sync + Clone,
    Inner: Matrix<T>,
{
    /// Returns the number of columns in the slice.
    #[inline(always)]
    fn width(&self) -> usize { self.width }

    /// Returns the number of rows in the matrix (same as the inner matrix).
    #[inline(always)]
    fn height(&self) -> usize { self.inner.height() }

    #[inline(always)]
    unsafe fn get_unchecked(&self, r: usize, c: usize) -> T {
        // Safety: The caller must ensure that `c < self.width` and `r < self.height()`.
        // We translate column `c` to column `self.offset + c` in the inner matrix.
        unsafe { self.inner.get_unchecked(r, self.offset + c) }
    }

    unsafe fn row_unchecked(
        &self,
        r: usize,
    ) -> impl IntoIterator<Item = T, IntoIter = impl Iterator<Item = T> + Send + Sync> {
        // Safety: The caller must ensure that `r < self.height()`.
        // We slice from offset to offset+width.
        unsafe { self.inner.row_subseq_unchecked(r, self.offset, self.offset + self.width) }
    }

    unsafe fn row_subseq_unchecked(
        &self,
        r: usize,
        start: usize,
        end: usize,
    ) -> impl IntoIterator<Item = T, IntoIter = impl Iterator<Item = T> + Send + Sync> {
        // Safety: The caller must ensure that r < self.height() and start <= end <= self.width().
        // We translate the slice to the inner matrix's coordinate system.
        unsafe { self.inner.row_subseq_unchecked(r, self.offset + start, self.offset + end) }
    }

    unsafe fn row_subslice_unchecked(
        &self,
        r: usize,
        start: usize,
        end: usize,
    ) -> impl core::ops::Deref<Target = [T]> {
        // Safety: The caller must ensure that `r < self.height()` and `start <= end <= self.width()`.
        // We translate the slice to the inner matrix's coordinate system.
        unsafe { self.inner.row_subslice_unchecked(r, self.offset + start, self.offset + end) }
    }
}

#[cfg(test)]
mod tests {
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;

    #[test]
    fn test_column_slice() {
        // Create a 3x6 matrix:
        // [ 1  2  3  4  5  6]
        // [ 7  8  9 10 11 12]
        // [13 14 15 16 17 18]
        let inner = RowMajorMatrix::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
            6,
        );

        // Slice columns 2-5 (width 4, offset 2)
        let sliced = ColumnSliceMatrix::new(inner, 2, 4).expect("Should be valid");

        assert_eq!(sliced.width(), 4);
        assert_eq!(sliced.height(), 3);

        // Check individual elements
        assert_eq!(sliced.get(0, 0), Some(3)); // row 0, col 0 of slice = row 0, col 2 of inner
        assert_eq!(sliced.get(1, 1), Some(10)); // row 1, col 1 of slice = row 1, col 3 of inner
        #[allow(unsafe_code)]
        unsafe {
            assert_eq!(sliced.get_unchecked(0, 2), 5); // row 0, col 2 of slice = row 0, col 4 of inner
        }

        // Row 0: should return [3, 4, 5, 6]
        let row0: Vec<_> = sliced.row(0).expect("Row 0 should exist").into_iter().collect();
        assert_eq!(row0, vec![3, 4, 5, 6]);

        #[allow(unsafe_code)]
        unsafe {
            let row1 = sliced.row_slice_unchecked(1);
            assert_eq!(&*row1, &[9, 10, 11, 12]);
        }
    }

    #[test]
    fn test_invalid_slice() {
        let inner = RowMajorMatrix::new(vec![1, 2, 3, 4, 5, 6], 3);

        // Attempt to slice beyond inner width (invalid).
        assert!(ColumnSliceMatrix::new(inner, 1, 3).is_none()); // offset 1 + width 3 = 4 > 3
    }

    #[test]
    fn test_row_subseq_and_subslice_unchecked() {
        let inner = RowMajorMatrix::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            4, // width
        );
        let slice = ColumnSliceMatrix::new(inner, 1, 3).expect("slice should succeed");

        #[allow(unsafe_code)]
        unsafe {
            let collected: Vec<_> = slice.row_subseq_unchecked(2, 0, 2).into_iter().collect();
            assert_eq!(collected, vec![10, 11], "Should read translated subseq");

            let subslice = slice.row_subslice_unchecked(1, 1, 3);
            assert_eq!(&*subslice, &[7, 8], "Subslice should map into inner matrix");
        }
    }
}
