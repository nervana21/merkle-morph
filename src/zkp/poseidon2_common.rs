//! Common Poseidon2 AIR infrastructure
//!
//! This module provides shared Poseidon2 AIR constants, parameters, and utilities
//! used by both channel and wallet commitment verification.

use core::mem::size_of;
use core::ptr::addr_of;

use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2::ExternalLayerConstants;
use p3_poseidon2_air::{num_cols, Poseidon2Air, Poseidon2Cols, RoundConstants};
use rand::distr::StandardUniform;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use crate::zkp::types::Val;

/// Poseidon2 parameters for BabyBear
pub(crate) const POSEIDON2_WIDTH: usize = 16;
/// Poseidon2 sponge rate (number of field elements absorbed per permutation)
/// For width 16, rate 8 means capacity 8 (rate + capacity = width)
pub(crate) const POSEIDON2_RATE: usize = 8;
/// Poseidon2 output size in field elements (8 elements = 32 bytes = 256 bits)
pub(crate) const POSEIDON2_OUTPUT_SIZE: usize = 8;
pub(crate) const POSEIDON2_SBOX_DEGREE: u64 = 7;
pub(crate) const POSEIDON2_SBOX_REGISTERS: usize = 1;
pub(crate) const POSEIDON2_HALF_FULL_ROUNDS: usize = 4;
pub(crate) const POSEIDON2_PARTIAL_ROUNDS: usize = 20;

/// Poseidon2 constants bundle created from a single RNG state
///
/// This ensures all constants are consistent - the AIR round constants
/// match the hash function parameters, guaranteeing that in-circuit
/// verification matches out-of-circuit hash computation.
#[derive(Clone)]
pub(crate) struct Poseidon2Constants {
    /// Round constants for Poseidon2 AIR verification
    pub round_constants:
        RoundConstants<Val, POSEIDON2_WIDTH, POSEIDON2_HALF_FULL_ROUNDS, POSEIDON2_PARTIAL_ROUNDS>,
    /// External layer constants for Poseidon2 hash computation
    pub external_constants: p3_poseidon2::ExternalLayerConstants<Val, POSEIDON2_WIDTH>,
    /// Internal constants for Poseidon2 hash computation
    pub internal_constants: Vec<Val>,
}

/// Create both RoundConstants and Poseidon2 parameters from the same RNG state
/// This ensures the hash function uses the same constants as the AIR
pub(crate) fn create_poseidon2_constants_and_params() -> Poseidon2Constants {
    // Create constants from the same RNG state, ensuring they match
    let mut rng = SmallRng::seed_from_u64(1);

    // Generate constants in the same order as RoundConstants::from_rng
    let mut beginning_full_round_constants =
        [[Val::ZERO; POSEIDON2_WIDTH]; POSEIDON2_HALF_FULL_ROUNDS];
    for item in &mut beginning_full_round_constants {
        *item = [(); POSEIDON2_WIDTH].map(|_| rng.sample(StandardUniform));
    }
    let partial_round_constants: [Val; POSEIDON2_PARTIAL_ROUNDS] =
        [(); POSEIDON2_PARTIAL_ROUNDS].map(|_| rng.sample(StandardUniform));
    let mut ending_full_round_constants =
        [[Val::ZERO; POSEIDON2_WIDTH]; POSEIDON2_HALF_FULL_ROUNDS];
    for item in &mut ending_full_round_constants {
        *item = [(); POSEIDON2_WIDTH].map(|_| rng.sample(StandardUniform));
    }

    // Create RoundConstants for AIR
    let round_constants = RoundConstants::new(
        beginning_full_round_constants,
        partial_round_constants,
        ending_full_round_constants,
    );

    // Create ExternalLayerConstants and internal constants for Poseidon2
    let external_constants = ExternalLayerConstants::new(
        beginning_full_round_constants.to_vec(),
        ending_full_round_constants.to_vec(),
    );
    let internal_constants = partial_round_constants.to_vec();

    Poseidon2Constants { round_constants, external_constants, internal_constants }
}

/// Create deterministic Poseidon2 round constants
///
/// Convenience function that extracts only the round constants needed for AIR.
/// Note: This still computes all constants internally to ensure consistency.
pub(crate) fn create_poseidon2_constants(
) -> RoundConstants<Val, POSEIDON2_WIDTH, POSEIDON2_HALF_FULL_ROUNDS, POSEIDON2_PARTIAL_ROUNDS> {
    create_poseidon2_constants_and_params().round_constants
}

/// Number of columns required for one Poseidon2 AIR computation
/// This uses Plonky3's num_cols() which returns the number of field elements.
/// The num_cols() function uses u8 as a placeholder but returns the count of elements,
/// not bytes, since it's used directly as the matrix width in RowMajorMatrix<Val>.
pub(crate) fn poseidon2_air_num_cols() -> usize {
    num_cols::<
        POSEIDON2_WIDTH,
        POSEIDON2_SBOX_DEGREE,
        POSEIDON2_SBOX_REGISTERS,
        POSEIDON2_HALF_FULL_ROUNDS,
        POSEIDON2_PARTIAL_ROUNDS,
    >()
}

/// Compute the offset (in field elements) to the final output state in Poseidon2Cols
///
/// The final output is stored in `ending_full_rounds[last].post[0..8]`.
/// Since `Poseidon2Cols` is `#[repr(C)]`, the layout is deterministic and we can
/// compute the offset at runtime using pointer arithmetic.
///
/// Returns the offset in number of field elements (not bytes) from the start of Poseidon2Cols.
pub(crate) fn poseidon2_output_offset() -> usize {
    // We need to compute the offset to ending_full_rounds[HALF_FULL_ROUNDS - 1].post[0]
    // Since #[repr(C)] guarantees deterministic layout, we can use pointer arithmetic
    // with addr_of! to safely compute offsets without creating references to uninitialized memory

    // Use Val (BabyBear) as the field type since that's what we use in the trace
    // The offset is computed in bytes, then converted to field elements
    let size_of_field = size_of::<Val>();

    // Create a zero-initialized instance on the stack to compute offsets
    // We'll use addr_of! to get pointers to fields without creating references
    let dummy = core::mem::MaybeUninit::<
        Poseidon2Cols<
            Val,
            POSEIDON2_WIDTH,
            POSEIDON2_SBOX_DEGREE,
            POSEIDON2_SBOX_REGISTERS,
            POSEIDON2_HALF_FULL_ROUNDS,
            POSEIDON2_PARTIAL_ROUNDS,
        >,
    >::zeroed();

    #[allow(unsafe_code)]
    unsafe {
        let cols_ptr = dummy.as_ptr();

        // Use addr_of! to get pointer to the last ending_full_round's post field
        // This avoids creating a reference to uninitialized memory
        let last_round_idx = POSEIDON2_HALF_FULL_ROUNDS - 1;
        let post_ptr = addr_of!((*cols_ptr).ending_full_rounds[last_round_idx].post[0]);

        // Compute offset in bytes, then convert to field elements
        let offset_bytes = post_ptr as usize - cols_ptr as usize;
        offset_bytes / size_of_field
    }
}

/// Poseidon2 AIR type used across all modules
///
/// This is the common type for Poseidon2 AIR instances used in channel and wallet proofs.
pub(crate) type CommonPoseidon2Air = Poseidon2Air<
    Val,
    GenericPoseidon2LinearLayersBabyBear,
    POSEIDON2_WIDTH,
    POSEIDON2_SBOX_DEGREE,
    POSEIDON2_SBOX_REGISTERS,
    POSEIDON2_HALF_FULL_ROUNDS,
    POSEIDON2_PARTIAL_ROUNDS,
>;

/// Create a Poseidon2 AIR instance with deterministic constants
///
/// This function creates a Poseidon2 AIR instance using the same constants
/// as the hash function, ensuring consistency between in-circuit verification
/// and out-of-circuit hash computation.
pub(crate) fn create_poseidon2_air() -> CommonPoseidon2Air {
    let constants = create_poseidon2_constants();
    CommonPoseidon2Air::new(constants)
}

/// Evaluate a single Poseidon2 AIR permutation at a given column offset
///
/// This helper function evaluates a Poseidon2 AIR instance on a slice of columns
/// from the main trace, starting at the specified offset.
///
/// # Arguments
/// * `air`: The Poseidon2 AIR instance to evaluate
/// * `builder`: The air builder containing the trace
/// * `offset`: The column offset where the Poseidon2 trace begins
pub(crate) fn eval_poseidon2_air_at_offset<AB, PA>(air: &PA, builder: &mut AB, offset: usize)
where
    AB: p3_air::AirBuilderWithPublicValues,
    AB::F: p3_field::PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
    for<'a> PA: p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
{
    use crate::zkp::builder_wrapper::ColumnSliceBuilder;
    let poseidon2_cols = poseidon2_air_num_cols();
    let mut hash_builder = ColumnSliceBuilder::new(builder, offset, poseidon2_cols);
    air.eval(&mut hash_builder);
}

/// Evaluate multiple Poseidon2 AIR permutations starting at a given column offset
///
/// This helper function evaluates a Poseidon2 AIR instance on multiple consecutive
/// slices of columns from the main trace, starting at the specified offset.
///
/// # Arguments
/// * `air`: The Poseidon2 AIR instance to evaluate
/// * `builder`: The air builder containing the trace
/// * `offset`: The column offset where the first Poseidon2 trace begins
/// * `num_permutations`: The number of consecutive permutations to evaluate
pub(crate) fn eval_poseidon2_air_multiple_permutations<AB, PA>(
    air: &PA,
    builder: &mut AB,
    offset: usize,
    num_permutations: usize,
) where
    AB: p3_air::AirBuilderWithPublicValues,
    AB::F: p3_field::PrimeField64 + core::marker::Send + core::marker::Sync + core::marker::Sized,
    for<'a> PA: p3_air::Air<crate::zkp::builder_wrapper::ColumnSliceBuilder<'a, AB>>,
{
    use crate::zkp::builder_wrapper::ColumnSliceBuilder;
    let poseidon2_cols = poseidon2_air_num_cols();
    for i in 0..num_permutations {
        let perm_offset = offset + i * poseidon2_cols;
        let mut hash_builder = ColumnSliceBuilder::new(builder, perm_offset, poseidon2_cols);
        air.eval(&mut hash_builder);
    }
}
