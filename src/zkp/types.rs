//! Type definitions for ZKP module
//!
//! This module provides core type definitions for the zero-knowledge proof system,
//! including field types, proof system configuration, and proof types. It defines
//! the concrete types used throughout the ZKP module for STARK proof generation
//! and verification.

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::PrimeCharacteristicRing;
use p3_fri::TwoAdicFriPcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{Proof as StarkProof, StarkConfig as UniStarkConfig};
use rand::rngs::SmallRng;
use rand::SeedableRng;

use crate::{Bytes32, Result};

/// Field type: BabyBear (31-bit) with extension for 128-bit security
pub(super) type Val = BabyBear;
pub(super) type Challenge = BinomialExtensionField<Val, 4>;

/// Permutation and hash types
type Perm = Poseidon2BabyBear<16>;
type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;

/// MMC types
type ValMmcs = MerkleTreeMmcs<
    <Val as p3_field::Field>::Packing,
    <Val as p3_field::Field>::Packing,
    MyHash,
    MyCompress,
    8,
>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

/// DFT and PCS types
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

/// Challenger type
type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

/// Type alias for trace matrix
pub(super) type Trace = RowMajorMatrix<Val>;

/// STARK configuration type (current implementation)
///
/// This is the concrete type for the current Plonky3-based implementation.
/// For generic code, prefer using `ZkpConfig` instead.
pub type StarkConfig = UniStarkConfig<Pcs, Challenge, Challenger>;

/// Zero-knowledge proof type
///
/// Currently implemented using Plonky3 STARK proofs.
/// This type can be updated when switching to different proof system backends.
pub type Proof = StarkProof<StarkConfig>;

/// Creates a proof system configuration
///
/// This function creates a configuration for the current proof system backend.
/// The configuration is used for both proof generation and verification.
pub fn create_config() -> Result<StarkConfig> {
    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    // Use log_blowup = 3 instead of 2 to handle high-degree constraints (SBOX_DEGREE = 7)
    // This ensures LDE height >= quotient domain size when log_quotient_degree = 3
    let fri_params = p3_fri::FriParameters {
        log_blowup: 3, // Increased from 2 to handle constraint degree 7
        log_final_poly_len: 2,
        num_queries: 2,
        proof_of_work_bits: 1,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    Ok(StarkConfig::new(pcs, challenger))
}

/// Helper to convert u64 to field element
/// Note: BabyBear is a 31-bit field, so we take modulo 2^31
pub(super) fn u64_to_field(val: u64) -> Val { BabyBear::new((val % (1u64 << 31)) as u32) }

/// Helper to convert Bytes32 to field elements (splits into 8 u32s)
pub(super) fn bytes32_to_fields(bytes: Bytes32) -> [Val; 8] {
    let mut fields = [BabyBear::ZERO; 8];
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(chunk);
        let u32_val = u32::from_le_bytes(arr);
        fields[i] = BabyBear::new(u32_val);
    }
    fields
}
