//! Poseidon2 hash functions for channel commitments
//!
//! This module provides Poseidon2-based hashing functions for
//! in-circuit verification of commitments.

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_field::PrimeField32;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

use crate::zkp::poseidon2_common::{
    create_poseidon2_constants_and_params, POSEIDON2_OUTPUT_SIZE, POSEIDON2_RATE, POSEIDON2_WIDTH,
};
use crate::Bytes32;

/// Poseidon2 permutation type for BabyBear (width: 16)
type Perm = Poseidon2BabyBear<POSEIDON2_WIDTH>;
/// Poseidon2 hash sponge (rate: 8, output: 8 field elements = 32 bytes)
type PoseidonHash = PaddingFreeSponge<Perm, POSEIDON2_WIDTH, POSEIDON2_RATE, POSEIDON2_OUTPUT_SIZE>;

/// Creates a deterministic Poseidon2 hash instance
/// Uses the same constants as the AIR to ensure consistency
fn create_poseidon_hash() -> PoseidonHash {
    // Use the same constants as the AIR to ensure trace generation matches hash computation
    // This function creates both RoundConstants (for AIR) and Poseidon2 params (for hash) from the same RNG
    let constants = create_poseidon2_constants_and_params();

    // Create permutation from constants (matching AIR)
    let perm = Perm::new(constants.external_constants, constants.internal_constants);
    PoseidonHash::new(perm)
}

/// Converts bytes to field elements (4 bytes per field element, little-endian)
/// Note: BabyBear is 31-bit, so we can safely fit 4 bytes per element
fn bytes_to_fields(bytes: &[u8]) -> Vec<BabyBear> {
    let mut fields = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut arr = [0u8; 4];
        arr[..chunk.len()].copy_from_slice(chunk);
        let u32_val = u32::from_le_bytes(arr);
        fields.push(BabyBear::new(u32_val));
    }
    fields
}

/// Converts 8 field elements to Bytes32 (little-endian)
fn fields_to_bytes32(fields: [BabyBear; 8]) -> Bytes32 {
    let mut bytes = [0u8; 32];
    for (i, field) in fields.iter().enumerate() {
        // BabyBear is a 31-bit field, so we can safely convert to u32
        // Use the canonical representation via PrimeField32 trait
        let val = PrimeField32::as_canonical_u32(field);
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    bytes
}

/// Hash arbitrary bytes using Poseidon2
pub fn poseidon2_hash_bytes(input: &[u8]) -> Bytes32 {
    let hash = create_poseidon_hash();
    let fields = bytes_to_fields(input);
    let output_fields = hash.hash_iter(fields.iter().copied());
    fields_to_bytes32(output_fields)
}

/// Hash a fixed-size input using Poseidon2
/// This is a convenience function for hashing structured data
pub fn poseidon2_hash_fixed(inputs: &[&[u8]]) -> Bytes32 {
    // Concatenate all inputs
    let total_len: usize = inputs.iter().map(|x| x.len()).sum();
    let mut combined = Vec::with_capacity(total_len);
    for input in inputs {
        combined.extend_from_slice(input);
    }
    poseidon2_hash_bytes(&combined)
}
