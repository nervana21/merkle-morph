//! Global-level zero-knowledge proof verification and composition.
//!
//! Verifies wallet proofs at the global level. Supports direct wallet verification
//! with proofs and subtree verification with aggregated roots. Also provides
//! zero-knowledge proofs for global root composition from subtree roots.
//!
//! ```no_run
//! use merkle_morph::zkp::global::GlobalRootVerifier;
//! use merkle_morph::zkp::types::create_config;
//! use merkle_morph::zkp::prove_wallet_commitment;
//! use merkle_morph::global::GlobalState;
//! use merkle_morph::wallet::WalletState;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = create_config()?;
//! let global_state = GlobalState::default();
//! let wallet = WalletState::new([0u8; 32]);
//! let proof = prove_wallet_commitment(&config, &wallet)?;
//!
//! GlobalRootVerifier::new(&config, &global_state)
//!     .with_wallet_proof([0u8; 32], wallet, proof)
//!     .verify()?;
//! # Ok(())
//! # }
//! ```

mod air;
mod debug;
mod poseidon2_air;
mod prover;
mod trace;
mod verifier;

pub use debug::{
    compare_roots, print_composition_steps, print_subtree_details, verify_composition_steps,
    verify_poseidon2_trace, verify_start_depth, verify_step_ordering, verify_subtree_root,
    verify_trace_structure,
};
pub use poseidon2_air::global_trace_cols;
pub use prover::prove_global_root_composition;
pub use verifier::{
    verify_global_root, verify_global_root_composition, GlobalRootVerifier, WalletsWithProofs,
};
