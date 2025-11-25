//! Bitcoin transaction builders for channels
//!
//! This module provides Bitcoin transaction construction functions that translate
//! channel state transitions into Bitcoin transaction format.
//!
//! Transaction builders are mechanical - they construct Bitcoin transactions
//! but do not contain business logic or commitment rules. Business logic lives
//! in the `transition/` module.
//!
//! All transaction builders use Silent Payments (BIP 352) for recipient outputs.

/// Challenge transaction utilities
pub mod challenge;
/// Cooperative close transaction utilities
pub mod cooperative_close;
/// Force close transaction utilities
pub mod force_close;

pub use challenge::{
    build_all_challenge_transactions, build_challenge_transaction_for_output,
    build_revocation_sweep_transaction,
};
pub use cooperative_close::build_cooperative_close_transaction;
pub use force_close::build_force_close_transaction;
