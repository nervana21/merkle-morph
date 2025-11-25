//! Channel state transitions
//!
//! This module implements transitions for unidirectional
//! payment channels. Transition functions are pure, side-effect-free operations that
//! transform channel states according to well-defined rules and invariants.
//!
//! Each transition is a self-contained unit that specifies:
//! - Valid source and target states in the channel lifecycle
//! - Preconditions that must hold before the transition can be applied
//! - Postconditions that are guaranteed after a successful transition
//! - Input requirements and validation rules
//! - Nonce progression rules (typically strict +1 increment, with documented exceptions)
//! - Fee semantics and allocation policies

pub mod cooperative_close;
pub mod force_close;
pub mod recover;
pub mod transfer;

pub use cooperative_close::{
    apply_cooperative_close, apply_cooperative_close_with_fee_contributions,
};
pub use force_close::{apply_force_close, validate_force_close_state};
pub use recover::apply_recover;
pub use transfer::{apply_transfer, apply_transfer_state_only, TransferResult};
