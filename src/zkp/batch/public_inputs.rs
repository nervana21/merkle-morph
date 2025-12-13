// SPDX-License-Identifier: CC0-1.0

//! Batch-level public inputs for zero-knowledge proof verification.
//!
//! This mirrors the `SubtreeRootPublicInput` pattern: only the commitments we
//! care about (pre/post roots plus a nonce) are exposed as public inputs. All
//! intermediate steps stay private to keep circuits small while still binding
//! the execution trace to the final commitment.

use crate::GlobalRoot;

/// Public inputs for a batch-level proof: initial root, final root, and nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchPublicInputs {
    /// Global root before the batch executes.
    pub pre_root: GlobalRoot,
    /// Global root after the batch executes.
    pub post_root: GlobalRoot,
    /// Monotonically increasing nonce for replay protection.
    pub nonce: u32,
}
