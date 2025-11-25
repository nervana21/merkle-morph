#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Transfer amount type for channel state transitions
//!
//! This module defines a validated transfer amount type for channel state transitions.
//! In a unilateral channel, transfers are always from the sender to the receiver.
//!
//! ```rust
//! use merkle_morph::channel::TransferAmount;
//!
//! fn main() -> Result<(), merkle_morph::errors::ChannelError> {
//!     let amount = TransferAmount::new(100)?;
//!     // Can be used directly as u64 via Deref
//!     let value: u64 = *amount;
//!     Ok(())
//! }
//! ```

use std::ops::Deref;

/// Transfer amount structure
///
/// A validated transfer amount for channel state transitions. Represents a non-zero amount
/// to transfer from the sender to the receiver in a unilateral channel. The receiver is
/// fixed by the channel state.
///
/// # Usage
///
/// `TransferAmount` implements `Deref<Target = u64>`, so it can be used directly
/// as a `u64` in most contexts:
///
/// ```rust
/// use merkle_morph::channel::TransferAmount;
///
/// fn main() -> Result<(), merkle_morph::errors::ChannelError> {
///     let amount = TransferAmount::new(100)?;
///     let doubled = *amount * 2;
///     Ok(())
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferAmount(u64);

impl TransferAmount {
    /// Create a new transfer amount
    ///
    /// # Arguments
    /// * `amount` - The amount to transfer (must be > 0)
    ///
    /// # Returns
    /// * `Ok(TransferAmount)` - If the amount is valid
    /// * `Err(ChannelError::InvalidZeroTransfer)` - If amount is 0
    pub fn new(amount: u64) -> Result<Self, crate::errors::ChannelError> {
        if amount == 0 {
            return Err(crate::errors::ChannelError::InvalidZeroTransfer);
        }
        Ok(Self(amount))
    }
}

impl Deref for TransferAmount {
    type Target = u64;

    #[inline]
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ChannelError;

    #[test]
    fn test_transfer_amount_new() {
        let amount = TransferAmount::new(100).expect("valid amount");
        assert_eq!(*amount, 100);
    }

    #[test]
    fn test_transfer_amount_zero() {
        let result = TransferAmount::new(0);
        assert!(matches!(result, Err(ChannelError::InvalidZeroTransfer)));
    }

    #[test]
    fn test_transfer_amount_max() {
        let amount = TransferAmount::new(u64::MAX).expect("valid amount");
        assert_eq!(*amount, u64::MAX);
    }

    #[test]
    fn test_transfer_amount_deref() {
        let amount = TransferAmount::new(100).expect("valid amount");
        // Test deref usage
        let value: u64 = *amount;
        assert_eq!(value, 100);

        // Test in arithmetic
        let doubled = *amount * 2;
        assert_eq!(doubled, 200);
    }
}
