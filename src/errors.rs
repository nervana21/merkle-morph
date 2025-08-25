//! Error types for the Merkle Morph library
//!
//! This module defines all error types used throughout the library,
//! providing detailed error information for debugging and handling.

use thiserror::Error;

use crate::types::ChannelId;

/// The main error type for the Merkle Morph library
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Channel-related errors
    #[error(transparent)]
    Channel(#[from] ChannelError),

    /// Wallet-related errors
    #[error(transparent)]
    Wallet(#[from] WalletError),
}

/// Errors that can occur during channel operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChannelError {
    /// Cannot transfer zero amount
    #[error("Transfer amount cannot be zero")]
    InvalidZeroTransfer,

    /// Insufficient balance for transfer
    #[error("Insufficient balance")]
    InsufficientBalance,

    /// Balance overflow during transfer
    #[error("Balance overflow: would exceed maximum value")]
    BalanceOverflow,

    /// Nonce overflow: cannot increment further
    #[error("Nonce overflow: cannot increment further")]
    ChannelNonceOverflow,
}

/// Errors that can occur during wallet operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WalletError {
    /// Channel-related errors
    #[error(transparent)]
    Channel(#[from] ChannelError),

    /// Channel not found in wallet
    #[error("Channel not found in wallet: {0:?}")]
    ChannelNotFound(ChannelId),

    /// Wallet nonce overflow
    #[error("Nonce overflow: cannot increment further")]
    WalletNonceOverflow,
}

/// Result type alias for the library
pub type Result<T> = std::result::Result<T, Error>;
