#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Error types for the Merkle Morph library
//!
//! This module defines all error types used throughout the library,
//! providing detailed error information for debugging and handling.

use thiserror::Error;

use crate::types::{ChannelId, WalletId};

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

    /// Global state errors
    #[error(transparent)]
    Global(#[from] GlobalError),

    /// Bitcoin transaction errors
    #[error(transparent)]
    Btx(#[from] BtxError),

    /// Zero-knowledge proof errors
    #[error(transparent)]
    Zkp(#[from] ZkpError),
}

/// Errors that can occur during channel operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChannelError {
    /// Channel is closed and cannot accept further operations
    #[error("Channel is closed")]
    ChannelClosed,

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

/// Errors that can occur during global state operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GlobalError {
    /// Wallet not found in global state
    #[error("Wallet not found in global state: {0:?}")]
    WalletNotFound(WalletId),

    /// Global state nonce overflow
    #[error("Global state nonce overflow: cannot increment further")]
    GlobalNonceOverflow,
}

/// Errors that can occur during zero-knowledge proof operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZkpError {
    /// Proof generation failed
    #[error("Proof generation failed")]
    ProofGenerationFailed,

    /// Proof verification failed
    #[error("Proof verification failed")]
    ProofVerificationFailed,

    /// AIR constraint violation
    #[error("AIR constraint violation")]
    InvalidAir,

    /// Trace generation failed
    #[error("Trace generation failed: {0}")]
    TraceGenerationFailed(String),

    /// Configuration setup failed
    #[error("Configuration setup failed")]
    ConfigSetupFailed,
}

/// Errors that can occur during Bitcoin transaction operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BtxError {
    /// Transaction validation failed (input value < output value)
    ///
    /// In Bitcoin, transaction inputs must be greater than or equal to outputs
    /// (the difference is the transaction fee). This error indicates insufficient
    /// input value to cover the outputs.
    #[error("Invalid transaction: input value is less than output value")]
    InvalidTransaction,

    /// Cannot compose invalid transactions
    #[error("Invalid composition: cannot compose invalid transactions")]
    InvalidComposition,

    /// Script execution failed
    ///
    /// The script execution did not complete successfully. This could be due to
    /// invalid signatures, incorrect script logic, or other script execution errors.
    #[error("Script execution failed: {0}")]
    ScriptExecutionFailed(String),

    /// Invalid scriptSig
    ///
    /// The scriptSig (unlocking script) failed validation against the scriptPubkey.
    #[error("Invalid scriptSig at input {0}: {1}")]
    InvalidScriptSig(usize, String),

    /// Invalid witness
    ///
    /// The witness data failed validation for SegWit transactions.
    #[error("Invalid witness at input {0}: {1}")]
    InvalidWitness(usize, String),

    /// Invalid scriptPubkey
    ///
    /// The scriptPubkey (locking script) is invalid or cannot be parsed.
    #[error("Invalid scriptPubkey: {0}")]
    InvalidScriptPubkey(String),

    /// Missing spent output
    ///
    /// A required spent output (UTXO) was not found for the given OutPoint.
    #[error("Missing spent output: {0:?}")]
    MissingSpentOutput(bitcoin::OutPoint),

    /// Invalid locktime
    ///
    /// The transaction locktime validation failed.
    #[error("Invalid locktime")]
    InvalidLockTime,

    /// Invalid sequence
    ///
    /// The sequence number validation failed.
    #[error("Invalid sequence at input {0}")]
    InvalidSequence(usize),

    /// Transaction size exceeded
    ///
    /// The transaction exceeds Bitcoin's size limits.
    #[error("Transaction size exceeded: {0} bytes (max: {1} bytes)")]
    TransactionSizeExceeded(usize, usize),

    /// Invalid version
    ///
    /// The transaction version is invalid.
    #[error("Invalid transaction version")]
    InvalidVersion,

    /// Address derivation failed
    ///
    /// Could not derive a Bitcoin address from the script_pubkey.
    /// This can happen for non-standard scripts (e.g., OP_RETURN outputs).
    #[error("Cannot derive address from script_pubkey: {0}")]
    AddressDerivationFailed(String),

    /// Missing UTXO data
    ///
    /// Required UTXO data (value, address) is missing and cannot be derived.
    #[error("Missing UTXO data for outpoint {0:?}")]
    MissingUtxoData(bitcoin::OutPoint),
}

/// Result type alias for the library
pub type Result<T> = std::result::Result<T, Error>;
