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

    /// Funder cannot afford the closing fee
    #[error("Funder cannot afford fee on force close transaction: balance {balance} < fee {fee}")]
    FunderCannotAffordFee {
        /// The funder's current balance
        balance: u64,
        /// The required closing fee
        fee: u64,
    },

    /// Force closer cannot afford the closing fee
    #[error(
        "Force closer cannot afford fee on force close transaction: balance {balance} < fee {fee}"
    )]
    ForceCloserCannotAffordFee {
        /// The force closer's current balance
        balance: u64,
        /// The required closing fee
        fee: u64,
    },

    /// Closer cannot afford the closing fee
    #[error("Closer cannot afford fee on closing transaction: balance {balance} < fee {fee}")]
    CloserCannotAffordFee {
        /// The closer's current balance
        balance: u64,
        /// The required closing fee
        fee: u64,
    },

    /// Combined fee contributions from both parties are insufficient (sum < required)
    #[error(
        "Insufficient combined fee contribution: sender {sender_contribution} + receiver {receiver_contribution} = {total_contribution} < required {required_fee}"
    )]
    InsufficientCombinedFeeContribution {
        /// The sender's fee contribution
        sender_contribution: u64,
        /// The receiver's fee contribution
        receiver_contribution: u64,
        /// The total combined fee contribution (sender + receiver)
        total_contribution: u64,
        /// The required closing fee
        required_fee: u64,
    },

    /// One or both parties individually contribute more than the required fee
    #[error(
        "Per-party fee contribution exceeds required fee: sender {sender_contribution}, receiver {receiver_contribution}, required {required_fee}"
    )]
    PerPartyFeeContributionExceedsRequired {
        /// The sender's fee contribution
        sender_contribution: u64,
        /// The receiver's fee contribution
        receiver_contribution: u64,
        /// The required closing fee
        required_fee: u64,
    },

    /// Total fee contribution does not match the required fee (sum > required)
    #[error(
        "Total fee contribution mismatch: sender {sender_contribution} + receiver {receiver_contribution} = {total_contribution} > required {required_fee}"
    )]
    TotalFeeContributionMismatch {
        /// The sender's fee contribution
        sender_contribution: u64,
        /// The receiver's fee contribution
        receiver_contribution: u64,
        /// The total combined fee contribution (sender + receiver)
        total_contribution: u64,
        /// The required closing fee
        required_fee: u64,
    },

    /// Sender cannot afford their fee contribution
    #[error(
        "Sender cannot afford fee contribution: balance {balance} < contribution {contribution}"
    )]
    InsufficientSenderFeeContribution {
        /// The sender's current balance
        balance: u64,
        /// The required sender contribution
        contribution: u64,
    },

    /// Receiver cannot afford their fee contribution
    #[error(
        "Receiver cannot afford fee contribution: balance {balance} < contribution {contribution}"
    )]
    InsufficientReceiverFeeContribution {
        /// The receiver's current balance
        balance: u64,
        /// The required receiver contribution
        contribution: u64,
    },

    /// Public key is missing when required
    #[error("Public key is missing: {0}")]
    MissingPublicKey(String),

    /// Invalid funding script
    #[error("Invalid funding script: {0}")]
    InvalidFundingScript(String),

    /// Force close timeout not met (CSV time lock not satisfied)
    #[error(
        "Force close timeout not met: current height {current_height}, required height {required_height}"
    )]
    ForceCloseTimeoutNotMet {
        /// Current block height
        current_height: u32,
        /// Required block height for time lock
        required_height: u32,
    },

    /// Invalid force close state (using old state)
    #[error(
        "Invalid force close state: provided nonce {provided_nonce} < latest nonce {latest_nonce}"
    )]
    InvalidForceCloseState {
        /// Nonce in the force close transaction
        provided_nonce: u32,
        /// Latest known nonce for the channel
        latest_nonce: u32,
    },

    /// Invalid force close transaction (e.g., missing or malformed outputs)
    #[error("Invalid force close transaction: {reason}")]
    InvalidForceCloseTransaction {
        /// Reason why the force close transaction is considered invalid
        reason: String,
    },

    /// Output value is below dust limit after fee deduction
    #[error("Output {output_index} value {output_value} sats is below dust limit {dust_limit} after fee deduction {fee}")]
    OutputBelowDustLimit {
        /// The index of the output that is below dust
        output_index: usize,
        /// The output value in satoshis
        output_value: u64,
        /// The fee deducted in satoshis
        fee: u64,
        /// The dust limit in satoshis
        dust_limit: u64,
    },

    /// No challengeable outputs found (all outputs are dust after fee deduction)
    #[error("No challengeable outputs found: all outputs are below dust limit {dust_limit} after fee deduction")]
    NoChallengeableOutputs {
        /// The dust limit in satoshis
        dust_limit: u64,
    },

    /// Invalid challenge transaction parameters (e.g., parameter length mismatch)
    #[error("Invalid challenge transaction parameters: {reason}")]
    InvalidChallengeParameters {
        /// Reason why the challenge parameters are invalid
        reason: String,
    },

    /// Penalty transaction required (old state detected)
    #[error("Penalty transaction required: old state detected with nonce {old_nonce}, latest is {latest_nonce}")]
    PenaltyTransactionRequired {
        /// Nonce of the old state
        old_nonce: u32,
        /// Latest known nonce
        latest_nonce: u32,
    },

    /// Silent payment error
    #[error("Silent payment error: {reason}")]
    SilentPaymentError {
        /// Reason for the silent payment error
        reason: String,
    },

    /// Channel metadata exceeds maximum size
    #[error("Channel metadata too large: {size} bytes (maximum: {max_size} bytes)")]
    MetadataTooLarge {
        /// The size of the provided metadata in bytes
        size: usize,
        /// The maximum allowed metadata size in bytes
        max_size: usize,
    },
}

/// Errors that can occur during wallet operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WalletError {
    /// Channel not found in wallet
    #[error("Channel not found in wallet: {0:?}")]
    ChannelNotFound(ChannelId),

    /// Wallet nonce overflow
    #[error("Nonce overflow: cannot increment further")]
    WalletNonceOverflow,

    /// Wallet has too many channels
    #[error("Wallet has {channel_count} channels, but maximum supported is {max_channels}")]
    TooManyChannels {
        /// The number of channels in the wallet
        channel_count: usize,
        /// The maximum number of channels supported
        max_channels: usize,
    },

    /// Channel-related errors
    #[error(transparent)]
    Channel(#[from] ChannelError),
}

/// Errors that can occur during global state operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GlobalError {
    /// Invalid parameters provided to a global state operation
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    /// Wallet not found in global state
    #[error("Wallet not found in global state: {0:?}")]
    WalletNotFound(WalletId),

    /// Global state nonce overflow
    #[error("Global state nonce overflow: cannot increment further")]
    GlobalNonceOverflow,

    /// Internal database or storage error
    #[error("Internal error: {0}")]
    Internal(String),
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
