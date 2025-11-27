#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Bitcoin transaction category module
//!
//! This module provides the BitcoinTransactionCategory (BTX) implementation,
//! which represents Bitcoin transactions as categorical morphisms. A Bitcoin
//! transaction consumes UTXOs as inputs and produces new UTXOs as outputs.

pub mod commitment;
pub mod conversion;
pub mod script;
pub mod state;
pub mod transition;

pub use commitment::{compute_btx_commitment, compute_commitment, BtxCommitment};
pub use conversion::{
    build_spent_outputs_closure, derive_address_from_script, transaction_to_btx, txout_to_utxo,
    utxo_to_txout,
};
pub use script::{
    detect_script_type, script_pubkey_from_address, validate_p2pkh_spend, validate_p2sh_spend,
    validate_segwit_spend, ScriptType,
};
pub use state::{BitcoinTransaction, TxInputData, Utxo};
pub use transition::{
    apply_transaction, compose, empty, is_valid, validate_consensus_rules,
    validate_script_execution, validate_with_scripts, verify_bitcoin_transaction,
};
