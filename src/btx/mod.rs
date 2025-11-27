// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transaction category module
//!
//! This module provides the BitcoinTransactionCategory (BTX) implementation,
//! which represents Bitcoin transactions as categorical morphisms. A Bitcoin
//! transaction consumes UTXOs as inputs and produces new UTXOs as outputs.

pub mod chain_oracle;
pub mod commitment;
pub mod conversion;
pub mod script;
pub mod state;
pub mod timelock;
pub mod transition;
pub mod truc;

pub use chain_oracle::{ChainOracle, MockChainOracle};
pub use commitment::{compute_btx_commitment, compute_commitment, BtxCommitment};
pub use conversion::{
    build_spent_outputs_closure, derive_address_from_script, transaction_to_btx, txout_to_utxo,
    utxo_to_txout,
};
pub use script::{
    build_funding_info, build_miniscript_funding_script, detect_script_type, validate_segwit_spend,
    validate_taproot_multisig_spend, MiniscriptFundingInfo, ScriptType,
};
pub use state::{BitcoinTransaction, TxInputData, Utxo};
pub use timelock::{
    compute_sequence_for_blocks, extract_csv_blocks, validate_csv_timelock,
    FORCE_CLOSE_TIMEOUT_BLOCKS,
};
pub use transition::{
    apply_transaction, apply_transaction_with_truc_context, compose, empty, is_valid,
    validate_consensus_rules_with_height, validate_p2tr_witnesses, validate_transaction_structure,
    validate_with_scripts, verify_bitcoin_transaction,
};
pub use truc::{
    is_child_transaction, is_truc_transaction, validate_truc_size,
    validate_truc_size_with_truc_context,
};

pub use crate::types::{TRUC_CHILD_MAX_VSIZE, TRUC_MAX_VSIZE};
