//! Bitcoin transaction category module
//!
//! This module provides the BitcoinTransactionCategory (BTX) implementation,
//! which represents Bitcoin transactions as categorical morphisms. A Bitcoin
//! transaction consumes UTXOs as inputs and produces new UTXOs as outputs.

pub mod commitment;
pub mod conversion;
pub mod script;
pub mod state;
pub mod timelock;
pub mod transition;

pub use commitment::{compute_btx_commitment, compute_commitment, BtxCommitment};
pub use conversion::{
    build_spent_outputs_closure, derive_address_from_script, transaction_to_btx, txout_to_utxo,
    utxo_to_txout,
};
pub use script::{
    build_2_of_2_multisig_script, build_funding_info, build_miniscript_funding_script,
    build_taproot_address, detect_script_type, script_pubkey_from_address,
    validate_miniscript_spend, validate_p2pkh_spend, validate_p2sh_spend, validate_segwit_spend,
    validate_taproot_multisig_spend, MiniscriptFundingInfo, ScriptType,
};
pub use state::{BitcoinTransaction, TxInputData, Utxo};
pub use timelock::{
    compute_sequence_for_blocks, extract_csv_blocks, validate_csv_timelock,
    FORCE_CLOSE_TIMEOUT_BLOCKS,
};
pub use transition::{
    apply_transaction, compose, empty, is_valid, validate_consensus_rules,
    validate_consensus_rules_with_height, validate_p2tr_witnesses, validate_with_scripts,
    verify_bitcoin_transaction,
};
