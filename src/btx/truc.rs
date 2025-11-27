// SPDX-License-Identifier: CC0-1.0

//! TRUC (Topologically Restricted Until Confirmation) transaction support
//!
//! This module provides constants and validation functions for Bitcoin version 3
//! TRUC transactions, which are designed for package relay and CPFP (Child Pays For Parent).
//!
//! TRUC transactions enable zero-fee funding transactions that can be paid for
//! by child transactions via package relay, making them ideal for Merkle Morph channel funding.

use std::collections::HashSet;

use bitcoin::transaction::Version;
use bitcoin::Txid;

use crate::btx::state::BitcoinTransaction;
use crate::errors::{BtxError, Result};
use crate::types::{
    TRUC_CHILD_MAX_VSIZE, TRUC_MAX_VSIZE, TX_LOCKTIME_SIZE, TX_OUTPOINT_SIZE, TX_SEQUENCE_SIZE,
    TX_VALUE_SIZE, TX_VERSION_SIZE, TX_WEIGHT_BASE_MULTIPLIER, TX_WITNESS_MARKER_SIZE,
    WITNESS_SCALE_FACTOR,
};

/// Checks if a transaction is a TRUC transaction (version 3)
///
/// # Arguments
/// * `tx` - The transaction to check
///
/// # Returns
/// `true` if the transaction version is 3, `false` otherwise
pub fn is_truc_transaction(tx: &BitcoinTransaction) -> bool { tx.version == Version::THREE }

/// Checks if a transaction is a TRUC child transaction (spends from unconfirmed TRUC outputs)
///
/// A child transaction is one that spends outputs from unconfirmed TRUC (v3) transactions.
/// This function checks if any input's previous transaction ID is in the set of known TRUC transaction IDs.
///
/// # Arguments
/// * `tx` - The transaction to check
/// * `truc_txids` - Set of transaction IDs that are known to be TRUC transactions
///
/// # Returns
/// `true` if the transaction spends from any unconfirmed TRUC output, `false` otherwise
///
/// # Example
///
/// ```rust
/// use merkle_morph::btx::state::BitcoinTransaction;
/// use merkle_morph::btx::truc::is_child_transaction;
/// use bitcoin::hashes::Hash;
/// use std::collections::HashSet;
///
/// let tx = BitcoinTransaction::new(vec![], vec![]);
/// let truc_txids: HashSet<bitcoin::Txid> = HashSet::new();
/// let is_child = is_child_transaction(&tx, &truc_txids);
/// ```
pub fn is_child_transaction(tx: &BitcoinTransaction, truc_txids: &HashSet<Txid>) -> bool {
    if truc_txids.is_empty() {
        return false;
    }

    for input_data in &tx.inputs_data {
        let prev_txid = input_data.utxo.txid();
        if truc_txids.contains(prev_txid) {
            return true;
        }
    }

    false
}

/// Validates that a TRUC transaction respects size limits
///
/// For parent transactions (not spending unconfirmed TRUC outputs), the limit is TRUC_MAX_VSIZE.
/// For child transactions (spending unconfirmed TRUC outputs), the limit is TRUC_CHILD_MAX_VSIZE.
///
/// # Arguments
/// * `tx` - The transaction to validate
/// * `is_child` - If `true`, validates against TRUC_CHILD_MAX_VSIZE, otherwise TRUC_MAX_VSIZE
///
/// # Returns
/// * `Ok(())` - Transaction size is within limits
/// * `Err(BtxError)` - Transaction exceeds size limits
pub fn validate_truc_size(tx: &BitcoinTransaction, is_child: bool) -> Result<()> {
    if !is_truc_transaction(tx) {
        return Ok(());
    }

    // Calculate weight, then convert to vsize for comparison
    // Empty transactions (no inputs) are not valid Bitcoin transactions
    let weight = transaction_weight(tx).ok_or(BtxError::InvalidTransaction)?;
    let vsize = weight.div_ceil(WITNESS_SCALE_FACTOR);

    let max_vsize = if is_child { TRUC_CHILD_MAX_VSIZE } else { TRUC_MAX_VSIZE };

    if vsize > max_vsize {
        return Err(BtxError::InvalidTransaction.into());
    }

    Ok(())
}

/// Validates TRUC size limits with TRUC context for automatic child transaction detection
///
/// This function automatically detects if a transaction is a child transaction
/// by checking if it spends from unconfirmed TRUC outputs, then validates
/// the appropriate size limit.
///
/// # Arguments
/// * `tx` - The transaction to validate
/// * `truc_txids` - Set of transaction IDs that are known to be TRUC transactions
///
/// # Returns
/// * `Ok(())` - Transaction size is within limits
/// * `Err(BtxError)` - Transaction exceeds size limits or is not a TRUC transaction
///
/// # Example
///
/// ```rust
/// use merkle_morph::btx::state::BitcoinTransaction;
/// use merkle_morph::btx::truc::validate_truc_size_with_truc_context;
/// use std::collections::HashSet;
///
/// let tx = BitcoinTransaction::new(vec![], vec![]);
/// let truc_txids: HashSet<bitcoin::Txid> = HashSet::new();
/// let result = validate_truc_size_with_truc_context(&tx, &truc_txids);
/// ```
pub fn validate_truc_size_with_truc_context(
    tx: &BitcoinTransaction,
    truc_txids: &HashSet<Txid>,
) -> Result<()> {
    if !is_truc_transaction(tx) {
        return Ok(());
    }

    let is_child = is_child_transaction(tx, truc_txids);

    validate_truc_size(tx, is_child)
}

/// Calculates the size of a variable-length integer (VarInt) encoding
///
/// Bitcoin uses variable-length integers to encode counts and lengths.
/// This function returns the number of bytes needed to encode a value.
///
/// # Arguments
/// * `value` - The value to encode
///
/// # Returns
/// The number of bytes needed to encode the value as a VarInt
fn varint_size(value: u64) -> usize {
    match value {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x10000..=0xFFFFFFFF => 5,
        _ => 9,
    }
}

/// Calculates the weight of a transaction
///
/// This function calculates the transaction weight by summing the sizes of all transaction
/// components, properly accounting for VarInt encoding.
///
/// # Arguments
/// * `tx` - The transaction to calculate weight for
///
/// # Returns
/// * `Some(usize)` - The exact weight if the transaction has inputs
/// * `None` - If transaction has no inputs (empty transactions are not valid Bitcoin transactions)
///
/// # Note
/// This function works correctly for transactions of any size, properly handling VarInt
/// encoding for input/output counts, script lengths, and witness data. It works even when
/// scripts are empty (uses length 0).
fn transaction_weight(tx: &BitcoinTransaction) -> Option<usize> {
    if tx.inputs_data.is_empty() {
        return None;
    }

    // Calculate non-witness size (base transaction data without witness)
    // Start with version and locktime, then add:
    // - input count (VarInt) + inputs (without witness)
    // - output count (VarInt) + outputs
    let mut non_witness_size = TX_VERSION_SIZE + TX_LOCKTIME_SIZE;

    // Add VarInt size for input count
    non_witness_size += varint_size(tx.inputs_data.len() as u64);

    // Add inputs (without witness data)
    for input in &tx.inputs_data {
        non_witness_size += TX_OUTPOINT_SIZE;
        non_witness_size += varint_size(input.script_sig.len() as u64);
        non_witness_size += input.script_sig.len();
        non_witness_size += TX_SEQUENCE_SIZE;
    }

    // Add VarInt size for output count
    non_witness_size += varint_size(tx.outputs.len() as u64);

    // Add outputs
    for output in &tx.outputs {
        non_witness_size += TX_VALUE_SIZE;
        let script_len = output.script_pubkey().len();
        non_witness_size += varint_size(script_len as u64);
        non_witness_size += script_len;
    }

    // Calculate total size (non-witness + witness data)
    let mut total_size = non_witness_size;

    // Add witness data if present
    let has_witness = tx.inputs_data.iter().any(|input| !input.witness.is_empty());
    if has_witness {
        // Add witness marker (0x00) and flag (0x01)
        total_size += TX_WITNESS_MARKER_SIZE;

        // Add witness data for each input
        for input in &tx.inputs_data {
            // Witness stack item count (VarInt)
            total_size += varint_size(input.witness.len() as u64);

            // Each witness item
            for witness_item in &input.witness {
                total_size += varint_size(witness_item.len() as u64);
                total_size += witness_item.len();
            }
        }
    }

    // Calculate weight: weight = non_witness_size * TX_WEIGHT_BASE_MULTIPLIER + total_size
    // This formula accounts for the fact that witness data is counted at 1/4 weight
    let weight = non_witness_size * TX_WEIGHT_BASE_MULTIPLIER + total_size;

    Some(weight)
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::script::ScriptSigBuf;
    use bitcoin::transaction::Version;
    use bitcoin::{Address, Sequence, Txid, Witness};

    use super::*;
    use crate::btx::state::{TxInputData, Utxo};

    fn addr(s: &str) -> Address<NetworkUnchecked> { s.parse().expect("valid Bitcoin address") }

    #[test]
    fn test_is_truc_transaction() {
        let txid = Txid::from_byte_array([1u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let input = Utxo::new(txid, 0, 1000, address);
        let output = Utxo::new(txid, 0, 500, address);
        let tx_v3 = BitcoinTransaction::new(vec![input.clone()], vec![output.clone()]);

        let result = is_truc_transaction(&tx_v3);

        assert!(result);

        let txid2 = Txid::from_byte_array([2u8; 32]);
        let address2 = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let input2 = Utxo::new(txid2, 0, 1000, address2);
        let output2 = Utxo::new(txid2, 0, 500, address2);
        let tx_v2 = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![TxInputData::new(input2, ScriptSigBuf::new(), Witness::new(), Sequence::MAX)],
            vec![output2],
            LockTime::ZERO,
        );

        let result = is_truc_transaction(&tx_v2);

        assert!(!result);
    }

    #[test]
    fn test_is_child_transaction() {
        let txid1 = Txid::from_byte_array([1u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let input = Utxo::new(txid1, 0, 1000, address);
        let output = Utxo::new(txid1, 0, 500, address);
        let tx = BitcoinTransaction::new(vec![input], vec![output]);
        let truc_txids: HashSet<Txid> = HashSet::new();

        let result = is_child_transaction(&tx, &truc_txids);

        assert!(!result);

        let txid3 = Txid::from_byte_array([3u8; 32]);
        let truc_txid = Txid::from_byte_array([4u8; 32]);
        let address2 = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let input_with_truc = Utxo::new(truc_txid, 0, 1000, address2);
        let output2 = Utxo::new(txid3, 0, 500, address2);
        let tx_with_truc_input = BitcoinTransaction::new(vec![input_with_truc], vec![output2]);
        let mut truc_txids_with_match = HashSet::new();
        truc_txids_with_match.insert(truc_txid);

        let result = is_child_transaction(&tx_with_truc_input, &truc_txids_with_match);

        assert!(result);

        let txid5 = Txid::from_byte_array([5u8; 32]);
        let txid6 = Txid::from_byte_array([6u8; 32]);
        let address3 = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let input_no_match = Utxo::new(txid5, 0, 1000, address3);
        let output3 = Utxo::new(txid6, 0, 500, address3);
        let tx_no_match = BitcoinTransaction::new(vec![input_no_match], vec![output3]);
        let mut truc_txids_no_match = HashSet::new();
        truc_txids_no_match.insert(truc_txid);

        let result = is_child_transaction(&tx_no_match, &truc_txids_no_match);

        assert!(!result);
    }

    #[test]
    fn test_validate_truc_size() -> Result<()> {
        let txid1 = Txid::from_byte_array([1u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let input = Utxo::new(txid1, 0, 1000, address);
        let output = Utxo::new(txid1, 0, 500, address);
        let tx_non_truc = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![TxInputData::new(input, ScriptSigBuf::new(), Witness::new(), Sequence::MAX)],
            vec![output],
            LockTime::ZERO,
        );

        let result = validate_truc_size(&tx_non_truc, false);

        assert!(result.is_ok());

        let txid2 = Txid::from_byte_array([2u8; 32]);
        let address2 = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let input2 = Utxo::new(txid2, 0, 1000, address2);
        let output2 = Utxo::new(txid2, 0, 500, address2);
        let tx_truc_small = BitcoinTransaction::new(vec![input2], vec![output2]);

        let result = validate_truc_size(&tx_truc_small, false);

        assert!(result.is_ok());

        let txid3 = Txid::from_byte_array([3u8; 32]);
        let address3 = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let input3 = Utxo::new(txid3, 0, 1000, address3);
        let large_script = bitcoin::script::ScriptPubKeyBuf::from_bytes(vec![0u8; TRUC_MAX_VSIZE]);
        let output3 = Utxo::with_script_pubkey(txid3, 0, 500, address3, large_script);
        let input_data3 =
            TxInputData::new(input3, ScriptSigBuf::new(), Witness::new(), Sequence::MAX);
        let tx_truc_large = BitcoinTransaction::with_scripts(
            Version::THREE,
            vec![input_data3],
            vec![output3],
            LockTime::ZERO,
        );

        let result = validate_truc_size(&tx_truc_large, false);

        assert!(result.is_err());

        let txid4 = Txid::from_byte_array([4u8; 32]);
        let address4 = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let input4 = Utxo::new(txid4, 0, 1000, address4);
        let output4 = Utxo::new(txid4, 0, 500, address4);
        let tx_truc_child_small = BitcoinTransaction::new(vec![input4], vec![output4]);

        let result = validate_truc_size(&tx_truc_child_small, true);

        assert!(result.is_ok());

        let txid5 = Txid::from_byte_array([5u8; 32]);
        let address5 = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let input5 = Utxo::new(txid5, 0, 1000, address5);
        let large_script2 =
            bitcoin::script::ScriptPubKeyBuf::from_bytes(vec![0u8; TRUC_CHILD_MAX_VSIZE]);
        let output5 = Utxo::with_script_pubkey(txid5, 0, 500, address5, large_script2);
        let input_data5 =
            TxInputData::new(input5, ScriptSigBuf::new(), Witness::new(), Sequence::MAX);
        let tx_truc_child_large = BitcoinTransaction::with_scripts(
            Version::THREE,
            vec![input_data5],
            vec![output5],
            LockTime::ZERO,
        );

        let result = validate_truc_size(&tx_truc_child_large, true);

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_validate_truc_size_with_truc_context() -> Result<()> {
        let txid1 = Txid::from_byte_array([1u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let input = Utxo::new(txid1, 0, 1000, address);
        let output = Utxo::new(txid1, 0, 500, address);
        let tx_non_truc = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![TxInputData::new(input, ScriptSigBuf::new(), Witness::new(), Sequence::MAX)],
            vec![output],
            LockTime::ZERO,
        );
        let truc_txids: HashSet<Txid> = HashSet::new();

        let result = validate_truc_size_with_truc_context(&tx_non_truc, &truc_txids);

        assert!(result.is_ok());

        let truc_txid = Txid::from_byte_array([2u8; 32]);
        let txid3 = Txid::from_byte_array([3u8; 32]);
        let address2 = addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2");
        let input_child = Utxo::new(truc_txid, 0, 1000, address2);
        let output2 = Utxo::new(txid3, 0, 500, address2);
        let tx_truc_child = BitcoinTransaction::new(vec![input_child], vec![output2]);
        let mut truc_txids_child = HashSet::new();
        truc_txids_child.insert(truc_txid);

        let result = validate_truc_size_with_truc_context(&tx_truc_child, &truc_txids_child);

        assert!(result.is_ok());

        let txid4 = Txid::from_byte_array([4u8; 32]);
        let address3 = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let input_parent = Utxo::new(txid4, 0, 1000, address3);
        let output3 = Utxo::new(txid4, 0, 500, address3);
        let tx_truc_parent = BitcoinTransaction::new(vec![input_parent], vec![output3]);
        let truc_txids_parent: HashSet<Txid> = HashSet::new();

        let result = validate_truc_size_with_truc_context(&tx_truc_parent, &truc_txids_parent);

        assert!(result.is_ok());
        Ok(())
    }
}
