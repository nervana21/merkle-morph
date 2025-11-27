// SPDX-License-Identifier: CC0-1.0

//! Bitcoin transaction transition logic
//!
//! This module provides pure functions for applying state transitions to Bitcoin transactions.
//! All transition logic is deterministic and side-effect free.

use std::collections::HashSet;

use bitcoin::absolute::LockTime;
use bitcoin::consensus_validation::TxVerifyError;
use bitcoin::transaction::Version;
use bitcoin::{OutPoint, Transaction, TxOut, Txid};

use crate::btx::conversion::build_spent_outputs_closure;
use crate::btx::script::{detect_script_type, validate_segwit_spend};
use crate::btx::state::BitcoinTransaction;
use crate::btx::timelock::{extract_csv_blocks, validate_csv_timelock};
use crate::btx::truc::{
    is_child_transaction, is_truc_transaction, validate_truc_size,
    validate_truc_size_with_truc_context,
};
use crate::errors::{BtxError, Result};

/// Returns the maximum version between two versions.
///
/// Higher version numbers support more features (e.g., Version::TWO supports SegWit),
/// so using the maximum ensures all features from both transactions are available.
/// This is used when composing non-empty transactions. For identity preservation
/// (composing with empty transactions), the other transaction's version is used directly.
fn max_version(v1: Version, v2: Version) -> Version {
    // Version implements Ord, so we can compare directly
    v1.max(v2)
}

/// Returns the maximum lock_time between two lock times.
///
/// Higher lock_time values enforce stricter spending constraints, so using the maximum
/// ensures the composed transaction respects the most restrictive time lock from either
/// original transaction. This preserves security guarantees.
/// This is used when composing non-empty transactions. For identity preservation
/// (composing with empty transactions), the other transaction's lock_time is used directly.
fn max_lock_time(lt1: LockTime, lt2: LockTime) -> LockTime {
    let lt1_val = lt1.to_consensus_u32();
    let lt2_val = lt2.to_consensus_u32();
    if lt1_val >= lt2_val {
        lt1
    } else {
        lt2
    }
}

/// Composes two valid Bitcoin transactions
///
/// Composition concatenates the inputs and outputs of both transactions.
/// Both transactions must be valid for composition to succeed.
/// Script data is preserved when both transactions have scripts.
///
/// **Metadata composition (version and lock_time):**
/// - If one transaction is empty (identity morphism), the other transaction's metadata
///   is preserved to maintain the identity property: `compose(a, empty()) == a`
/// - If both transactions are non-empty, the maximum is used for both:
///   - Version: maximum preserves all features from both transactions
///   - LockTime: maximum preserves the most restrictive security constraint
///
/// This approach ensures mathematical properties (identity, associativity) are preserved
/// while maintaining security guarantees and feature compatibility.
///
/// # Arguments
/// * `tx1` - First transaction
/// * `tx2` - Second transaction
///
/// # Returns
/// * `Ok(BitcoinTransaction)` - Composed transaction
/// * `Err(BtxError::InvalidTransaction)` - If either transaction is invalid
/// * `Err(BtxError::InvalidComposition)` - If composition fails
pub fn compose(tx1: &BitcoinTransaction, tx2: &BitcoinTransaction) -> Result<BitcoinTransaction> {
    if !is_valid(tx1) {
        return Err(BtxError::InvalidTransaction.into());
    }
    if !is_valid(tx2) {
        return Err(BtxError::InvalidTransaction.into());
    }

    let mut inputs_data = tx1.inputs_data.clone();
    inputs_data.extend_from_slice(&tx2.inputs_data);

    let mut outputs = tx1.outputs.clone();
    outputs.extend_from_slice(&tx2.outputs);

    // Handle version and lock_time composition:
    // - If one transaction is empty (identity), preserve the other's metadata to maintain identity property
    // - Otherwise, use max() for both to balance features and security:
    //   * Version: maximum preserves all features from both transactions
    //   * LockTime: maximum preserves the most restrictive security constraint
    let (version, lock_time) = if tx1.inputs_data.is_empty() && tx1.outputs.is_empty() {
        // tx1 is empty (identity) - preserve tx2's metadata
        (tx2.version, tx2.lock_time)
    } else if tx2.inputs_data.is_empty() && tx2.outputs.is_empty() {
        // tx2 is empty (identity) - preserve tx1's metadata
        (tx1.version, tx1.lock_time)
    } else {
        // Both non-empty: use max() to preserve features and security
        (max_version(tx1.version, tx2.version), max_lock_time(tx1.lock_time, tx2.lock_time))
    };

    let composed = BitcoinTransaction::with_scripts(version, inputs_data, outputs, lock_time);

    // Verify the composed transaction is still valid
    if !is_valid(&composed) {
        return Err(BtxError::InvalidComposition.into());
    }

    // Validate TRUC size limits for v3 transactions
    let truc_txids = HashSet::new();

    let is_child = if is_truc_transaction(tx1) || is_truc_transaction(tx2) {
        is_child_transaction(&composed, &truc_txids)
    } else {
        false
    };

    validate_truc_size(&composed, is_child)?;

    // If both transactions had scripts, validate the composed transaction scripts
    if tx1.has_scripts() && tx2.has_scripts() {
        validate_p2tr_witnesses(&composed)?;
    }

    Ok(composed)
}

/// Applies a transaction transition
///
/// This is a pure function that validates and returns a new transaction state.
/// It follows the pattern from channel/wallet transitions.
///
/// # Arguments
/// * `tx` - The transaction to apply
/// * `validate_scripts` - If true, perform full script validation when scripts are present
///
/// # Returns
/// * `Ok(BitcoinTransaction)` - The validated transaction
/// * `Err(BtxError)` - If the transaction is invalid
pub fn apply_transaction(
    tx: BitcoinTransaction,
    validate_scripts: bool,
) -> Result<BitcoinTransaction> {
    apply_transaction_with_truc_context(tx, validate_scripts, &HashSet::new())
}

/// Applies a transaction transition with TRUC context for child detection
///
/// This function extends `apply_transaction` to support automatic child transaction
/// detection by providing a set of known TRUC transaction IDs.
///
/// # Arguments
/// * `tx` - The transaction to apply
/// * `validate_scripts` - If true, perform full script validation when scripts are present
/// * `truc_txids` - Set of transaction IDs that are known to be TRUC transactions
///
/// # Returns
/// * `Ok(BitcoinTransaction)` - The validated transaction
/// * `Err(BtxError)` - If the transaction is invalid
pub fn apply_transaction_with_truc_context(
    tx: BitcoinTransaction,
    validate_scripts: bool,
    truc_txids: &HashSet<Txid>,
) -> Result<BitcoinTransaction> {
    if !is_valid(&tx) {
        return Err(BtxError::InvalidTransaction.into());
    }

    validate_truc_size_with_truc_context(&tx, truc_txids)?;

    if validate_scripts && tx.has_scripts() {
        validate_with_scripts(&tx)?;
    }

    Ok(tx)
}

/// Returns an empty transaction
///
/// An empty transaction has no inputs and no outputs, representing
/// the identity morphism in the BTX category. This is the neutral element
/// for transaction composition.
///
/// # Returns
/// An empty `BitcoinTransaction` with no inputs or outputs
pub fn empty() -> BitcoinTransaction { BitcoinTransaction::new(vec![], vec![]) }

/// Validates a Bitcoin transaction
///
/// This function performs a simplified validation check that verifies:
/// - Total input value is greater than or equal to total output value (allowing for fees)
/// - Transaction has at least one input or output (non-empty)
///
/// # Limitations
///
/// This is a **simplified validation** that only checks value balance. For full Bitcoin
/// Core kernel transaction validation, you need to:
/// - Verify script execution (scriptSig/witness against scriptPubkey)
/// - Check transaction size limits
/// - Validate locktime and sequence numbers
/// - Verify signatures and cryptographic proofs
/// - Check for double-spending
///
/// To perform full validation, use Bitcoin Core's script verification with the actual
/// transaction data including scripts, witnesses, and spent outputs.
///
/// # Arguments
/// * `tx` - The transaction to validate
///
/// # Returns
/// `true` if the transaction passes basic value balance checks, `false` otherwise
pub fn is_valid(tx: &BitcoinTransaction) -> bool {
    // Empty transactions are considered valid (identity morphism)
    if tx.inputs_data.is_empty() && tx.outputs.is_empty() {
        return true;
    }

    let total_in: u64 = tx.inputs_data.iter().map(|id| id.utxo.value).sum();
    let total_out: u64 = tx.outputs.iter().map(|u| u.value).sum();

    // Inputs must be >= outputs
    total_in >= total_out
}

/// Validates a BitcoinTransaction with full script validation
///
/// This function performs full validation including script execution when
/// the transaction has script data.
///
/// # Arguments
/// * `btx` - The BitcoinTransaction to validate
///
/// # Returns
/// * `Ok(())` - Transaction is valid
/// * `Err(BtxError)` - Transaction validation failed
pub fn validate_with_scripts(btx: &BitcoinTransaction) -> Result<()> {
    // First check basic value balance
    if !is_valid(btx) {
        return Err(BtxError::InvalidTransaction.into());
    }

    // If we have script data, validate scripts
    if btx.has_scripts() {
        // Convert to bitcoin::Transaction for full validation
        let tx: Transaction = btx.clone().try_into()?;
        let spent_outputs = build_spent_outputs_closure(btx);
        verify_bitcoin_transaction(&tx, spent_outputs)?;
    }

    Ok(())
}

/// Validates a real Bitcoin transaction using Bitcoin Core consensus rules
///
/// This function performs full Bitcoin transaction validation including:
/// - Script execution (scriptSig/witness against scriptPubkey)
/// - Signature verification
/// - All consensus rules (P2SH, SegWit, etc.)
///
/// # Arguments
///
/// * `tx` - The Bitcoin transaction to validate
/// * `spent_outputs` - A function that returns the `TxOut` for each `OutPoint`
///   being spent. This should return `Some(TxOut)` for each input's `previous_output`,
///   or `None` if the output is not found (which will cause validation to fail).
///
/// # Returns
///
/// * `Ok(())` - Transaction is valid according to Bitcoin Core consensus rules
/// * `Err(BtxError)` - Transaction validation failed with specific error
///
/// # Example
///
/// ```no_run
/// # use bitcoin::{Transaction, OutPoint, TxOut};
/// # use merkle_morph::btx::transition::verify_bitcoin_transaction;
/// # fn example(tx: &Transaction, get_output: impl Fn(&OutPoint) -> Option<TxOut>) {
/// match verify_bitcoin_transaction(tx, get_output) {
///     Ok(()) => println!("Transaction is valid"),
///     Err(e) => println!("Validation failed: {}", e),
/// }
/// # }
/// ```
pub fn verify_bitcoin_transaction<S>(tx: &Transaction, spent_outputs: S) -> Result<()>
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    // Validate transaction structure first
    validate_transaction_structure(tx)?;

    // Then verify transaction with Bitcoin Core
    bitcoin::consensus_validation::verify_transaction(tx, spent_outputs).map_err(|e| {
        crate::Error::Btx(match e {
            TxVerifyError::UnknownSpentOutput(outpoint) => BtxError::MissingSpentOutput(outpoint),
            TxVerifyError::ScriptVerification(err) =>
                BtxError::ScriptExecutionFailed(format!("Script verification failed: {:?}", err)),
            // Handle any future variants added to the non-exhaustive enum
            _ => BtxError::InvalidTransaction,
        })
    })?;
    Ok(())
}

/// Validates basic transaction structure
///
/// This function performs basic structural validation:
/// - Transaction size limits (max 100KB for standard transactions)
/// - Empty transaction handling
/// - CSV sequence number structure extraction (without validation)
///
/// # Arguments
/// * `tx` - The transaction to validate
///
/// # Returns
/// * `Ok(())` - Transaction passes basic structure checks
/// * `Err(BtxError)` - Transaction violates structure requirements
pub fn validate_transaction_structure(tx: &Transaction) -> Result<()> {
    // Check transaction size (max 100KB for standard transactions)
    // Use serialized size as approximation
    let tx_size = bitcoin::consensus::encode::serialize(tx).len();
    const MAX_STANDARD_TX_SIZE: usize = 100_000;
    if tx_size > MAX_STANDARD_TX_SIZE {
        return Err(BtxError::TransactionSizeExceeded(tx_size, MAX_STANDARD_TX_SIZE).into());
    }

    // Check input/output count limits
    if tx.inputs.is_empty() && tx.outputs.is_empty() {
        // Empty transactions are valid (identity morphism)
        return Ok(());
    }

    // Validate locktime
    // Locktime validation is context-dependent (requires block height/time),
    // so we just check that it's a valid value
    // Full validation happens during script execution

    // Validate sequence numbers and CSV time locks
    for input in tx.inputs.iter() {
        let sequence = input.sequence;
        if sequence.to_consensus_u32() == 0xFFFFFFFF {
            // Sequence 0xFFFFFFFF means no relative lock time
            continue;
        }

        // Check for CSV time lock (basic structure validation)
        // Full CSV validation requires block heights and is done separately
        // We extract the required blocks here to verify the sequence number has valid CSV structure,
        // even though we don't use the value (actual validation happens in validate_consensus_rules_with_height)
        // Note: This only extracts the CSV structure, it doesn't validate the time lock itself
        if let Some(_required_blocks) = extract_csv_blocks(sequence) {
            // CSV is enabled - structure is valid
            // Actual time lock validation requires current_height and lock_height
        }
    }

    Ok(())
}

/// Validates consensus rules with block height for CSV validation
///
/// This extends `validate_transaction_structure` to validate CSV time locks when
/// block heights are provided.
///
/// # Arguments
/// * `tx` - The transaction to validate
/// * `current_height` - Current block height for CSV validation
/// * `lock_height` - Block height when transaction was first seen
///
/// # Returns
/// * `Ok(())` - Consensus rules are satisfied
/// * `Err(BtxError)` - Consensus rule violation (e.g., CSV time lock not met)
pub fn validate_consensus_rules_with_height(
    tx: &Transaction,
    current_height: Option<u32>,
    lock_height: Option<u32>,
) -> Result<()> {
    // First do basic structure validation
    validate_transaction_structure(tx)?;

    // If heights provided, validate CSV time locks
    if let (Some(current), Some(lock)) = (current_height, lock_height) {
        for (idx, input) in tx.inputs.iter().enumerate() {
            let sequence = input.sequence;
            if let Some(_required_blocks) = extract_csv_blocks(sequence) {
                // CSV is enabled, validate time lock
                if !validate_csv_timelock(sequence, current, lock) {
                    return Err(BtxError::InvalidSequence(idx).into());
                }
            }
        }
    }

    Ok(())
}

/// Validates P2TR/P2A outputs and P2TR witness structure for inputs
///
/// This function validates that:
/// - All outputs must be P2TR or P2A (enforced by this codebase)
/// - P2TR/P2A inputs must have valid witness structures
/// - Legacy and SegWit inputs are allowed (they can be spent to create P2TR/P2A outputs)
///
/// It performs simplified validation - full validation requires Bitcoin Core.
///
/// # Arguments
/// * `btx` - The BitcoinTransaction to validate
///
/// # Returns
/// * `Ok(())` - All outputs are P2TR/P2A and P2TR witnesses are valid
/// * `Err(BtxError)` - Validation failed (non-P2TR output or invalid P2TR witness)
pub fn validate_p2tr_witnesses(btx: &BitcoinTransaction) -> Result<()> {
    // Validate that all outputs are P2TR/P2A
    for (idx, output) in btx.outputs.iter().enumerate() {
        let script_pubkey = output.script_pubkey();
        let script_type = detect_script_type(&script_pubkey);

        match script_type {
            crate::btx::script::ScriptType::P2TR | crate::btx::script::ScriptType::P2A => {
                // Both P2TR and P2A are supported
            }
            _ => {
                return Err(crate::Error::Btx(BtxError::InvalidScriptPubkey(format!(
                    "Unsupported output type at output {}: expected P2TR or P2A, but detected {:?} (script length: {} bytes)",
                    idx, script_type, script_pubkey.len()
                ))));
            }
        }
    }

    // Validate inputs: allow any input type, but validate P2TR witness structure when input is P2TR
    for (idx, input_data) in btx.inputs_data.iter().enumerate() {
        let script_pubkey = input_data.utxo.script_pubkey();
        let script_type = detect_script_type(&script_pubkey);

        match script_type {
            crate::btx::script::ScriptType::P2TR | crate::btx::script::ScriptType::P2A => {
                // P2TR and P2A inputs must have valid witness structure
                if input_data.witness.is_empty() {
                    return Err(crate::Error::Btx(BtxError::InvalidWitness(
                        idx,
                        format!("{:?} witness is empty", script_type),
                    )));
                }
                validate_segwit_spend(&input_data.witness, &script_pubkey).map_err(|e| {
                    crate::Error::Btx(BtxError::InvalidWitness(
                        idx,
                        format!("{:?} input validation failed: {:?}", script_type, e),
                    ))
                })?;
            }
            crate::btx::script::ScriptType::Unknown => {
                // Legacy or SegWit inputs are allowed - they can be spent to create P2TR/P2A outputs.
                // Note: outputs must be P2TR or P2A, but inputs can be any valid Bitcoin script type.
                // Full validation of these inputs is done by Bitcoin Core in validate_with_scripts()
                // We just check that they have appropriate unlocking data
                if input_data.script_sig.is_empty() && input_data.witness.is_empty() {
                    return Err(crate::Error::Btx(BtxError::InvalidScriptPubkey(format!(
                        "Input {} has no unlocking script data (script_sig or witness)",
                        idx
                    ))));
                }
            }
        }
    }

    Ok(())
}

impl BitcoinTransaction {
    /// Returns an empty transaction (identity morphism)
    ///
    /// This is a convenience method that calls the module-level `empty()` function.
    pub fn empty() -> Self { empty() }

    /// Validates this transaction
    ///
    /// This is a convenience method that calls the module-level `is_valid()` function.
    pub fn is_valid(&self) -> bool { is_valid(self) }

    /// Composes this transaction with another
    ///
    /// This is a convenience method that calls the module-level `compose()` function.
    pub fn compose(&self, other: &BitcoinTransaction) -> Result<BitcoinTransaction> {
        compose(self, other)
    }

    /// Applies this transaction with optional script validation
    ///
    /// This is a convenience method that calls the module-level `apply_transaction()` function.
    pub fn apply(self, validate_scripts: bool) -> Result<BitcoinTransaction> {
        apply_transaction(self, validate_scripts)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Address, Amount, Network, OutPoint, ScriptPubKeyBuf, ScriptSigBuf, Sequence, TxIn, TxOut,
        Txid, Witness,
    };

    use super::*;
    use crate::btx::state::{TxInputData, Utxo};
    use crate::channel::test_utils::test_taproot_input_keypair;

    fn addr(s: &str) -> Address<NetworkUnchecked> { s.parse().expect("valid Bitcoin address") }

    fn create_valid_utxo(value: u64) -> Utxo {
        let txid = Txid::from_byte_array([1u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        Utxo::new(txid, 0, value, address)
    }

    fn create_p2tr_utxo(value: u64) -> Utxo {
        let (_, script_pubkey) = test_taproot_input_keypair();
        let txid = Txid::from_byte_array([2u8; 32]);
        let address = *Address::from_script(&script_pubkey, Network::Regtest)
            .expect("address")
            .as_unchecked();
        Utxo::with_script_pubkey(txid, 0, value, address, script_pubkey)
    }

    #[test]
    fn test_compose() -> Result<()> {
        let invalid_input1 = create_valid_utxo(1000);
        let invalid_output1 = create_valid_utxo(2000);
        let tx1_invalid = BitcoinTransaction::new(vec![invalid_input1], vec![invalid_output1]);
        let tx2_valid =
            BitcoinTransaction::new(vec![create_valid_utxo(2000)], vec![create_valid_utxo(1500)]);

        let result = compose(&tx1_invalid, &tx2_valid);

        assert!(result.is_err());

        let tx1_valid =
            BitcoinTransaction::new(vec![create_valid_utxo(1000)], vec![create_valid_utxo(500)]);
        let invalid_input2 = create_valid_utxo(2000);
        let invalid_output2 = create_valid_utxo(3000);
        let tx2_invalid = BitcoinTransaction::new(vec![invalid_input2], vec![invalid_output2]);

        let result = compose(&tx1_valid, &tx2_invalid);

        assert!(result.is_err());

        let empty_tx1 = empty();
        let tx2_non_empty =
            BitcoinTransaction::new(vec![create_valid_utxo(2000)], vec![create_valid_utxo(1500)]);

        let result = compose(&empty_tx1, &tx2_non_empty)?;

        assert_eq!(result.version, tx2_non_empty.version);
        assert_eq!(result.lock_time, tx2_non_empty.lock_time);

        let tx1_non_empty =
            BitcoinTransaction::new(vec![create_valid_utxo(1000)], vec![create_valid_utxo(500)]);
        let empty_tx2 = empty();

        let result = compose(&tx1_non_empty, &empty_tx2)?;

        assert_eq!(result.version, tx1_non_empty.version);
        assert_eq!(result.lock_time, tx1_non_empty.lock_time);

        let tx1_both = BitcoinTransaction::with_scripts(
            Version::ONE,
            vec![TxInputData::new(
                create_valid_utxo(1000),
                ScriptSigBuf::new(),
                Witness::new(),
                Sequence::MAX,
            )],
            vec![create_valid_utxo(500)],
            LockTime::from_consensus(100),
        );
        let tx2_both = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![TxInputData::new(
                create_valid_utxo(2000),
                ScriptSigBuf::new(),
                Witness::new(),
                Sequence::MAX,
            )],
            vec![create_valid_utxo(1500)],
            LockTime::from_consensus(200),
        );

        let result = compose(&tx1_both, &tx2_both)?;

        assert_eq!(result.version, Version::TWO);
        assert_eq!(result.lock_time.to_consensus_u32(), 200);

        let invalid_compose_input = create_valid_utxo(500);
        let invalid_compose_output = create_valid_utxo(2000);
        let tx1_compose_invalid =
            BitcoinTransaction::new(vec![invalid_compose_input], vec![invalid_compose_output]);
        let tx2_compose_valid =
            BitcoinTransaction::new(vec![create_valid_utxo(1000)], vec![create_valid_utxo(500)]);

        let result = compose(&tx1_compose_invalid, &tx2_compose_valid);

        assert!(result.is_err());

        let p2tr_utxo1 = create_p2tr_utxo(1000);
        let p2tr_output1 = create_p2tr_utxo(500);
        let mut witness1 = Witness::new();
        witness1.push(vec![0u8; 64]);
        let input_data1 = TxInputData::with_witness(p2tr_utxo1, witness1, Sequence::MAX);
        let tx1_with_scripts = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![input_data1],
            vec![p2tr_output1],
            LockTime::ZERO,
        );
        let p2tr_utxo2 = create_p2tr_utxo(2000);
        let p2tr_output2 = create_p2tr_utxo(1500);
        let mut witness2 = Witness::new();
        witness2.push(vec![0u8; 64]);
        let input_data2 = TxInputData::with_witness(p2tr_utxo2, witness2, Sequence::MAX);
        let tx2_with_scripts = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![input_data2],
            vec![p2tr_output2],
            LockTime::ZERO,
        );

        let result = compose(&tx1_with_scripts, &tx2_with_scripts)?;

        assert_eq!(result.inputs_data.len(), 2);
        assert_eq!(result.outputs.len(), 2);

        let tx1_no_scripts =
            BitcoinTransaction::new(vec![create_valid_utxo(1000)], vec![create_valid_utxo(500)]);
        let tx2_no_scripts =
            BitcoinTransaction::new(vec![create_valid_utxo(2000)], vec![create_valid_utxo(1500)]);

        let result = compose(&tx1_no_scripts, &tx2_no_scripts)?;

        assert_eq!(result.inputs_data.len(), 2);
        assert_eq!(result.outputs.len(), 2);
        Ok(())
    }

    #[test]
    fn test_apply_transaction() -> Result<()> {
        let invalid_input = create_valid_utxo(1000);
        let invalid_output = create_valid_utxo(2000);
        let tx_invalid = BitcoinTransaction::new(vec![invalid_input], vec![invalid_output]);

        let result = apply_transaction(tx_invalid, false);

        assert!(result.is_err());

        let p2tr_utxo = create_p2tr_utxo(1000);
        let p2tr_output = create_p2tr_utxo(500);
        let mut witness = Witness::new();
        witness.push(vec![0u8; 64]);
        let input_data = TxInputData::with_witness(p2tr_utxo, witness, Sequence::MAX);
        let tx_with_scripts = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![input_data],
            vec![p2tr_output],
            LockTime::ZERO,
        );

        let result = apply_transaction(tx_with_scripts.clone(), true)?;

        assert_eq!(result.inputs_data.len(), 1);
        assert_eq!(result.outputs.len(), 1);

        let tx_no_scripts =
            BitcoinTransaction::new(vec![create_valid_utxo(1000)], vec![create_valid_utxo(500)]);

        let result = apply_transaction(tx_no_scripts.clone(), false)?;

        assert_eq!(result.inputs_data.len(), tx_no_scripts.inputs_data.len());
        assert_eq!(result.outputs.len(), tx_no_scripts.outputs.len());
        Ok(())
    }

    #[test]
    fn test_empty() {
        let result = empty();

        assert_eq!(result.inputs_data.len(), 0);
        assert_eq!(result.outputs.len(), 0);
    }

    #[test]
    fn test_is_valid() {
        let tx_empty = BitcoinTransaction::new(vec![], vec![]);

        let result = is_valid(&tx_empty);

        assert!(result);

        let tx_valid =
            BitcoinTransaction::new(vec![create_valid_utxo(1000)], vec![create_valid_utxo(500)]);

        let result = is_valid(&tx_valid);

        assert!(result);

        let tx_invalid =
            BitcoinTransaction::new(vec![create_valid_utxo(1000)], vec![create_valid_utxo(2000)]);

        let result = is_valid(&tx_invalid);

        assert!(!result);
    }

    #[test]
    fn test_validate_with_scripts() -> Result<()> {
        let invalid_input = create_valid_utxo(1000);
        let invalid_output = create_valid_utxo(2000);
        let tx_invalid = BitcoinTransaction::new(vec![invalid_input], vec![invalid_output]);

        let result = validate_with_scripts(&tx_invalid);

        assert!(result.is_err());

        let p2tr_utxo = create_p2tr_utxo(1000);
        let p2tr_output = create_p2tr_utxo(500);
        let mut witness = Witness::new();
        witness.push(vec![0u8; 64]);
        let input_data = TxInputData::with_witness(p2tr_utxo, witness, Sequence::MAX);
        let tx_with_scripts = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![input_data],
            vec![p2tr_output],
            LockTime::ZERO,
        );

        validate_with_scripts(&tx_with_scripts)?;

        let tx_no_scripts =
            BitcoinTransaction::new(vec![create_valid_utxo(1000)], vec![create_valid_utxo(500)]);

        validate_with_scripts(&tx_no_scripts)?;
        Ok(())
    }

    #[test]
    fn test_verify_bitcoin_transaction() -> Result<()> {
        let large_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![],
            outputs: vec![TxOut {
                amount: Amount::from_sat(1000).expect("1000 is in range"),
                script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0u8; 100_001]),
            }],
        };

        let result = verify_bitcoin_transaction(&large_tx, |_| None);

        assert!(result.is_err());

        let (_, p2tr_script) = test_taproot_input_keypair();
        let missing_outpoint = OutPoint { txid: Txid::from_byte_array([2u8; 32]), vout: 0 };
        let tx_missing = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: missing_outpoint,
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(500).expect("500 is in range"),
                script_pubkey: p2tr_script.clone(),
            }],
        };

        let result = verify_bitcoin_transaction(&tx_missing, |_| None);

        assert!(result.is_err());
        assert!(matches!(result, Err(crate::Error::Btx(BtxError::MissingSpentOutput(_)))));

        let tx_empty = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![],
            outputs: vec![],
        };

        verify_bitcoin_transaction(&tx_empty, |_| None)?;
        Ok(())
    }

    #[test]
    fn test_validate_transaction_structure() -> Result<()> {
        let large_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![],
            outputs: vec![TxOut {
                amount: Amount::from_sat(1000).expect("1000 is in range"),
                script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0u8; 100_001]),
            }],
        };

        let result = validate_transaction_structure(&large_tx);

        assert!(result.is_err());

        let tx_empty = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![],
            outputs: vec![],
        };

        validate_transaction_structure(&tx_empty)?;

        let (_, p2tr_script) = test_taproot_input_keypair();
        let tx_sequence_max = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(500).expect("500 is in range"),
                script_pubkey: p2tr_script.clone(),
            }],
        };

        validate_transaction_structure(&tx_sequence_max)?;

        let tx_csv = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([2u8; 32]), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::from_consensus(0x8000_0090),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(500).expect("500 is in range"),
                script_pubkey: p2tr_script.clone(),
            }],
        };

        validate_transaction_structure(&tx_csv)?;

        let tx_normal = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([3u8; 32]), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::from_consensus(0x0000_0000),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(500).expect("500 is in range"),
                script_pubkey: p2tr_script,
            }],
        };

        validate_transaction_structure(&tx_normal)?;
        Ok(())
    }

    #[test]
    fn test_validate_consensus_rules_with_height() -> Result<()> {
        let large_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![],
            outputs: vec![TxOut {
                amount: Amount::from_sat(1000).expect("1000 is in range"),
                script_pubkey: ScriptPubKeyBuf::from_bytes(vec![0u8; 100_001]),
            }],
        };

        let result = validate_consensus_rules_with_height(&large_tx, Some(1000), Some(500));

        assert!(result.is_err());

        let (_, p2tr_script) = test_taproot_input_keypair();
        let tx_csv_fail = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([1u8; 32]), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::from_consensus(0x8000_0090),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(500).expect("500 is in range"),
                script_pubkey: p2tr_script.clone(),
            }],
        };

        let result = validate_consensus_rules_with_height(&tx_csv_fail, Some(1000), Some(1000));

        assert!(result.is_err());

        let tx_csv_pass = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([2u8; 32]), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::from_consensus(0x8000_0090),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(500).expect("500 is in range"),
                script_pubkey: p2tr_script,
            }],
        };

        validate_consensus_rules_with_height(&tx_csv_pass, Some(1144), Some(1000))?;

        let (_, p2tr_script2) = test_taproot_input_keypair();
        let tx_no_heights = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([3u8; 32]), vout: 0 },
                script_sig: ScriptSigBuf::new(),
                sequence: Sequence::from_consensus(0x8000_0090),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(500).expect("500 is in range"),
                script_pubkey: p2tr_script2,
            }],
        };

        validate_consensus_rules_with_height(&tx_no_heights, None, Some(1000))?;
        Ok(())
    }

    #[test]
    fn test_validate_p2tr_witnesses() -> Result<()> {
        let unknown_script = ScriptPubKeyBuf::from_bytes(vec![0x00u8, 0x01u8, 0x02u8]);
        let txid = Txid::from_byte_array([1u8; 32]);
        let address = addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let unknown_output = Utxo::with_script_pubkey(txid, 0, 1000, address, unknown_script);
        let tx_non_p2tr_output =
            BitcoinTransaction::new(vec![create_valid_utxo(2000)], vec![unknown_output]);

        let result = validate_p2tr_witnesses(&tx_non_p2tr_output);

        assert!(result.is_err());

        let p2tr_utxo = create_p2tr_utxo(1000);
        let p2tr_output = create_p2tr_utxo(500);
        let empty_witness = Witness::new();
        let input_data_empty = TxInputData::with_witness(p2tr_utxo, empty_witness, Sequence::MAX);
        let tx_empty_witness = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![input_data_empty],
            vec![p2tr_output],
            LockTime::ZERO,
        );

        let result = validate_p2tr_witnesses(&tx_empty_witness);

        assert!(result.is_err());

        let p2tr_utxo2 = create_p2tr_utxo(2000);
        let p2tr_output2 = create_p2tr_utxo(1500);
        let mut invalid_witness = Witness::new();
        invalid_witness.push(vec![0u8; 32]);
        invalid_witness.push(vec![0u8; 33]);
        let input_data_invalid =
            TxInputData::with_witness(p2tr_utxo2, invalid_witness, Sequence::MAX);
        let tx_invalid_witness = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![input_data_invalid],
            vec![p2tr_output2],
            LockTime::ZERO,
        );

        let result = validate_p2tr_witnesses(&tx_invalid_witness);

        assert!(result.is_err());

        let unknown_utxo = Utxo::with_script_pubkey(
            Txid::from_byte_array([4u8; 32]),
            0,
            1000,
            addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            ScriptPubKeyBuf::from_bytes(vec![0x00u8, 0x01u8, 0x02u8]),
        );
        let p2tr_output3 = create_p2tr_utxo(500);
        let input_data_no_unlock =
            TxInputData::new(unknown_utxo, ScriptSigBuf::new(), Witness::new(), Sequence::MAX);
        let tx_no_unlock = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![input_data_no_unlock],
            vec![p2tr_output3],
            LockTime::ZERO,
        );

        let result = validate_p2tr_witnesses(&tx_no_unlock);

        assert!(result.is_err());

        let p2tr_utxo3 = create_p2tr_utxo(1000);
        let p2tr_output4 = create_p2tr_utxo(500);
        let mut valid_witness = Witness::new();
        valid_witness.push(vec![0u8; 64]);
        let input_data_valid = TxInputData::with_witness(p2tr_utxo3, valid_witness, Sequence::MAX);
        let tx_valid = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![input_data_valid],
            vec![p2tr_output4],
            LockTime::ZERO,
        );

        validate_p2tr_witnesses(&tx_valid)?;
        Ok(())
    }
}
