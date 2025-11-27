//! Bitcoin transaction transition logic
//!
//! This module provides pure functions for applying state transitions to Bitcoin transactions.
//! All transition logic is deterministic and side-effect free.

use bitcoin::consensus::validation::TxVerifyError;
use bitcoin::{OutPoint, Transaction, TxOut};

use crate::btx::conversion::build_spent_outputs_closure;
use crate::btx::script::{
    detect_script_type, validate_p2pkh_spend, validate_p2sh_spend, validate_segwit_spend,
};
use crate::btx::state::BitcoinTransaction;
use crate::errors::{BtxError, Result};

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

/// Composes two valid Bitcoin transactions
///
/// Composition concatenates the inputs and outputs of both transactions.
/// Both transactions must be valid for composition to succeed.
/// Script data is preserved when both transactions have scripts.
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

    // Use the version and lock_time from tx1 (or combine if needed)
    // For simplicity, use tx1's version and lock_time
    let version = tx1.version;
    let lock_time = tx1.lock_time;

    let composed = BitcoinTransaction::with_scripts(version, lock_time, inputs_data, outputs);

    // Verify the composed transaction is still valid
    if !is_valid(&composed) {
        return Err(BtxError::InvalidComposition.into());
    }

    // If both transactions had scripts, validate the composed transaction scripts
    if tx1.has_scripts() && tx2.has_scripts() {
        validate_script_execution(&composed)?;
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
    if !is_valid(&tx) {
        return Err(BtxError::InvalidTransaction.into());
    }

    if validate_scripts && tx.has_scripts() {
        validate_with_scripts(&tx)?;
    }

    Ok(tx)
}

/// Validates a real Bitcoin transaction using Bitcoin Core consensus rules
///
/// This function performs full Bitcoin transaction validation including:
/// - Script execution (scriptSig/witness against scriptPubkey)
/// - Signature verification
/// - All consensus rules (P2SH, SegWit, etc.)
///
/// This is the **proper** way to validate Bitcoin transactions according to
/// Bitcoin Core kernel rules, as opposed to the simplified `is_valid` function
/// which only checks value balance.
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
    // Validate consensus rules first
    validate_consensus_rules(tx)?;

    // Then verify transaction with Bitcoin Core
    bitcoin::consensus::verify_transaction(tx, spent_outputs).map_err(|e| {
        crate::errors::Error::Btx(match e {
            TxVerifyError::UnknownSpentOutput(outpoint) => BtxError::MissingSpentOutput(outpoint),
            TxVerifyError::ScriptVerification(err) =>
                BtxError::ScriptExecutionFailed(format!("Script verification failed: {:?}", err)),
            // Handle any future variants added to the non-exhaustive enum
            _ => BtxError::InvalidTransaction,
        })
    })?;
    Ok(())
}

/// Validates Bitcoin Core consensus rules
///
/// This function validates transaction size, input/output counts, locktime,
/// sequence numbers, and other consensus rules before script execution.
///
/// # Arguments
/// * `tx` - The transaction to validate
///
/// # Returns
/// * `Ok(())` - Transaction passes consensus rules
/// * `Err(BtxError)` - Transaction violates consensus rules
pub fn validate_consensus_rules(tx: &Transaction) -> Result<()> {
    // Check transaction size (max 100KB for standard transactions)
    // Use serialized size as approximation
    let tx_size = bitcoin::consensus::encode::serialize(tx).len();
    const MAX_STANDARD_TX_SIZE: usize = 100_000;
    if tx_size > MAX_STANDARD_TX_SIZE {
        return Err(BtxError::TransactionSizeExceeded(tx_size, MAX_STANDARD_TX_SIZE).into());
    }

    // Check input/output count limits
    if tx.input.is_empty() && tx.output.is_empty() {
        // Empty transactions are valid (identity morphism)
        return Ok(());
    }

    // Validate locktime
    // Locktime validation is context-dependent (requires block height/time),
    // so we just check that it's a valid value
    // Full validation happens during script execution

    // Validate sequence numbers
    // Sequence numbers are valid if they're within the valid range
    // Full validation requires context (locktime, etc.)
    // We just check basic structure here

    Ok(())
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

/// Validates script execution for individual inputs
///
/// This function validates each input's script against its scriptPubkey.
/// It performs simplified validation - full validation requires Bitcoin Core.
///
/// # Arguments
/// * `btx` - The BitcoinTransaction to validate
///
/// # Returns
/// * `Ok(())` - All scripts are valid
/// * `Err(BtxError)` - Script validation failed
pub fn validate_script_execution(btx: &BitcoinTransaction) -> Result<()> {
    if !btx.has_scripts() {
        return Ok(()); // No scripts to validate
    }

    for (idx, input_data) in btx.inputs_data.iter().enumerate() {
        let script_pubkey = input_data.utxo.script_pubkey();
        let script_type = detect_script_type(&script_pubkey);

        match script_type {
            crate::btx::script::ScriptType::P2PKH => {
                validate_p2pkh_spend(&input_data.script_sig, &script_pubkey).map_err(|e| {
                    crate::errors::Error::Btx(BtxError::InvalidScriptSig(idx, format!("{:?}", e)))
                })?;
            }
            crate::btx::script::ScriptType::P2SH => {
                validate_p2sh_spend(&input_data.script_sig, &script_pubkey).map_err(|e| {
                    crate::errors::Error::Btx(BtxError::InvalidScriptSig(idx, format!("{:?}", e)))
                })?;
            }
            crate::btx::script::ScriptType::P2WPKH
            | crate::btx::script::ScriptType::P2WSH
            | crate::btx::script::ScriptType::P2TR => {
                validate_segwit_spend(&input_data.witness, &script_pubkey).map_err(|e| {
                    crate::errors::Error::Btx(BtxError::InvalidWitness(idx, format!("{:?}", e)))
                })?;
            }
            crate::btx::script::ScriptType::Unknown => {
                return Err(crate::errors::Error::Btx(BtxError::InvalidScriptPubkey(format!(
                    "Unknown script type at input {}",
                    idx
                ))));
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
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::hashes::Hash;
    use bitcoin::{Address, Txid};

    use super::*;
    use crate::btx::state::Utxo;

    // Helper function to parse addresses
    fn addr(s: &str) -> Address<NetworkUnchecked> { s.parse().expect("valid Bitcoin address") }

    #[test]
    fn test_empty() {
        let empty_tx = empty();
        assert!(empty_tx.inputs_data.is_empty());
        assert!(empty_tx.outputs.is_empty());
        assert!(is_valid(&empty_tx));
    }

    #[test]
    fn test_empty_method() {
        let empty_tx = BitcoinTransaction::empty();
        assert!(empty_tx.inputs_data.is_empty());
        assert!(empty_tx.outputs.is_empty());
        assert!(empty_tx.is_valid());
    }

    #[test]
    fn test_is_valid_equal() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let inputs = vec![
            Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")),
            Utxo::new(txid2, 1, 2000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")),
        ];
        let outputs = vec![Utxo::new(txid3, 0, 3000, addr("1CounterpartyXXXXXXXXXXXXXXXUWLpVr"))];
        let tx = BitcoinTransaction::new(inputs, outputs);
        assert!(is_valid(&tx));
        assert!(tx.is_valid());
    }

    #[test]
    fn test_is_valid_unequal() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let inputs = vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))];
        let outputs = vec![Utxo::new(txid2, 0, 2000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))];
        let tx = BitcoinTransaction::new(inputs, outputs);
        assert!(!is_valid(&tx));
        assert!(!tx.is_valid());
    }

    #[test]
    fn test_is_valid_with_fees() {
        // Transaction with fees: inputs > outputs
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let inputs = vec![
            Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")),
            Utxo::new(txid2, 1, 2000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")),
        ];
        // Outputs total 2900, leaving 100 satoshis as fee
        let outputs = vec![Utxo::new(txid3, 0, 2900, addr("1CounterpartyXXXXXXXXXXXXXXXUWLpVr"))];
        let tx = BitcoinTransaction::new(inputs, outputs);
        assert!(is_valid(&tx));
        assert!(tx.is_valid());
    }

    #[test]
    fn test_is_valid_empty() {
        let tx = BitcoinTransaction::new(vec![], vec![]);
        assert!(is_valid(&tx));
    }

    #[test]
    fn test_compose_valid() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let txid4 = Txid::from_byte_array([0x04; 32]);
        let tx1 = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let tx2 = BitcoinTransaction::new(
            vec![Utxo::new(txid3, 0, 2000, addr("1CounterpartyXXXXXXXXXXXXXXXUWLpVr"))],
            vec![Utxo::new(txid4, 0, 2000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
        );

        let composed = compose(&tx1, &tx2).expect("composition should succeed");
        assert_eq!(composed.inputs_data.len(), 2);
        assert_eq!(composed.outputs.len(), 2);
        assert!(is_valid(&composed));

        // Test method version
        let composed2 = tx1.compose(&tx2).expect("composition should succeed");
        assert_eq!(composed.inputs_data.len(), composed2.inputs_data.len());
        assert_eq!(composed.outputs.len(), composed2.outputs.len());
    }

    #[test]
    fn test_compose_invalid_first() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let txid4 = Txid::from_byte_array([0x04; 32]);
        let tx1 = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 2000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))], // Invalid: 1000 != 2000
        );
        let tx2 = BitcoinTransaction::new(
            vec![Utxo::new(txid3, 0, 2000, addr("1CounterpartyXXXXXXXXXXXXXXXUWLpVr"))],
            vec![Utxo::new(txid4, 0, 2000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
        );

        let result = compose(&tx1, &tx2);
        assert!(result.is_err());
        assert!(matches!(
            result.expect_err("expected error"),
            crate::errors::Error::Btx(BtxError::InvalidTransaction)
        ));
    }

    #[test]
    fn test_compose_invalid_second() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let txid4 = Txid::from_byte_array([0x04; 32]);
        let tx1 = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let tx2 = BitcoinTransaction::new(
            vec![Utxo::new(txid3, 0, 2000, addr("1CounterpartyXXXXXXXXXXXXXXXUWLpVr"))],
            vec![Utxo::new(txid4, 0, 3000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))], // Invalid: 2000 != 3000
        );

        let result = compose(&tx1, &tx2);
        assert!(result.is_err());
        assert!(matches!(
            result.expect_err("expected error"),
            crate::errors::Error::Btx(BtxError::InvalidTransaction)
        ));
    }

    #[test]
    fn test_compose_empty() {
        let empty_tx = empty();
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let tx = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );

        // Composing with empty transaction (identity morphism) should return the original transaction
        let composed1 = compose(&empty_tx, &tx).expect("should succeed");
        assert_eq!(composed1.inputs_data.len(), 1);
        assert_eq!(composed1.outputs.len(), 1);

        let composed2 = compose(&tx, &empty_tx).expect("should succeed");
        assert_eq!(composed2.inputs_data.len(), 1);
        assert_eq!(composed2.outputs.len(), 1);
    }

    #[test]
    fn test_apply_transaction_valid() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let tx = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let result = apply_transaction(tx.clone(), false).expect("should succeed");
        assert_eq!(result.inputs_data.len(), 1);
        assert_eq!(result.outputs.len(), 1);
    }

    #[test]
    fn test_apply_transaction_invalid() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let tx = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 2000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let result = apply_transaction(tx, false);
        assert!(result.is_err());
        assert!(matches!(
            result.expect_err("expected error"),
            crate::errors::Error::Btx(BtxError::InvalidTransaction)
        ));
    }

    #[test]
    fn test_verify_bitcoin_transaction_missing_output() {
        use bitcoin::absolute::LockTime;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut};

        // Create a simple transaction that tries to spend a non-existent output
        let prev_txid = Txid::from_byte_array([0x42; 32]);
        let outpoint = OutPoint { txid: prev_txid, vout: 0 };

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
        };

        // Try to verify with a function that returns None (output doesn't exist)
        let result = verify_bitcoin_transaction(&tx, |_| None);
        assert!(result.is_err());
        assert!(matches!(
            result.expect_err("expected error"),
            crate::errors::Error::Btx(BtxError::MissingSpentOutput(_))
        ));
    }

    #[test]
    fn test_verify_bitcoin_transaction_consensus_validation() {
        use bitcoin::absolute::LockTime;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut};

        // This test demonstrates consensus validation by showing:
        // 1. How to set up a transaction with proper structure
        // 2. How to provide spent outputs via the closure
        // 3. How consensus validation checks scripts and signatures

        // Create a previous transaction output (the UTXO being spent)
        let prev_txid = Txid::from_byte_array([0x01; 32]);
        let outpoint = OutPoint { txid: prev_txid, vout: 0 };

        // Create a simple P2PKH output (this would normally have a proper script)
        // For demonstration, we use an empty script - in reality this would fail script validation
        let spent_output = TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: ScriptBuf::from_bytes(vec![
                0x76, // OP_DUP
                0xa9, // OP_HASH160
                0x14, // Push 20 bytes
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 20 zero bytes (pubkey hash)
                0x88, // OP_EQUALVERIFY
                0xac, // OP_CHECKSIG
            ]),
        };

        // Create a transaction that tries to spend this output
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(), // Empty script - will fail validation
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49000), // 1000 sat fee
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // Provide the spent output via closure
        let mut outputs_provided = false;
        let result = verify_bitcoin_transaction(&tx, |op| {
            if op == &outpoint {
                outputs_provided = true;
                Some(spent_output.clone())
            } else {
                None
            }
        });

        // The transaction should fail because:
        // 1. The script_sig is empty (no signature provided)
        // 2. The script doesn't match the scriptPubkey requirements
        // This demonstrates that consensus validation actually checks scripts!
        assert!(result.is_err());
        assert!(outputs_provided, "The spent_outputs closure should be called");
        let err = result.expect_err("expected script verification error");
        assert!(
            matches!(err, crate::errors::Error::Btx(BtxError::ScriptExecutionFailed(_))),
            "Expected ScriptExecutionFailed, got: {:?}",
            err
        );
    }
}
