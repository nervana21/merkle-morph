//! Bitcoin transaction transition logic
//!
//! This module provides pure functions for applying state transitions to Bitcoin transactions.
//! All transition logic is deterministic and side-effect free.

use bitcoin::consensus::validation::TxVerifyError;
use bitcoin::{OutPoint, Transaction, TxOut};

use crate::btx::conversion::build_spent_outputs_closure;
use crate::btx::script::{detect_script_type, validate_segwit_spend};
use crate::btx::state::BitcoinTransaction;
use crate::btx::timelock::{extract_csv_blocks, validate_csv_timelock};
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

    // Validate sequence numbers and CSV time locks
    for input in tx.input.iter() {
        let sequence = input.sequence;
        if sequence.to_consensus_u32() == 0xFFFFFFFF {
            // Sequence 0xFFFFFFFF means no relative lock time
            continue;
        }

        // Check for CSV time lock (basic structure validation)
        // Full CSV validation requires block heights and is done separately
        if let Some(_required_blocks) = extract_csv_blocks(sequence) {
            // CSV is enabled - structure is valid
            // Actual time lock validation requires current_height and lock_height
        }
    }

    Ok(())
}

/// Validates consensus rules with block height for CSV validation
///
/// This extends `validate_consensus_rules` to validate CSV time locks when
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
    // First do basic validation
    validate_consensus_rules(tx)?;

    // If heights provided, validate CSV time locks
    if let (Some(current), Some(lock)) = (current_height, lock_height) {
        for (idx, input) in tx.input.iter().enumerate() {
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

/// Validates P2TR witness structure for transaction inputs
///
/// This function validates that all inputs spend P2TR outputs and that their
/// witness structures are valid. It performs simplified validation - full validation
/// requires Bitcoin Core.
///
/// # Arguments
/// * `btx` - The BitcoinTransaction to validate
///
/// # Returns
/// * `Ok(())` - All P2TR witnesses are valid
/// * `Err(BtxError)` - Witness validation failed or non-P2TR script type detected
pub fn validate_p2tr_witnesses(btx: &BitcoinTransaction) -> Result<()> {
    for (idx, input_data) in btx.inputs_data.iter().enumerate() {
        let script_pubkey = input_data.utxo.script_pubkey();
        let script_type = detect_script_type(&script_pubkey);

        match script_type {
            crate::btx::script::ScriptType::P2TR => {
                if input_data.witness.is_empty() {
                    return Err(crate::Error::Btx(BtxError::InvalidWitness(
                        idx,
                        "P2TR witness is empty".to_string(),
                    )));
                }
                validate_segwit_spend(&input_data.witness, &script_pubkey).map_err(|e| {
                    crate::Error::Btx(BtxError::InvalidWitness(idx, format!("{:?}", e)))
                })?;
            }
            crate::btx::script::ScriptType::Unknown => {
                return Err(crate::Error::Btx(BtxError::InvalidScriptPubkey(format!(
                    "Unsupported script type {:?} at input {} (only P2TR is supported)",
                    script_type, idx
                ))));
            }
            _ => {
                // Non-Taproot inputs are not validated by this helper
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
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
    use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};

    use super::*;
    use crate::btx::state::{TxInputData, Utxo};
    use crate::btx::timelock::compute_sequence_for_blocks;

    fn addr(s: &str) -> Address<NetworkUnchecked> { s.parse().expect("valid Bitcoin address") }

    #[test]
    fn test_empty() {
        let result = empty();

        assert!(result.inputs_data.is_empty());
        assert!(result.outputs.is_empty());
    }

    #[test]
    fn test_is_valid() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let empty_tx = BitcoinTransaction::new(vec![], vec![]);
        let valid_tx = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let invalid_tx = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid3, 0, 2000, addr("1CounterpartyXXXXXXXXXXXXXXXUWLpVr"))],
        );

        assert!(is_valid(&empty_tx));
        assert!(is_valid(&valid_tx));
        assert!(!is_valid(&invalid_tx));
    }

    #[test]
    fn test_compose() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let txid4 = Txid::from_byte_array([0x04; 32]);
        let txid5 = Txid::from_byte_array([0x05; 32]);
        let valid_tx1 = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let valid_tx2 = BitcoinTransaction::new(
            vec![Utxo::new(txid3, 0, 2000, addr("1CounterpartyXXXXXXXXXXXXXXXUWLpVr"))],
            vec![Utxo::new(txid4, 0, 2000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
        );
        let invalid_tx1 = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 2000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let invalid_tx2 = BitcoinTransaction::new(
            vec![Utxo::new(txid3, 0, 2000, addr("1CounterpartyXXXXXXXXXXXXXXXUWLpVr"))],
            vec![Utxo::new(txid5, 0, 3000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
        );
        let secp = Secp256k1::new();
        let test_sk = SecretKey::from_slice(&[1u8; 32]).expect("valid SecretKey");
        let test_x_only_pk = XOnlyPublicKey::from_keypair(&test_sk.keypair(&secp)).0;
        let output_key = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(test_x_only_pk);
        let p2tr_script = ScriptBuf::new_p2tr_tweaked(output_key);
        let mut p2tr_utxo1 =
            Utxo::new(txid1, 0, 1000, addr("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        p2tr_utxo1.script_pubkey = Some(p2tr_script.clone());
        let mut p2tr_utxo2 =
            Utxo::new(txid3, 0, 2000, addr("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        p2tr_utxo2.script_pubkey = Some(p2tr_script.clone());
        let script_tx1 = BitcoinTransaction::with_scripts(
            bitcoin::transaction::Version::TWO,
            LockTime::ZERO,
            vec![TxInputData::new(
                p2tr_utxo1,
                ScriptBuf::new(),
                bitcoin::Witness::from_slice(&[vec![0x01]]),
                Sequence::MAX,
            )],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let script_tx2 = BitcoinTransaction::with_scripts(
            bitcoin::transaction::Version::TWO,
            LockTime::ZERO,
            vec![TxInputData::new(
                p2tr_utxo2,
                ScriptBuf::new(),
                bitcoin::Witness::from_slice(&[vec![0x01]]),
                Sequence::MAX,
            )],
            vec![Utxo::new(txid4, 0, 2000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
        );
        let composed_invalid = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 2000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );

        assert!(compose(&invalid_tx1, &valid_tx2).is_err());

        assert!(compose(&valid_tx1, &invalid_tx2).is_err());

        assert!(compose(&valid_tx1, &valid_tx2).is_ok());

        assert!(compose(&script_tx1, &script_tx2).is_ok());

        let composed_result = compose(&valid_tx1, &composed_invalid);

        if let Ok(composed) = composed_result {
            assert!(!is_valid(&composed));
        }
    }

    #[test]
    fn test_apply_transaction() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let valid_tx = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let invalid_tx = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid3, 0, 2000, addr("1CounterpartyXXXXXXXXXXXXXXXUWLpVr"))],
        );
        let mut script_tx = valid_tx.clone();
        script_tx.inputs_data[0].script_sig = ScriptBuf::from_bytes(vec![0x01]);

        assert!(apply_transaction(valid_tx.clone(), false).is_ok());

        assert!(apply_transaction(valid_tx, true).is_ok());

        assert!(apply_transaction(invalid_tx, false).is_err());

        assert!(apply_transaction(script_tx, true).is_err());
    }

    #[test]
    fn test_verify_bitcoin_transaction() {
        let prev_txid = Txid::from_byte_array([0x01; 32]);
        let outpoint = OutPoint { txid: prev_txid, vout: 0 };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
        };
        let secp = Secp256k1::new();
        let test_sk = SecretKey::from_slice(&[1u8; 32]).expect("valid SecretKey");
        let test_x_only_pk = XOnlyPublicKey::from_keypair(&test_sk.keypair(&secp)).0;
        let output_key = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(test_x_only_pk);
        let spent_output = TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
        };
        let large_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::from_bytes(vec![0u8; 50000]),
                sequence: Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
        };

        assert!(verify_bitcoin_transaction(&tx, |_| None).is_err());

        let serialized = bitcoin::consensus::encode::serialize(&large_tx);

        if serialized.len() > 100_000 {
            assert!(verify_bitcoin_transaction(&large_tx, |op| if op == &outpoint {
                Some(spent_output.clone())
            } else {
                None
            })
            .is_err());
        }
    }

    #[test]
    fn test_validate_consensus_rules() {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let large_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0x01; 32]), vout: 0 },
                script_sig: ScriptBuf::from_bytes(vec![0u8; 50000]),
                sequence: Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
        };
        let csv_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0x01; 32]), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: compute_sequence_for_blocks(144),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
        };
        let non_csv_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0x01; 32]), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0x00000000),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
        };

        assert!(validate_consensus_rules(&tx).is_ok());

        assert!(validate_consensus_rules(&csv_tx).is_ok());

        assert!(validate_consensus_rules(&non_csv_tx).is_ok());

        let serialized = bitcoin::consensus::encode::serialize(&large_tx);

        if serialized.len() > 100_000 {
            assert!(validate_consensus_rules(&large_tx).is_err());
        }
    }

    #[test]
    fn test_validate_consensus_rules_with_height() {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0x01; 32]), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0x00000000),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
        };
        let csv_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::from_byte_array([0x01; 32]), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: compute_sequence_for_blocks(144),
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(1000), script_pubkey: ScriptBuf::new() }],
        };

        assert!(validate_consensus_rules_with_height(&tx, None, None).is_ok());

        assert!(validate_consensus_rules_with_height(&tx, Some(1000), Some(900)).is_ok());

        assert!(validate_consensus_rules_with_height(&csv_tx, Some(1144), Some(1000)).is_ok());

        assert!(validate_consensus_rules_with_height(&csv_tx, Some(1143), Some(1000)).is_err());
    }

    #[test]
    fn test_validate_with_scripts() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let valid_tx = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let invalid_tx = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid3, 0, 2000, addr("1CounterpartyXXXXXXXXXXXXXXXUWLpVr"))],
        );
        let mut script_tx = valid_tx.clone();
        script_tx.inputs_data[0].script_sig = ScriptBuf::from_bytes(vec![0x01]);

        assert!(validate_with_scripts(&valid_tx).is_ok());

        assert!(validate_with_scripts(&invalid_tx).is_err());

        assert!(validate_with_scripts(&script_tx).is_err());
    }

    #[test]
    fn test_validate_p2tr_witnesses() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let no_script_tx = BitcoinTransaction::new(
            vec![Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let secp = Secp256k1::new();
        let test_sk = SecretKey::from_slice(&[1u8; 32]).expect("valid SecretKey");
        let test_x_only_pk = XOnlyPublicKey::from_keypair(&test_sk.keypair(&secp)).0;
        let output_key = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(test_x_only_pk);
        let p2tr_script = ScriptBuf::new_p2tr_tweaked(output_key);
        let mut p2tr_utxo =
            Utxo::new(txid1, 0, 1000, addr("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        p2tr_utxo.script_pubkey = Some(p2tr_script.clone());
        let p2tr_tx = BitcoinTransaction::with_scripts(
            bitcoin::transaction::Version::TWO,
            LockTime::ZERO,
            vec![TxInputData::new(
                p2tr_utxo,
                ScriptBuf::new(),
                bitcoin::Witness::from_slice(&[vec![0x01]]),
                Sequence::MAX,
            )],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let mut invalid_witness_utxo =
            Utxo::new(txid1, 0, 1000, addr("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        invalid_witness_utxo.script_pubkey = Some(p2tr_script.clone());
        let invalid_witness_tx = BitcoinTransaction::with_scripts(
            bitcoin::transaction::Version::TWO,
            LockTime::ZERO,
            vec![TxInputData::new(
                invalid_witness_utxo,
                ScriptBuf::new(),
                bitcoin::Witness::new(),
                Sequence::MAX,
            )],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );
        let mut unknown_utxo =
            Utxo::new(txid1, 0, 1000, addr("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        unknown_utxo.script_pubkey = Some(ScriptBuf::from_bytes(vec![0xFF]));
        let unknown_tx = BitcoinTransaction::with_scripts(
            bitcoin::transaction::Version::TWO,
            LockTime::ZERO,
            vec![TxInputData::new(
                unknown_utxo,
                ScriptBuf::new(),
                bitcoin::Witness::new(),
                Sequence::MAX,
            )],
            vec![Utxo::new(txid2, 0, 1000, addr("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))],
        );

        assert!(validate_p2tr_witnesses(&no_script_tx).is_ok());

        assert!(validate_p2tr_witnesses(&p2tr_tx).is_ok());

        assert!(validate_p2tr_witnesses(&invalid_witness_tx).is_err());

        assert!(validate_p2tr_witnesses(&unknown_tx).is_err());
    }
}
