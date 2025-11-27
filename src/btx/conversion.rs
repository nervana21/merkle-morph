// SPDX-License-Identifier: CC0-1.0

//! Conversion layer between BitcoinTransaction and bitcoin::Transaction
//!
//! This module provides conversions between the BTX abstraction types
//! and the bitcoin::Transaction type.
//!
//! The conversions handle address derivation from script_pubkey using the
//! bitcoin::Transaction standard APIs, with proper error handling for scripts
//! that cannot map to an address (unspendable/data outputs). P2A taproot anchors
//! are standard segwit outputs and are accepted.

use bitcoin::address::NetworkUnchecked;
use bitcoin::script::ScriptPubKeyBuf;
use bitcoin::{Address, Amount, Network, OutPoint, Transaction, TxIn, TxOut, Txid};

use crate::btx::state::{BitcoinTransaction, TxInputData, Utxo};
use crate::errors::{BtxError, Result};

/// Derives a Bitcoin address from a script_pubkey
///
/// Uses bitcoin::Transaction's `Address::from_script` API to derive addresses
/// for standard script types. This codebase uses P2TR and P2A script types.
/// For other script types, this function returns an error.
///
/// # Arguments
/// * `script_pubkey` - The script public key to derive an address from
/// * `network` - The Bitcoin network (mainnet, testnet, etc.)
///
/// # Returns
/// * `Ok(Address)` - The derived address
/// * `Err(BtxError::AddressDerivationFailed)` - If address cannot be derived
///
/// # Example
///
/// ```rust,no_run
/// use bitcoin::{Network, script::ScriptPubKeyBuf};
/// use merkle_morph::btx::conversion::derive_address_from_script;
///
/// fn example() -> Result<(), Box<dyn std::error::Error>> {
///     // Example with a P2TR script (taproot)
///     let script = ScriptPubKeyBuf::from_bytes(vec![0x51, 0x20]); // Simplified example
///     match derive_address_from_script(&script, Network::Bitcoin) {
///         Ok(addr) => println!("Address: {:?}", addr),
///         Err(e) => println!("Cannot derive address: {}", e),
///     }
///     Ok(())
/// }
/// ```
pub fn derive_address_from_script(
    script_pubkey: &ScriptPubKeyBuf,
    network: Network,
) -> Result<Address<NetworkUnchecked>> {
    match Address::from_script(script_pubkey, network) {
        Ok(addr) => Ok(*addr.as_unchecked()),
        Err(e) => Err(BtxError::AddressDerivationFailed(format!(
            "bitcoin::Transaction Address::from_script failed: {:?}",
            e
        ))
        .into()),
    }
}

/// Converts a bitcoin `TxOut` into the internal `Utxo` representation.
///
/// The function always clones the original `script_pubkey` onto the `Utxo` and
/// derives the human-readable address via [`derive_address_from_script`]. Any
/// script that cannot be mapped to an address causes the conversion to fail.
///
/// # Arguments
/// * `txout` - The TxOut to convert
/// * `txid` - The transaction ID that created this output
/// * `index` - The output index
/// * `network` - Optional Bitcoin network (defaults to `Network::Bitcoin`)
///
/// # Returns
/// * `Ok(Utxo)` - The converted UTXO
/// * `Err(BtxError)` - If address derivation fails for the script
///
/// # Example
///
/// ```rust
/// use bitcoin::{Network, OutPoint, TxOut, Amount, script::{ScriptPubKeyBuf, ScriptPubKeyBufExt}, Txid};
/// use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
/// use bitcoin::key::TweakedPublicKey;
/// use merkle_morph::btx::conversion::txout_to_utxo;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Create a valid P2TR script
///     let secp = Secp256k1::new();
///     let sk = SecretKey::from_secret_bytes([0x01; 32])?;
///     let x_only_pk = XOnlyPublicKey::from_keypair(&sk.keypair()).0;
///     let key_bytes = x_only_pk.serialize();
///     let key = bitcoin::key::XOnlyPublicKey::from_byte_array(&key_bytes)?;
///     let output_key = TweakedPublicKey::dangerous_assume_tweaked(key);
///     let script_pubkey = ScriptPubKeyBuf::new_p2tr_tweaked(output_key);
///
///     let txout = TxOut {
///         amount: Amount::from_sat(1000).expect("1000 is in range"),
///         script_pubkey,
///     };
///     let utxo = txout_to_utxo(&txout, Txid::from_byte_array([0u8; 32]), 0, None)?;
///     Ok(())
/// }
/// ```
pub fn txout_to_utxo(
    txout: &TxOut,
    txid: Txid,
    index: u32,
    network: Option<Network>,
) -> Result<Utxo> {
    let network = network.unwrap_or(Network::Bitcoin);
    let address = derive_address_from_script(&txout.script_pubkey, network)?;

    Ok(Utxo::with_script_pubkey(
        txid,
        index,
        txout.amount.to_sat(),
        address,
        txout.script_pubkey.clone(),
    ))
}

/// Converts a bitcoin::Transaction to BitcoinTransaction
///
/// This conversion attempts to derive addresses from script_pubkeys, but note that:
/// - Input UTXOs require looking up the actual spent outputs (value, script_pubkey)
/// - Output addresses are derived from script_pubkeys
///
/// # Arguments
/// * `tx` - The bitcoin::Transaction to convert
/// * `network` - Optional Bitcoin network (defaults to regtest)
/// * `spent_outputs` - Function to look up spent outputs for inputs.
///
/// # Returns
/// * `Ok(BitcoinTransaction)` - The converted transaction
/// * `Err(BtxError)` - If conversion fails
///
/// # Example
///
/// ```rust
/// use bitcoin::{Network, Transaction, OutPoint, TxOut, TxIn, Amount, script::ScriptBuf};
/// use bitcoin::absolute::LockTime;
/// use merkle_morph::btx::conversion::transaction_to_btx;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let tx = Transaction {
///         version: bitcoin::transaction::Version::TWO,
///         lock_time: LockTime::ZERO,
///         inputs: vec![],
///         outputs: vec![],
///     };
///     let btx = transaction_to_btx(&tx, Some(Network::Bitcoin), |_| None)?;
///     Ok(())
/// }
/// ```
pub fn transaction_to_btx<S>(
    tx: &Transaction,
    network: Option<Network>,
    mut spent_outputs: S,
) -> Result<BitcoinTransaction>
where
    S: FnMut(&OutPoint) -> Option<TxOut>,
{
    let network = network.unwrap_or(Network::Regtest);
    let txid = tx.compute_txid();

    let inputs_data: Result<Vec<TxInputData>> = tx
        .inputs
        .iter()
        .map(|txin| {
            let outpoint = &txin.previous_output;

            let spent_output =
                spent_outputs(outpoint).ok_or(BtxError::MissingUtxoData(*outpoint))?;

            let utxo = txout_to_utxo(&spent_output, outpoint.txid, outpoint.vout, Some(network))?;

            Ok(TxInputData::new(utxo, txin.script_sig.clone(), txin.witness.clone(), txin.sequence))
        })
        .collect();

    let inputs_data = inputs_data?;

    let outputs: Result<Vec<Utxo>> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(idx, txout)| txout_to_utxo(txout, txid, idx as u32, Some(network)))
        .collect();

    let outputs = outputs?;

    Ok(BitcoinTransaction::with_scripts(tx.version, inputs_data, outputs, tx.lock_time))
}

/// Converts a BitcoinTransaction to bitcoin::Transaction
///
/// This conversion requires full script data in the BitcoinTransaction.
///
/// # Arguments
/// * `btx` - The BitcoinTransaction to convert
///
/// # Returns
/// * `Ok(Transaction)` - The converted transaction
/// * `Err(BtxError)` - If conversion fails (e.g., missing script data)
///
/// # Note on Empty Transactions
///
/// Empty transactions (with no inputs) are rejected by this conversion.
/// While `is_valid()` allows empty transactions as identity morphisms in the
/// BTX category, `bitcoin::Transaction` requires at least one input for practical
/// use. If you need to represent an empty transaction, use `BitcoinTransaction`
/// directly rather than converting to `bitcoin::Transaction`.
impl TryFrom<BitcoinTransaction> for Transaction {
    type Error = crate::Error;

    fn try_from(btx: BitcoinTransaction) -> Result<Transaction> {
        // Reject empty transactions: bitcoin::Transaction requires at least one input
        // Empty transactions are valid in the BTX abstraction (identity morphism) but
        // cannot be represented as a real Bitcoin transaction.
        if btx.inputs_data.is_empty() {
            return Err(BtxError::InvalidTransaction.into());
        }

        let inputs: Vec<TxIn> = btx
            .inputs_data
            .iter()
            .map(|input_data| TxIn {
                previous_output: input_data.utxo.outpoint(),
                script_sig: input_data.script_sig.clone(),
                sequence: input_data.sequence,
                witness: input_data.witness.clone(),
            })
            .collect();

        let outputs: Vec<TxOut> = btx.outputs.iter().map(utxo_to_txout).collect();

        Ok(Transaction { version: btx.version, lock_time: btx.lock_time, inputs, outputs })
    }
}

/// Converts a Utxo to TxOut
///
/// # Arguments
/// * `utxo` - The UTXO to convert
///
/// # Returns
/// A TxOut representing the UTXO
pub fn utxo_to_txout(utxo: &Utxo) -> TxOut {
    TxOut {
        amount: Amount::from_sat(utxo.value).expect("UTXO value out of range"),
        script_pubkey: utxo.script_pubkey(),
    }
}

/// Builds a spent_outputs closure from a BitcoinTransaction
///
/// This creates a closure that can be used with `verify_bitcoin_transaction`
/// to provide the spent outputs for validation.
///
/// # Arguments
/// * `btx` - The BitcoinTransaction containing the inputs
///
/// # Returns
/// A closure that returns the TxOut for each OutPoint
pub fn build_spent_outputs_closure(
    btx: &BitcoinTransaction,
) -> impl FnMut(&OutPoint) -> Option<TxOut> {
    let mut outputs_map: std::collections::HashMap<OutPoint, TxOut> =
        std::collections::HashMap::new();

    for input_data in &btx.inputs_data {
        let outpoint = input_data.utxo.outpoint();
        let txout = utxo_to_txout(&input_data.utxo);
        outputs_map.insert(outpoint, txout);
    }

    move |outpoint: &OutPoint| outputs_map.get(outpoint).cloned()
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, Network, OutPoint, ScriptPubKeyBuf, Sequence, Transaction, TxIn, TxOut, Txid,
        Witness,
    };

    use super::*;
    use crate::channel::test_utils::*;

    #[test]
    fn test_derive_address_from_script() {
        let (_, p2tr_script) = test_taproot_input_keypair();

        let derived =
            derive_address_from_script(&p2tr_script, Network::Regtest).expect("p2tr should derive");

        let unknown_script = ScriptPubKeyBuf::from_bytes(vec![0x01, 0x02, 0x03]);

        let unknown_result = derive_address_from_script(&unknown_script, Network::Bitcoin);

        assert_eq!(derived.assume_checked_ref().script_pubkey(), p2tr_script);
        assert!(matches!(
            unknown_result,
            Err(crate::Error::Btx(BtxError::AddressDerivationFailed(_)))
        ));
    }

    #[test]
    fn test_txout_to_utxo() {
        let (_, script_pubkey) = test_taproot_input_keypair();
        let txout = TxOut {
            amount: Amount::from_sat(5000).expect("5000 is in range"),
            script_pubkey: script_pubkey.clone(),
        };
        let txid = Txid::from_byte_array([1u8; 32]);

        let utxo = txout_to_utxo(&txout, txid, 1, None).expect("standard output converts");

        assert_eq!(utxo.value, 5000);
        assert_eq!(utxo.script_pubkey(), script_pubkey);
    }

    #[test]
    fn test_transaction_to_btx() {
        let (_, script_pubkey) = test_taproot_input_keypair();

        let spent_outpoint = OutPoint { txid: Txid::from_byte_array([2u8; 32]), vout: 0 };
        let spent_txout = TxOut {
            amount: Amount::from_sat(9000).expect("9000 is in range"),
            script_pubkey: script_pubkey.clone(),
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: spent_outpoint,
                script_sig: bitcoin::script::ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(4000).expect("4000 is in range"),
                script_pubkey: script_pubkey.clone(),
            }],
        };
        let mut lookup = move |outpoint: &OutPoint| {
            if *outpoint == spent_outpoint {
                Some(spent_txout.clone())
            } else {
                None
            }
        };

        let btx = transaction_to_btx(&tx, None, &mut lookup).expect("conversion succeeds");

        let missing_prev_outpoint = OutPoint { txid: Txid::from_byte_array([3u8; 32]), vout: 0 };
        let error_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: missing_prev_outpoint,
                script_sig: bitcoin::script::ScriptSigBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                amount: Amount::from_sat(2000).expect("2000 is in range"),
                script_pubkey: script_pubkey.clone(),
            }],
        };
        let mut missing_lookup = |_outpoint: &OutPoint| None;

        let err = transaction_to_btx(&error_tx, Some(Network::Bitcoin), &mut missing_lookup);

        assert_eq!(btx.inputs_data.len(), 1);
        assert_eq!(btx.outputs.len(), 1);
        assert!(matches!(
            err,
            Err(crate::Error::Btx(BtxError::MissingUtxoData(op))) if op == missing_prev_outpoint
        ));
    }

    #[test]
    fn test_utxo_to_txout() {
        let (_, script_pubkey) = test_taproot_input_keypair();
        let address = *Address::from_script(&script_pubkey, Network::Bitcoin)
            .expect("address")
            .as_unchecked();
        let utxo = Utxo::with_script_pubkey(
            Txid::from_byte_array([4u8; 32]),
            0,
            1234,
            address,
            script_pubkey.clone(),
        );

        let txout = utxo_to_txout(&utxo);

        assert_eq!(txout.amount, Amount::from_sat(1234).expect("1234 is in range"));
        assert_eq!(txout.script_pubkey, script_pubkey);
    }

    #[test]
    fn test_build_spent_outputs_closure() {
        let (_, script_pubkey) = test_taproot_input_keypair();
        let txid = Txid::from_byte_array([5u8; 32]);
        let address = *Address::from_script(&script_pubkey, Network::Regtest)
            .expect("address")
            .as_unchecked();
        let utxo = Utxo::with_script_pubkey(txid, 0, 2000, address, script_pubkey.clone());
        let input_data = TxInputData::new(
            utxo.clone(),
            bitcoin::script::ScriptSigBuf::new(),
            Witness::new(),
            Sequence::MAX,
        );
        let btx = BitcoinTransaction::with_scripts(
            Version::TWO,
            vec![input_data],
            vec![],
            LockTime::ZERO,
        );

        let mut closure = build_spent_outputs_closure(&btx);

        let existing = closure(&OutPoint { txid, vout: 0 }).expect("existing utxo");
        let missing = closure(&OutPoint { txid: Txid::from_byte_array([6u8; 32]), vout: 0 });

        assert_eq!(existing.amount, Amount::from_sat(2000).expect("2000 is in range"));
        assert!(missing.is_none());
    }
}
