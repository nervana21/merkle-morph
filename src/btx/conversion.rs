//! Conversion layer between BitcoinTransaction and bitcoin::Transaction
//!
//! This module provides conversions between the BTX abstraction types
//! and the bitcoin::Transaction type.
//!
//! The conversions handle address derivation from script_pubkey using
//! the bitcoin::Transaction standard APIs, with proper error handling for cases
//! where address derivation is not possible (e.g., OP_RETURN outputs).

use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid};

use crate::btx::script::detect_script_type;
use crate::btx::state::{BitcoinTransaction, TxInputData, Utxo};
use crate::errors::{BtxError, Result};

/// Standard OP_RETURN opcode (0x6a)
///
/// This opcode creates an unspendable output that is provably prunable.
const OP_RETURN: u8 = 0x6a;

/// Start of non-standard unspendable opcodes range (0xbb)
///
/// Opcodes 0xbb through 0xfe are non-standard opcodes that also create
/// unspendable outputs similar to OP_RETURN.
const NON_STANDARD_UNSPENDABLE_START: u8 = 0xbb;

/// End of non-standard unspendable opcodes range (0xfe)
///
/// Opcodes 0xbb through 0xfe are non-standard opcodes that also create
/// unspendable outputs similar to OP_RETURN.
const NON_STANDARD_UNSPENDABLE_END: u8 = 0xfe;

/// Derives a Bitcoin address from a script_pubkey
///
/// Uses bitcoin::Transaction's `Address::from_script` API to derive addresses
/// for standard script types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR).
/// For non-standard scripts (e.g., OP_RETURN), this function returns an error.
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
/// ```rust
/// use bitcoin::{Network, ScriptBuf};
/// use merkle_morph::btx::conversion::derive_address_from_script;
///
/// let script = ScriptBuf::from_hex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
/// match derive_address_from_script(&script, Network::Bitcoin) {
///     Ok(addr) => println!("Address: {:?}", addr),
///     Err(e) => println!("Cannot derive address: {}", e),
/// }
/// ```
pub fn derive_address_from_script(
    script_pubkey: &ScriptBuf,
    network: Network,
) -> Result<Address<NetworkUnchecked>> {
    let script_type = detect_script_type(script_pubkey);
    if script_type == crate::btx::script::ScriptType::Unknown {
        // Check for unspendable opcodes:
        let bytes = script_pubkey.as_bytes();
        if !bytes.is_empty() {
            let first_byte = bytes[0];
            if first_byte == OP_RETURN {
                return Err(BtxError::AddressDerivationFailed(
                    "OP_RETURN outputs do not have addresses".to_string(),
                )
                .into());
            } else if (NON_STANDARD_UNSPENDABLE_START..=NON_STANDARD_UNSPENDABLE_END)
                .contains(&first_byte)
            {
                return Err(BtxError::AddressDerivationFailed(
                    "Non-standard unspendable outputs do not have addresses".to_string(),
                )
                .into());
            }
        }
    }

    match Address::from_script(script_pubkey, network) {
        Ok(addr) => Ok(addr.as_unchecked().clone()),
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
/// script that cannot be mapped to an address (including OP_RETURN) causes the
/// conversion to fail.
///
/// # Arguments
/// * `txid` - The transaction ID that created this output
/// * `index` - The output index
/// * `txout` - The TxOut to convert
/// * `network` - Optional Bitcoin network (defaults to `Network::Bitcoin`)
///
/// # Returns
/// * `Ok(Utxo)` - The converted UTXO
/// * `Err(BtxError)` - If address derivation fails for the script
///
/// # Example
///
/// ```rust
/// use bitcoin::{Network, OutPoint, TxOut, Amount, ScriptBuf};
/// use merkle_morph::btx::conversion::txout_to_utxo;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let txout = TxOut {
///         value: Amount::from_sat(1000),
///         script_pubkey: ScriptBuf::from_hex("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap(),
///     };
///     let utxo = txout_to_utxo(OutPoint::default().txid, 0, &txout, None)?;
///     Ok(())
/// }
/// ```
pub fn txout_to_utxo(
    txid: Txid,
    index: u32,
    txout: &TxOut,
    network: Option<Network>,
) -> Result<Utxo> {
    let network = network.unwrap_or(Network::Bitcoin);
    let address = derive_address_from_script(&txout.script_pubkey, network)?;

    Ok(Utxo::with_script_pubkey(
        txid,
        index,
        txout.value.to_sat(),
        address,
        txout.script_pubkey.clone(),
    ))
}

/// Converts a bitcoin::Transaction to BitcoinTransaction
///
/// This conversion attempts to derive addresses from script_pubkeys, but note that:
/// - Input UTXOs require looking up the actual spent outputs (value, script_pubkey)
/// - Output addresses are derived from script_pubkeys
/// - For non-standard scripts (OP_RETURN), placeholder addresses are used
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
/// use bitcoin::{Network, Transaction, OutPoint, TxOut, TxIn, Amount, ScriptBuf};
/// use bitcoin::absolute::LockTime;
/// use merkle_morph::btx::conversion::transaction_to_btx;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let tx = Transaction {
///         version: bitcoin::transaction::Version::TWO,
///         lock_time: LockTime::ZERO,
///         input: vec![],
///         output: vec![],
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
        .input
        .iter()
        .map(|txin| {
            let outpoint = &txin.previous_output;

            let spent_output =
                spent_outputs(outpoint).ok_or(BtxError::MissingUtxoData(*outpoint))?;

            let utxo = txout_to_utxo(outpoint.txid, outpoint.vout, &spent_output, Some(network))?;

            Ok(TxInputData::new(utxo, txin.script_sig.clone(), txin.witness.clone(), txin.sequence))
        })
        .collect();

    let inputs_data = inputs_data?;

    let outputs: Result<Vec<Utxo>> = tx
        .output
        .iter()
        .enumerate()
        .map(|(idx, txout)| txout_to_utxo(txid, idx as u32, txout, Some(network)))
        .collect();

    let outputs = outputs?;

    Ok(BitcoinTransaction::with_scripts(tx.version, tx.lock_time, inputs_data, outputs))
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
impl TryFrom<BitcoinTransaction> for Transaction {
    type Error = crate::Error;

    fn try_from(btx: BitcoinTransaction) -> Result<Transaction> {
        if btx.inputs_data.is_empty() {
            return Err(BtxError::InvalidTransaction.into());
        }

        let input: Vec<TxIn> = btx
            .inputs_data
            .iter()
            .map(|input_data| TxIn {
                previous_output: input_data.utxo.outpoint(),
                script_sig: input_data.script_sig.clone(),
                sequence: input_data.sequence,
                witness: input_data.witness.clone(),
            })
            .collect();

        let output: Vec<TxOut> = btx.outputs.iter().map(utxo_to_txout).collect();

        Ok(Transaction { version: btx.version, lock_time: btx.lock_time, input, output })
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
    TxOut { value: Amount::from_sat(utxo.value), script_pubkey: utxo.script_pubkey() }
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
