//! Bitcoin transaction state representation
//!
//! This module defines the state structures for Bitcoin transactions,
//! including UTXO (Unspent Transaction Output) and BitcoinTransaction types.

use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::transaction::Version;
use bitcoin::{Address, OutPoint, ScriptBuf, Sequence, Txid, Witness};

/// Represents a Bitcoin UTXO (Unspent Transaction Output)
///
/// A UTXO is an output from a previous transaction that can be spent as an input
/// in a new transaction. It is uniquely identified by the transaction ID and output index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    /// Transaction ID of the transaction that created this UTXO
    pub txid: Txid,
    /// Output index within the transaction
    pub index: u32,
    /// Value in satoshis
    pub value: u64,
    /// Bitcoin address that can spend this UTXO
    pub address: Address<NetworkUnchecked>,
    /// Script public key (locking script) for this UTXO
    ///
    /// If `None`, the script_pubkey will be derived from the address.
    /// If `Some`, this explicit script_pubkey will be used.
    pub script_pubkey: Option<ScriptBuf>,
}

impl Utxo {
    /// Creates a new UTXO with the given parameters
    ///
    /// # Arguments
    /// * `txid` - Transaction ID
    /// * `index` - Output index
    /// * `value` - Value in satoshis
    /// * `address` - Bitcoin address
    pub fn new(txid: Txid, index: u32, value: u64, address: Address<NetworkUnchecked>) -> Self {
        Self { txid, index, value, address, script_pubkey: None }
    }

    /// Creates a new UTXO with explicit script_pubkey
    ///
    /// # Arguments
    /// * `txid` - Transaction ID
    /// * `index` - Output index
    /// * `value` - Value in satoshis
    /// * `address` - Bitcoin address
    /// * `script_pubkey` - Explicit script public key
    pub fn with_script_pubkey(
        txid: Txid,
        index: u32,
        value: u64,
        address: Address<NetworkUnchecked>,
        script_pubkey: ScriptBuf,
    ) -> Self {
        Self { txid, index, value, address, script_pubkey: Some(script_pubkey) }
    }

    /// Gets the transaction ID
    pub fn txid(&self) -> &Txid { &self.txid }

    /// Gets the output index
    pub fn index(&self) -> u32 { self.index }

    /// Gets the value in satoshis
    pub fn value(&self) -> u64 { self.value }

    /// Gets the Bitcoin address
    pub fn address(&self) -> &Address<NetworkUnchecked> { &self.address }

    /// Gets the script public key
    ///
    /// If an explicit script_pubkey was set, returns it.
    /// Otherwise, derives it from the address.
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.script_pubkey
            .clone()
            .unwrap_or_else(|| self.address.assume_checked_ref().script_pubkey().to_owned())
    }

    /// Gets the OutPoint for this UTXO
    pub fn outpoint(&self) -> OutPoint { OutPoint { txid: self.txid, vout: self.index } }
}

/// Represents full input data for a Bitcoin transaction
///
/// Contains the UTXO being spent along with the unlocking script data
/// (scriptSig for legacy, witness for SegWit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxInputData {
    /// The UTXO being spent
    pub utxo: Utxo,
    /// Script signature (unlocking script for legacy transactions)
    pub script_sig: ScriptBuf,
    /// Witness data (for SegWit transactions)
    pub witness: Witness,
    /// Sequence number
    pub sequence: Sequence,
}

impl TxInputData {
    /// Creates a new TxInputData
    ///
    /// # Arguments
    /// * `utxo` - The UTXO being spent
    /// * `script_sig` - Script signature
    /// * `witness` - Witness data
    /// * `sequence` - Sequence number
    pub fn new(utxo: Utxo, script_sig: ScriptBuf, witness: Witness, sequence: Sequence) -> Self {
        Self { utxo, script_sig, witness, sequence }
    }

    /// Creates a legacy input (no witness)
    pub fn legacy(utxo: Utxo, script_sig: ScriptBuf, sequence: Sequence) -> Self {
        Self { utxo, script_sig, witness: Witness::new(), sequence }
    }

    /// Creates a SegWit input (with witness, empty script_sig)
    pub fn segwit(utxo: Utxo, witness: Witness, sequence: Sequence) -> Self {
        Self { utxo, script_sig: ScriptBuf::new(), witness, sequence }
    }
}

/// Represents a Bitcoin transaction
///
/// A Bitcoin transaction consumes UTXOs as inputs and produces new UTXOs as outputs.
/// The transaction includes full input data with scripts and witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinTransaction {
    /// Transaction version
    pub version: Version,
    /// Lock time
    pub lock_time: LockTime,
    /// Full input data with scripts and witnesses
    pub inputs_data: Vec<TxInputData>,
    /// Output UTXOs being created
    pub outputs: Vec<Utxo>,
}

impl BitcoinTransaction {
    /// Creates a new Bitcoin transaction with the given inputs and outputs
    ///
    /// # Arguments
    /// * `inputs` - Vector of input UTXOs
    /// * `outputs` - Vector of output UTXOs
    ///
    /// Note: This creates TxInputData with empty scripts. For full script data,
    /// use `with_scripts()` instead.
    pub fn new(inputs: Vec<Utxo>, outputs: Vec<Utxo>) -> Self {
        let inputs_data: Vec<TxInputData> = inputs
            .into_iter()
            .map(|utxo| TxInputData::new(utxo, ScriptBuf::new(), Witness::new(), Sequence::MAX))
            .collect();
        Self { version: Version::TWO, lock_time: LockTime::ZERO, inputs_data, outputs }
    }

    /// Creates a new Bitcoin transaction with full script data
    ///
    /// # Arguments
    /// * `version` - Transaction version
    /// * `lock_time` - Lock time
    /// * `inputs_data` - Full input data with scripts/witnesses
    /// * `outputs` - Vector of output UTXOs
    pub fn with_scripts(
        version: Version,
        lock_time: LockTime,
        inputs_data: Vec<TxInputData>,
        outputs: Vec<Utxo>,
    ) -> Self {
        Self { version, lock_time, inputs_data, outputs }
    }

    /// Gets a reference to the input UTXOs
    ///
    /// This derives the UTXOs from the inputs_data field.
    pub fn inputs(&self) -> Vec<Utxo> {
        self.inputs_data.iter().map(|id| id.utxo.clone()).collect()
    }

    /// Gets a reference to the full input data
    pub fn inputs_data(&self) -> &[TxInputData] { &self.inputs_data }

    /// Gets a reference to the output UTXOs
    pub fn outputs(&self) -> &[Utxo] { &self.outputs }

    /// Checks if this transaction has full script data
    ///
    /// Returns true if at least one input has a non-empty script_sig or witness.
    pub fn has_scripts(&self) -> bool {
        self.inputs_data
            .iter()
            .any(|input| !input.script_sig.is_empty() || !input.witness.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::hashes::Hash;

    use super::*;

    #[test]
    fn test_utxo_new() {
        let mut txid_bytes = [0u8; 32];
        txid_bytes[0..4].copy_from_slice(&[0xab, 0xcd, 0x12, 0x34]);
        let txid = Txid::from_byte_array(txid_bytes);
        let address: Address<NetworkUnchecked> =
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse().expect("valid Bitcoin address");
        let utxo = Utxo::new(txid, 0, 1000, address.clone());
        assert_eq!(utxo.txid(), &txid);
        assert_eq!(utxo.index(), 0);
        assert_eq!(utxo.value(), 1000);
        assert_eq!(utxo.address(), &address);
    }

    #[test]
    fn test_utxo_getters() {
        let txid = Txid::from_byte_array([0x01; 32]);
        let address: Address<NetworkUnchecked> =
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse().expect("valid Bitcoin address");
        let utxo = Utxo::new(txid, 1, 5000, address.clone());
        assert_eq!(utxo.txid(), &txid);
        assert_eq!(utxo.index(), 1);
        assert_eq!(utxo.value(), 5000);
        assert_eq!(utxo.address(), &address);
    }

    #[test]
    fn test_bitcoin_transaction_new() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let txid3 = Txid::from_byte_array([0x03; 32]);
        let addr1: Address<NetworkUnchecked> =
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse().expect("valid Bitcoin address");
        let addr2: Address<NetworkUnchecked> =
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse().expect("valid Bitcoin address");
        let addr3: Address<NetworkUnchecked> =
            "1CounterpartyXXXXXXXXXXXXXXXUWLpVr".parse().expect("valid Bitcoin address");
        let inputs = vec![Utxo::new(txid1, 0, 1000, addr1), Utxo::new(txid2, 1, 2000, addr2)];
        let outputs = vec![Utxo::new(txid3, 0, 3000, addr3)];
        let tx = BitcoinTransaction::new(inputs.clone(), outputs.clone());
        assert_eq!(tx.inputs(), inputs);
        assert_eq!(tx.outputs(), &outputs[..]);
    }

    #[test]
    fn test_bitcoin_transaction_empty() {
        let tx = BitcoinTransaction::new(vec![], vec![]);
        assert!(tx.inputs().is_empty());
        assert!(tx.outputs().is_empty());
    }

    #[test]
    fn test_utxo_equality() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let addr: Address<NetworkUnchecked> =
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse().expect("valid Bitcoin address");
        let utxo1 = Utxo::new(txid1, 0, 1000, addr.clone());
        let utxo2 = Utxo::new(txid1, 0, 1000, addr.clone());
        let utxo3 = Utxo::new(txid2, 0, 1000, addr.clone());
        assert_eq!(utxo1, utxo2);
        assert_ne!(utxo1, utxo3);
    }

    #[test]
    fn test_bitcoin_transaction_equality() {
        let txid1 = Txid::from_byte_array([0x01; 32]);
        let txid2 = Txid::from_byte_array([0x02; 32]);
        let addr1: Address<NetworkUnchecked> =
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse().expect("valid Bitcoin address");
        let addr2: Address<NetworkUnchecked> =
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".parse().expect("valid Bitcoin address");
        let inputs = vec![Utxo::new(txid1, 0, 1000, addr1)];
        let outputs = vec![Utxo::new(txid2, 0, 1000, addr2)];
        let tx1 = BitcoinTransaction::new(inputs.clone(), outputs.clone());
        let tx2 = BitcoinTransaction::new(inputs.clone(), outputs.clone());
        let tx3 = BitcoinTransaction::new(vec![], outputs.clone());
        assert_eq!(tx1, tx2);
        assert_ne!(tx1, tx3);
    }
}
