// SPDX-License-Identifier: CC0-1.0

//! Multi-party anchoring functionality for Bitcoin
//!
//! Functions for building, validating, and managing multi-party anchor transactions
//! that allow multiple parties to share transaction fees.

use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::key::XOnlyPublicKey;
use bitcoin::Network;

use super::p2a::{build_p2a_txout, derive_default_p2a_internal_key, verify_p2a_script};
use super::types::{
    AnchorResult, MultiPartyAnchorRequest, MultiPartyAnchoringConfig, MultiPartyContribution,
    MultiPartySessionState,
};
use crate::btx::state::{BitcoinTransaction, TxInputData, Utxo};
use crate::types::{Bytes32, P2A_DEFAULT_NETWORK, P2A_DEFAULT_VALUE_SATS};

/// Get current Unix timestamp in seconds
pub(crate) fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Build a multi-party anchor transaction with anchor output
///
/// Creates a partial transaction containing the anchor output and initiator's inputs.
/// This transaction is ready for multi-party contributions.
///
/// # Arguments
/// * `global_root` - The global root to anchor
/// * `nonce` - Nonce for this anchor
/// * `initiator_inputs` - Inputs from the initiator
/// * `internal_key` - Internal key for P2A address
/// * `network` - Bitcoin network
/// * `anchor_value` - Value for anchor output in satoshis
///
/// # Returns
/// A tuple of (BitcoinTransaction, anchor_output_index)
pub fn build_multi_party_anchor_tx(
    global_root: Bytes32,
    nonce: u32,
    initiator_inputs: Vec<TxInputData>,
    internal_key: XOnlyPublicKey,
    network: Network,
    anchor_value: u64,
) -> Result<(BitcoinTransaction, usize), String> {
    // Build anchor output
    let anchor_output = build_p2a_txout(global_root, nonce, internal_key, anchor_value, network)
        .map_err(|e| format!("Failed to build anchor output: {e}"))?;
    let anchor_address = *bitcoin::Address::from_script(&anchor_output.script_pubkey, network)
        .map_err(|e| format!("Failed to derive address: {e}"))?
        .as_unchecked();
    let anchor_utxo = Utxo::with_script_pubkey(
        bitcoin::Txid::from_byte_array([0u8; 32]), // Placeholder txid
        0,                                         // Placeholder index
        anchor_value,
        anchor_address,
        anchor_output.script_pubkey.clone(),
    );

    // Create transaction with anchor output and initiator inputs
    let outputs = vec![anchor_utxo];
    let tx = BitcoinTransaction::with_scripts(
        bitcoin::transaction::Version::THREE,
        initiator_inputs,
        outputs,
        bitcoin::absolute::LockTime::ZERO,
    );

    // Anchor output is at index 0
    Ok((tx, 0))
}

/// Validate a multi-party contribution
///
/// Ensures the contribution is valid and doesn't violate multi-party anchoring rules.
///
/// # Arguments
/// * `session` - Current session state
/// * `contribution` - Contribution to validate
///
/// # Returns
/// Ok(()) if valid, Err with reason if invalid
pub fn validate_multi_party_contribution(
    session: &MultiPartySessionState,
    contribution: &MultiPartyContribution,
) -> Result<(), String> {
    // Check max contributors limit
    let config = &session.request.config;
    // Count: initiator (1) + existing contributions
    let current_count = 1 + session.contributions.len();
    if let Some(max) = config.max_contributors {
        if current_count >= max as usize {
            return Err(format!("Maximum contributors ({}) reached", max));
        }
    }

    // Check for duplicate inputs
    let existing_outpoints: std::collections::HashSet<_> =
        session.current_tx.inputs_data.iter().map(|input| input.utxo.outpoint()).collect();

    for input in &contribution.inputs {
        if existing_outpoints.contains(&input.utxo.outpoint()) {
            return Err("Duplicate input detected".to_string());
        }
    }

    // Validate contribution has inputs
    if contribution.inputs.is_empty() {
        return Err("Contribution must have at least one input".to_string());
    }

    Ok(())
}

/// Add a multi-party contribution to a multi-party anchor transaction
///
/// Adds the contribution's inputs and change output to the multi-party
/// anchor transaction.
///
/// # Arguments
/// * `tx` - Current multi-party anchor transaction state
/// * `contribution` - Contribution to add
///
/// # Returns
/// Updated multi-party anchor transaction with contribution added
pub fn add_multi_party_contribution(
    mut tx: BitcoinTransaction,
    contribution: MultiPartyContribution,
) -> BitcoinTransaction {
    // Add contribution inputs
    tx.inputs_data.extend(contribution.inputs);

    // Add change output if present
    if let Some(change) = contribution.change_output {
        tx.outputs.push(change);
    }

    tx
}

/// Calculate fee split among contributors
///
/// Implements "pay what you can" fee model:
/// - Multi-party contributors contribute what they can (input_value - change_output_value)
/// - Initiator pays the remainder, split proportionally among their inputs
///
/// # Arguments
/// * `session` - Multi-party session state
/// * `total_fee` - Total fee in satoshis
///
/// # Returns
/// Vector of (input_index, fee_amount) tuples for inputs that should pay fees.
/// Only initiator inputs are returned (contributors have already "paid" via their contributions).
pub fn calculate_multi_party_fee_split(
    session: &MultiPartySessionState,
    total_fee: u64,
) -> Vec<(usize, u64)> {
    // Identify initiator inputs by comparing with original partial transaction
    let initiator_inputs: std::collections::HashSet<_> =
        session.request.partial_tx.inputs_data.iter().map(|input| input.utxo.outpoint()).collect();

    // Calculate total contribution from multi-party participants
    // Each contributor's contribution = sum of their input values - sum of their change output values
    let mut total_contribution = 0u64;
    for contribution in &session.contributions {
        let contrib_input_value: u64 =
            contribution.inputs.iter().map(|input| input.utxo.value).sum();
        let contrib_change_value: u64 =
            contribution.change_output.as_ref().map(|utxo| utxo.value).unwrap_or(0);
        total_contribution += contrib_input_value.saturating_sub(contrib_change_value);
    }

    // Initiator must pay the remainder
    let initiator_fee = total_fee.saturating_sub(total_contribution);

    // If no fees for initiator or no initiator inputs, return empty
    if initiator_fee == 0 {
        return Vec::new();
    }

    // Find initiator input indices and calculate total initiator input value
    let mut initiator_indices = Vec::new();
    let mut initiator_total_value = 0u64;

    for (idx, input) in session.current_tx.inputs_data.iter().enumerate() {
        if initiator_inputs.contains(&input.utxo.outpoint()) {
            initiator_indices.push(idx);
            initiator_total_value += input.utxo.value;
        }
    }

    if initiator_indices.is_empty() || initiator_total_value == 0 {
        return Vec::new();
    }

    // Split initiator's fee portion proportionally among their inputs
    let mut splits = Vec::new();
    let mut remaining_fee = initiator_fee;

    for &idx in &initiator_indices {
        let input_value = session.current_tx.inputs_data[idx].utxo.value;
        let proportion = (input_value as f64) / (initiator_total_value as f64);
        let fee_amount = (initiator_fee as f64 * proportion) as u64;
        splits.push((idx, fee_amount));
        remaining_fee = remaining_fee.saturating_sub(fee_amount);
    }

    // Distribute any remainder from rounding proportionally
    if remaining_fee > 0 && !splits.is_empty() {
        let remainder_per_input = remaining_fee / splits.len() as u64;
        let extra_remainder = remaining_fee % splits.len() as u64;

        for split in &mut splits {
            split.1 += remainder_per_input;
        }

        // Add any final remainder to the first initiator input
        if extra_remainder > 0 {
            splits[0].1 += extra_remainder;
        }
    }

    splits
}

/// Default implementation for creating a multi-party anchor request
///
/// Implementations can override `create_multi_party_anchor_request` in the trait,
/// but this provides a sensible default that builds the partial transaction
/// with the anchor output.
pub fn default_create_multi_party_anchor_request(
    global_root: Bytes32,
    nonce: u32,
    fee_rate: u64,
    initiator_inputs: Vec<TxInputData>,
    config: Option<MultiPartyAnchoringConfig>,
) -> Result<MultiPartyAnchorRequest, String> {
    let config = config.unwrap_or_default();
    let internal_key = derive_default_p2a_internal_key()?;
    let anchor_value = P2A_DEFAULT_VALUE_SATS;

    let (partial_tx, anchor_output_index) = build_multi_party_anchor_tx(
        global_root,
        nonce,
        initiator_inputs,
        internal_key,
        P2A_DEFAULT_NETWORK,
        anchor_value,
    )?;

    Ok(MultiPartyAnchorRequest {
        partial_tx,
        global_root,
        nonce,
        anchor_output_index,
        fee_rate,
        config,
        created_at: current_timestamp(),
    })
}

/// Default implementation for contributing to a multi-party anchor
///
/// Validates the contribution (checks max contributors, duplicate inputs, etc.)
/// and adds it to the session state by adding the contributor's inputs and
/// change output to the transaction. Implementations can override
/// `contribute_to_multi_party_anchor` in the trait, but this provides a sensible
/// default that handles validation and state updates.
pub fn default_contribute_to_multi_party_anchor(
    session: &MultiPartySessionState,
    contribution: MultiPartyContribution,
) -> Result<MultiPartySessionState, String> {
    // Validate contribution
    validate_multi_party_contribution(session, &contribution)?;

    // Add contribution
    let updated_tx = add_multi_party_contribution(session.current_tx.clone(), contribution.clone());

    // Create updated session
    let mut updated_contributions = session.contributions.clone();
    updated_contributions.push(contribution);

    Ok(MultiPartySessionState {
        request: session.request.clone(),
        contributions: updated_contributions,
        current_tx: updated_tx,
    })
}

/// Default implementation for finalizing a multi-party anchor
///
/// Validates the session meets all requirements (min/max contributors, timeout,
/// anchor output preservation). This default implementation only performs validation
/// and returns an error. Implementations must override this method to actually
/// sign all inputs and broadcast the transaction to the Bitcoin network.
pub fn default_finalize_multi_party_anchor(
    session: &MultiPartySessionState,
) -> Result<AnchorResult, String> {
    // Validate session meets requirements
    let config = &session.request.config;
    let contributor_count = 1 + session.contributions.len();

    // Check max contributors
    if let Some(max) = config.max_contributors {
        if contributor_count > max as usize {
            return Err(format!("Too many contributors: got {}, max {}", contributor_count, max));
        }
    }

    // Check timeout
    if let Some(timeout) = config.timeout_seconds {
        let elapsed = current_timestamp().saturating_sub(session.request.created_at);
        if elapsed > timeout {
            return Err("Multi-party anchoring session timed out".to_string());
        }
    }

    // Check anchor output is preserved
    if session.current_tx.outputs.len() <= session.request.anchor_output_index {
        return Err("Anchor output missing from transaction".to_string());
    }

    let anchor_output = &session.current_tx.outputs[session.request.anchor_output_index];
    if !verify_p2a_script(
        &anchor_output.script_pubkey(),
        session.request.global_root,
        session.request.nonce,
        derive_default_p2a_internal_key()?,
        P2A_DEFAULT_NETWORK,
    ) {
        return Err("Anchor output script does not match expected P2A script".to_string());
    }

    // Default implementation can't actually broadcast, so return error
    // Implementations should override this method
    Err("finalize_multi_party_anchor must be implemented by BitcoinAnchoring implementation"
        .to_string())
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::address::NetworkUnchecked;
    use bitcoin::script::ScriptSigBuf;
    use bitcoin::transaction::Version;
    use bitcoin::{Address, Sequence, Txid, Witness};

    use super::*;

    fn dummy_utxo(value: u64) -> Utxo {
        let txid = Txid::from_byte_array([1u8; 32]);
        let address: Address<NetworkUnchecked> =
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".parse().expect("valid test address");
        Utxo::new(txid, 0, value, address)
    }

    fn dummy_utxo_with_index(value: u64, index: u32) -> Utxo {
        let mut txid_bytes = [1u8; 32];
        // Use index to make unique txid
        txid_bytes[0..4].copy_from_slice(&index.to_le_bytes());
        let txid = Txid::from_byte_array(txid_bytes);
        let address: Address<NetworkUnchecked> =
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".parse().expect("valid test address");
        Utxo::new(txid, 0, value, address)
    }

    fn dummy_tx_input_data(utxo: Utxo) -> TxInputData {
        TxInputData::new(utxo, ScriptSigBuf::new(), Witness::new(), Sequence::MAX)
    }

    fn dummy_multi_party_session_state() -> MultiPartySessionState {
        let global_root = [10u8; 32];
        let nonce = 1u32;
        let internal_key = derive_default_p2a_internal_key().expect("default key should be valid");
        let (partial_tx, anchor_output_index) = build_multi_party_anchor_tx(
            global_root,
            nonce,
            vec![],
            internal_key,
            P2A_DEFAULT_NETWORK,
            P2A_DEFAULT_VALUE_SATS,
        )
        .expect("should build valid multi-party anchor tx");
        let request = MultiPartyAnchorRequest {
            partial_tx: partial_tx.clone(),
            global_root,
            nonce,
            anchor_output_index,
            fee_rate: 1,
            config: MultiPartyAnchoringConfig::default(),
            created_at: 1000,
        };
        MultiPartySessionState { request, contributions: vec![], current_tx: partial_tx }
    }

    #[test]
    fn test_build_multi_party_anchor_tx() {
        let global_root = [20u8; 32];
        let nonce = 2u32;
        let internal_key = derive_default_p2a_internal_key().expect("default key should be valid");
        let network = P2A_DEFAULT_NETWORK;
        let anchor_value = 100u64;
        let initiator_inputs = vec![dummy_tx_input_data(dummy_utxo(1000))];

        let result = build_multi_party_anchor_tx(
            global_root,
            nonce,
            initiator_inputs,
            internal_key,
            network,
            anchor_value,
        );

        assert!(result.is_ok());
        let (tx, idx) = result.expect("should build valid multi-party anchor tx");
        assert_eq!(idx, 0);
        assert_eq!(tx.outputs.len(), 1);
        let expected_anchor =
            build_p2a_txout(global_root, nonce, internal_key, anchor_value, network)
                .expect("should build valid anchor");
        assert_eq!(tx.outputs[0].script_pubkey(), expected_anchor.script_pubkey);
        assert_eq!(tx.outputs[0].value, anchor_value);
    }

    #[test]
    fn test_validate_multi_party_contribution() {
        let mut session = dummy_multi_party_session_state();
        session.request.config.max_contributors = Some(1);
        session.contributions.push(MultiPartyContribution {
            inputs: vec![dummy_tx_input_data(dummy_utxo(500))],
            change_output: None,
            contributor_id: None,
        });
        let contribution1 = MultiPartyContribution {
            inputs: vec![dummy_tx_input_data(dummy_utxo(600))],
            change_output: None,
            contributor_id: None,
        };

        assert!(validate_multi_party_contribution(&session, &contribution1).is_err());

        let mut session2 = dummy_multi_party_session_state();
        let existing_input = dummy_tx_input_data(dummy_utxo(500));
        let existing_outpoint = existing_input.utxo.outpoint();
        session2.current_tx.inputs_data.push(existing_input);
        let contribution2 = MultiPartyContribution {
            inputs: vec![dummy_tx_input_data(Utxo::with_script_pubkey(
                existing_outpoint.txid,
                existing_outpoint.vout,
                600,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".parse().expect("valid test address"),
                bitcoin::script::ScriptPubKeyBuf::new(),
            ))],
            change_output: None,
            contributor_id: None,
        };

        assert!(validate_multi_party_contribution(&session2, &contribution2).is_err());

        let session3 = dummy_multi_party_session_state();
        let contribution3 =
            MultiPartyContribution { inputs: vec![], change_output: None, contributor_id: None };

        assert!(validate_multi_party_contribution(&session3, &contribution3).is_err());

        let session4 = dummy_multi_party_session_state();
        let contribution4 = MultiPartyContribution {
            inputs: vec![dummy_tx_input_data(dummy_utxo(700))],
            change_output: None,
            contributor_id: None,
        };

        assert!(validate_multi_party_contribution(&session4, &contribution4).is_ok());
    }

    #[test]
    fn test_add_multi_party_contribution() {
        let tx = BitcoinTransaction::with_scripts(Version::TWO, vec![], vec![], LockTime::ZERO);
        let contribution1 = MultiPartyContribution {
            inputs: vec![dummy_tx_input_data(dummy_utxo(500))],
            change_output: None,
            contributor_id: None,
        };

        let added1 = add_multi_party_contribution(tx.clone(), contribution1);

        assert_eq!(added1.inputs_data.len(), 1);
        assert_eq!(added1.outputs.len(), 0);

        let contribution2 = MultiPartyContribution {
            inputs: vec![dummy_tx_input_data(dummy_utxo(600))],
            change_output: Some(dummy_utxo(100)),
            contributor_id: None,
        };

        let added2 = add_multi_party_contribution(tx, contribution2);

        assert_eq!(added2.inputs_data.len(), 1);
        assert_eq!(added2.outputs.len(), 1);
    }

    #[test]
    fn test_calculate_multi_party_fee_split() {
        let mut session = dummy_multi_party_session_state();
        let zero_input1 = dummy_tx_input_data(dummy_utxo(0));
        let zero_input2 = dummy_tx_input_data(dummy_utxo(0));
        session.request.partial_tx.inputs_data = vec![zero_input1.clone(), zero_input2.clone()];
        session.current_tx.inputs_data = vec![zero_input1, zero_input2];

        let splits1 = calculate_multi_party_fee_split(&session, 100);

        assert!(splits1.is_empty());

        let init_input1 = dummy_tx_input_data(dummy_utxo(1000));
        let init_input2 = dummy_tx_input_data(dummy_utxo(2000));
        session.request.partial_tx.inputs_data = vec![init_input1.clone(), init_input2.clone()];
        session.current_tx.inputs_data = vec![init_input1, init_input2];
        session.contributions = vec![];

        let splits2 = calculate_multi_party_fee_split(&session, 100);

        assert_eq!(splits2.len(), 2);
        let total_fee: u64 = splits2.iter().map(|(_, fee)| fee).sum();
        assert_eq!(total_fee, 100);
        assert!(splits2[0].1 >= 33 && splits2[0].1 <= 34);
        assert!(splits2[1].1 >= 66 && splits2[1].1 <= 67);

        let init_input3 = dummy_tx_input_data(dummy_utxo_with_index(10000, 10));
        session.request.partial_tx.inputs_data = vec![init_input3.clone()];
        session.current_tx.inputs_data = vec![init_input3];

        let contrib_a_input = dummy_tx_input_data(dummy_utxo_with_index(1000, 20));
        let contrib_a = MultiPartyContribution {
            inputs: vec![contrib_a_input.clone()],
            change_output: Some(dummy_utxo_with_index(800, 21)),
            contributor_id: None,
        };

        let contrib_b_input = dummy_tx_input_data(dummy_utxo_with_index(100, 30));
        let contrib_b = MultiPartyContribution {
            inputs: vec![contrib_b_input.clone()],
            change_output: Some(dummy_utxo_with_index(80, 31)),
            contributor_id: None,
        };

        session.contributions = vec![contrib_a, contrib_b];
        session.current_tx.inputs_data.push(contrib_a_input);
        session.current_tx.inputs_data.push(contrib_b_input);

        let splits3 = calculate_multi_party_fee_split(&session, 1000);

        assert_eq!(splits3.len(), 1);
        assert_eq!(splits3[0].1, 780);
        let contrib_c_input = dummy_tx_input_data(dummy_utxo_with_index(1000, 40));
        let contrib_c = MultiPartyContribution {
            inputs: vec![contrib_c_input.clone()],
            change_output: None,
            contributor_id: None,
        };
        session.contributions = vec![contrib_c];
        session.current_tx.inputs_data =
            vec![session.request.partial_tx.inputs_data[0].clone(), contrib_c_input];

        let splits4 = calculate_multi_party_fee_split(&session, 1000);

        assert!(splits4.is_empty());
    }

    #[test]
    fn test_default_create_multi_party_anchor_request() {
        let global_root = [30u8; 32];
        let nonce = 3u32;
        let fee_rate = 10u64;
        let initiator_inputs = vec![dummy_tx_input_data(dummy_utxo(1000))];

        let result = default_create_multi_party_anchor_request(
            global_root,
            nonce,
            fee_rate,
            initiator_inputs,
            None,
        );

        assert!(result.is_ok());
        let request = result.expect("should create valid multi-party anchor request");
        assert_eq!(request.global_root, global_root);
        assert_eq!(request.nonce, nonce);
        assert_eq!(request.fee_rate, fee_rate);
        assert_eq!(request.anchor_output_index, 0);
        let expected_anchor = build_p2a_txout(
            global_root,
            nonce,
            derive_default_p2a_internal_key().expect("default key should be valid"),
            P2A_DEFAULT_VALUE_SATS,
            P2A_DEFAULT_NETWORK,
        )
        .expect("should build valid anchor");
        assert_eq!(request.partial_tx.outputs[0].script_pubkey(), expected_anchor.script_pubkey);
    }

    #[test]
    fn test_default_contribute_to_multi_party_anchor() {
        let session = dummy_multi_party_session_state();
        let invalid_contribution =
            MultiPartyContribution { inputs: vec![], change_output: None, contributor_id: None };

        assert!(default_contribute_to_multi_party_anchor(&session, invalid_contribution).is_err());

        let valid_contribution = MultiPartyContribution {
            inputs: vec![dummy_tx_input_data(dummy_utxo(500))],
            change_output: None,
            contributor_id: None,
        };

        let result = default_contribute_to_multi_party_anchor(&session, valid_contribution);

        assert!(result.is_ok());
        let updated_session = result.expect("should contribute to multi-party anchor");
        assert_eq!(updated_session.contributions.len(), 1);
        assert_eq!(updated_session.current_tx.inputs_data.len(), 1);
    }

    #[test]
    fn test_default_finalize_multi_party_anchor() {
        let mut session1 = dummy_multi_party_session_state();
        session1.request.config.max_contributors = Some(1);
        session1.contributions.push(MultiPartyContribution {
            inputs: vec![dummy_tx_input_data(dummy_utxo(500))],
            change_output: None,
            contributor_id: None,
        });
        session1.contributions.push(MultiPartyContribution {
            inputs: vec![dummy_tx_input_data(dummy_utxo(600))],
            change_output: None,
            contributor_id: None,
        });

        assert!(default_finalize_multi_party_anchor(&session1).is_err());

        let mut session2 = dummy_multi_party_session_state();
        session2.request.config.timeout_seconds = Some(10);
        session2.request.created_at = current_timestamp().saturating_sub(20);

        assert!(default_finalize_multi_party_anchor(&session2).is_err());

        let mut session3 = dummy_multi_party_session_state();
        session3.current_tx.outputs.clear();

        assert!(default_finalize_multi_party_anchor(&session3).is_err());

        let mut session4 = dummy_multi_party_session_state();
        session4.request.global_root = [99u8; 32];

        assert!(default_finalize_multi_party_anchor(&session4).is_err());

        let mut session5 = dummy_multi_party_session_state();
        session5.request.created_at = current_timestamp();
        session5.request.config.timeout_seconds = None;

        let result = default_finalize_multi_party_anchor(&session5);

        let err_msg = result.expect_err("should return error");
        assert!(
            err_msg.contains("finalize_multi_party_anchor must be implemented"),
            "Expected error message containing 'finalize_multi_party_anchor must be implemented', got: {}",
            err_msg
        );
    }
}
