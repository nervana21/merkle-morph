#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(clippy::unwrap_used)]
//! Channel state transition logic
//!
//! This module provides pure functions for applying state transitions to channels.
//! All transition logic is deterministic and side-effect free.

use crate::channel::commitment::compute_commitment;
use crate::channel::state::ChannelState;
use crate::channel::TransferAmount;
use crate::errors::ChannelError::{
    ChannelClosed, ChannelNonceOverflow, InsufficientBalance, InvalidZeroTransfer,
};
use crate::errors::Result;
use crate::types::ChannelId;
use crate::zkp::{prove_channel_transition, Proof, StarkConfig};

/// Result of a channel transfer operation
///
/// Contains the new state and a proof for the transition.
pub struct TransferResult {
    /// New channel state after transition
    pub new_state: ChannelState,
    /// Commitment to the new state
    pub commitment: crate::types::ChannelCommitment,
    /// Proof for the transition
    pub proof: Proof,
}

/// Internal function for pure state transitions
///
/// This function performs a pure state transition without generating proofs or commitments.
/// It is used internally by ZKP proof generation code and cross-channel claim operations.
///
/// # Arguments
/// * `state` - Current channel state
/// * `input` - Transfer input to apply
///
/// # Returns
/// * `Ok(ChannelState)` - New channel state after transfer
/// * `Err(ChannelError)` - Error if transfer is invalid
pub(crate) fn apply_transfer_state_only(
    state: &ChannelState,
    amount: &TransferAmount,
) -> Result<ChannelState> {
    // Check if channel is closed
    if state.is_closed {
        return Err(crate::errors::Error::Channel(ChannelClosed));
    }

    // Validate transfer amount (should already be validated in TransferAmount::new, but double-check)
    if **amount == 0 {
        return Err(crate::errors::Error::Channel(InvalidZeroTransfer));
    }

    // Compute new balances: check sender first (insufficient balance), then receiver (overflow)
    let new_sender_balance =
        state.sender_balance.checked_sub(**amount).ok_or(InsufficientBalance)?;
    let new_receiver_balance = state
        .receiver_balance
        .checked_add(**amount)
        .ok_or(crate::errors::ChannelError::BalanceOverflow)?;

    // Increment nonce
    let new_nonce = state.nonce.checked_add(1).ok_or(ChannelNonceOverflow)?;

    Ok(ChannelState {
        sender_balance: new_sender_balance,
        receiver_balance: new_receiver_balance,
        metadata: state.metadata.clone(),
        nonce: new_nonce,
        is_closed: false,
        commitment: state.commitment, // Will be updated by caller if needed
    })
}

/// Apply a transfer operation to a channel
///
/// This function generates a proof and commitment for the state transition.
///
/// # Arguments
/// * `state` - Current channel state
/// * `amount` - Transfer amount to apply
/// * `config` - STARK configuration for proof generation
/// * `channel_id` - Channel identifier
///
/// # Returns
/// * `Ok(TransferResult)` - Contains new state, commitment, and proof
/// * `Err(Error)` - Error if transfer or proof generation fails
///
/// # Examples
///
/// ```rust
/// use merkle_morph::channel::state::ChannelState;
/// use merkle_morph::channel::TransferAmount;
/// use merkle_morph::channel::transition::apply_transfer;
/// use merkle_morph::zkp::create_config;
///
/// let state = ChannelState::new(100);
/// let amount = TransferAmount::new(30)?;
/// let config = create_config()?;
/// let channel_id = [0u8; 32];
///
/// // Generate proof
/// let result = apply_transfer(&state, &amount, &config, channel_id)?;
/// assert_eq!(result.new_state.sender_balance, 70);
/// # Ok::<(), merkle_morph::errors::Error>(())
/// ```
pub fn apply_transfer(
    state: &ChannelState,
    amount: &TransferAmount,
    config: &StarkConfig,
    channel_id: ChannelId,
) -> Result<TransferResult> {
    // Apply the state transition
    let new_state = apply_transfer_state_only(state, amount)?;

    // Compute commitment for new state
    let commitment = compute_commitment(channel_id, &new_state);

    // Generate proof
    let proof = prove_channel_transition(config, channel_id, state, amount, &new_state)?;

    Ok(TransferResult { new_state, commitment, proof })
}

/// Calculate cooperative close outputs with fee payment policy
///
/// Implements the policy where the channel opener/funder (sender) pays the closing fees.
/// If the opener can't pay the full fee, the remainder is deducted from the counterparty.
///
/// # Arguments
/// * `sender_balance` - Balance of the sender (channel opener)
/// * `receiver_balance` - Balance of the receiver
/// * `closing_fee` - Total closing fee in satoshis
///
/// # Returns
/// Tuple of (sender_output, receiver_output) after fee deduction
///
/// # Examples
/// ```rust
/// use merkle_morph::channel::transition::calculate_cooperative_close_outputs;
///
/// // Opener has enough to pay full fee
/// let (sender, receiver) = calculate_cooperative_close_outputs(100, 50, 10);
/// assert_eq!(sender, 90);
/// assert_eq!(receiver, 50);
///
/// // Opener can't pay full fee
/// let (sender, receiver) = calculate_cooperative_close_outputs(5, 50, 10);
/// assert_eq!(sender, 0);
/// assert_eq!(receiver, 45);
/// ```
pub fn calculate_cooperative_close_outputs(
    sender_balance: u64,
    receiver_balance: u64,
    closing_fee: u64,
) -> (u64, u64) {
    // Sender is the opener, so they pay fees first
    if sender_balance >= closing_fee {
        (sender_balance - closing_fee, receiver_balance)
    } else {
        // Opener can't pay full fee, split it
        let remainder = closing_fee - sender_balance;
        if receiver_balance >= remainder {
            (0, receiver_balance - remainder)
        } else {
            // Neither can pay full fee - this shouldn't happen in practice
            // but handle gracefully by taking what's available
            let total_available = sender_balance.saturating_add(receiver_balance);
            if total_available >= closing_fee {
                (0, receiver_balance.saturating_sub(remainder))
            } else {
                // Total funds insufficient - return what's left after fee
                (0, 0)
            }
        }
    }
}

/// Calculate force close outputs with fee payment policy
///
/// Implements the policy where the party who force closes pays all fees.
///
/// # Arguments
/// * `sender_balance` - Balance of the sender
/// * `receiver_balance` - Balance of the receiver
/// * `closing_fee` - Total closing fee in satoshis
/// * `force_closer_is_sender` - Whether the sender initiated the force close
///
/// # Returns
/// Tuple of (sender_output, receiver_output) after fee deduction
///
/// # Examples
/// ```rust
/// use merkle_morph::channel::transition::calculate_force_close_outputs;
///
/// // Sender force closes
/// let (sender, receiver) = calculate_force_close_outputs(100, 50, 10, true);
/// assert_eq!(sender, 90);
/// assert_eq!(receiver, 50);
///
/// // Receiver force closes
/// let (sender, receiver) = calculate_force_close_outputs(100, 50, 10, false);
/// assert_eq!(sender, 100);
/// assert_eq!(receiver, 40);
/// ```
pub fn calculate_force_close_outputs(
    sender_balance: u64,
    receiver_balance: u64,
    closing_fee: u64,
    force_closer_is_sender: bool,
) -> (u64, u64) {
    if force_closer_is_sender {
        // Sender force closes - they pay fees
        if sender_balance >= closing_fee {
            (sender_balance - closing_fee, receiver_balance)
        } else {
            // Sender can't pay full fee, take what's available
            let remainder = closing_fee - sender_balance;
            if receiver_balance >= remainder {
                (0, receiver_balance - remainder)
            } else {
                (0, 0)
            }
        }
    } else {
        // Receiver force closes - they pay fees
        if receiver_balance >= closing_fee {
            (sender_balance, receiver_balance - closing_fee)
        } else {
            // Receiver can't pay full fee, take what's available
            let remainder = closing_fee - receiver_balance;
            if sender_balance >= remainder {
                (sender_balance - remainder, 0)
            } else {
                (0, 0)
            }
        }
    }
}

/// Apply a close operation to a channel
///
/// This is a pure function that finalizes a channel state, preventing further operations.
/// Closing a channel increments the nonce (maintaining sequence consistency) and sets
/// the `is_closed` flag to true.
///
/// # Arguments
/// * `state` - Current channel state
///
/// # Returns
/// * `Ok(ChannelState)` - New channel state with `is_closed: true`
/// * `Err(ChannelError::ChannelClosed)` - Error if channel is already closed
/// * `Err(ChannelError::ChannelNonceOverflow)` - Error if nonce would overflow
///
/// # Examples
/// ```rust
/// use merkle_morph::channel::state::ChannelState;
/// use merkle_morph::channel::transition::apply_close;
///
/// let state = ChannelState::new(100);
/// let closed_state = apply_close(&state)?;
/// assert!(closed_state.is_closed);
/// assert_eq!(closed_state.nonce, 1); // Nonce increments on close
/// # Ok::<(), merkle_morph::errors::Error>(())
/// ```
pub fn apply_close(state: &ChannelState) -> Result<ChannelState> {
    if state.is_closed {
        return Err(crate::errors::Error::Channel(ChannelClosed));
    }

    // Increment nonce (close is a state transition, maintains sequence consistency)
    let new_nonce = state.nonce.checked_add(1).ok_or(ChannelNonceOverflow)?;

    Ok(ChannelState {
        sender_balance: state.sender_balance,
        receiver_balance: state.receiver_balance,
        metadata: state.metadata.clone(),
        nonce: new_nonce,
        is_closed: true,
        commitment: state.commitment,
    })
}

/// Apply a cooperative close operation with fee deduction
///
/// This function closes a channel and applies the fee payment policy where the
/// channel opener (sender) pays the closing fees. If the opener can't pay the
/// full fee, the remainder is deducted from the receiver.
///
/// # Arguments
/// * `state` - Current channel state
/// * `closing_fee` - Total closing fee in satoshis
///
/// # Returns
/// * `Ok(ChannelState)` - New channel state with `is_closed: true` and adjusted balances
/// * `Err(ChannelError::ChannelClosed)` - Error if channel is already closed
/// * `Err(ChannelError::ChannelNonceOverflow)` - Error if nonce would overflow
///
/// # Examples
/// ```rust
/// use merkle_morph::channel::state::ChannelState;
/// use merkle_morph::channel::transition::apply_close_with_fees;
///
/// let state = ChannelState::new(100);
/// let closed_state = apply_close_with_fees(&state, 10)?;
/// assert!(closed_state.is_closed);
/// assert_eq!(closed_state.sender_balance, 90); // Fee deducted from opener
/// assert_eq!(closed_state.receiver_balance, 0);
/// # Ok::<(), merkle_morph::errors::Error>(())
/// ```
pub fn apply_close_with_fees(state: &ChannelState, closing_fee: u64) -> Result<ChannelState> {
    if state.is_closed {
        return Err(crate::errors::Error::Channel(ChannelClosed));
    }

    // Calculate outputs after fee deduction (cooperative close: opener pays)
    let (sender_output, receiver_output) = calculate_cooperative_close_outputs(
        state.sender_balance,
        state.receiver_balance,
        closing_fee,
    );

    // Increment nonce (close is a state transition, maintains sequence consistency)
    let new_nonce = state.nonce.checked_add(1).ok_or(ChannelNonceOverflow)?;

    Ok(ChannelState {
        sender_balance: sender_output,
        receiver_balance: receiver_output,
        metadata: state.metadata.clone(),
        nonce: new_nonce,
        is_closed: true,
        commitment: state.commitment,
    })
}

/// Apply a force close operation with fee deduction
///
/// This function closes a channel and applies the fee payment policy where the
/// party who force closes pays all fees.
///
/// # Arguments
/// * `state` - Current channel state
/// * `closing_fee` - Total closing fee in satoshis
/// * `force_closer_is_sender` - Whether the sender initiated the force close
///
/// # Returns
/// * `Ok(ChannelState)` - New channel state with `is_closed: true` and adjusted balances
/// * `Err(ChannelError::ChannelClosed)` - Error if channel is already closed
/// * `Err(ChannelError::ChannelNonceOverflow)` - Error if nonce would overflow
///
/// # Examples
/// ```rust
/// use merkle_morph::channel::state::ChannelState;
/// use merkle_morph::channel::transition::apply_force_close_with_fees;
///
/// let mut state = ChannelState::new(100);
/// state.receiver_balance = 50;
/// let closed_state = apply_force_close_with_fees(&state, 10, true)?;
/// assert!(closed_state.is_closed);
/// assert_eq!(closed_state.sender_balance, 90); // Sender pays fee
/// assert_eq!(closed_state.receiver_balance, 50);
/// # Ok::<(), merkle_morph::errors::Error>(())
/// ```
pub fn apply_force_close_with_fees(
    state: &ChannelState,
    closing_fee: u64,
    force_closer_is_sender: bool,
) -> Result<ChannelState> {
    if state.is_closed {
        return Err(crate::errors::Error::Channel(ChannelClosed));
    }

    // Calculate outputs after fee deduction (force close: force-closer pays)
    let (sender_output, receiver_output) = calculate_force_close_outputs(
        state.sender_balance,
        state.receiver_balance,
        closing_fee,
        force_closer_is_sender,
    );

    // Increment nonce (close is a state transition, maintains sequence consistency)
    let new_nonce = state.nonce.checked_add(1).ok_or(ChannelNonceOverflow)?;

    Ok(ChannelState {
        sender_balance: sender_output,
        receiver_balance: receiver_output,
        metadata: state.metadata.clone(),
        nonce: new_nonce,
        is_closed: true,
        commitment: state.commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::commitment::compute_commitment;
    use crate::channel::TransferAmount;
    use crate::errors::ChannelError;
    use crate::zkp::create_config;

    #[test]
    fn test_apply_transfer_state_only() {
        // Test the internal function directly
        let state = ChannelState::new(100);
        let amount = TransferAmount::new(30).expect("valid transfer");
        let new_state =
            apply_transfer_state_only(&state, &amount).expect("valid transfer should succeed");
        assert_eq!(new_state.sender_balance, 70);
        assert_eq!(new_state.receiver_balance, 30);
        assert_eq!(new_state.nonce, 1);
        assert!(!new_state.is_closed);

        // Insufficient balance (tested via apply_transfer_state_only)
        let state = ChannelState::new(100);
        let amount = TransferAmount::new(150).expect("valid amount");
        let result = apply_transfer_state_only(&state, &amount);
        assert!(matches!(
            result,
            Err(crate::errors::Error::Channel(ChannelError::InsufficientBalance))
        ));

        // Zero amount transfer (should fail in TransferAmount::new)
        let result = TransferAmount::new(0);
        assert!(matches!(result, Err(ChannelError::InvalidZeroTransfer)));

        // Transfer on closed channel
        let state = ChannelState::new(100);
        let closed_state = apply_close(&state).expect("close should succeed");
        let amount = TransferAmount::new(30).expect("valid transfer");
        let result = apply_transfer_state_only(&closed_state, &amount);
        assert!(matches!(result, Err(crate::errors::Error::Channel(ChannelError::ChannelClosed))));

        // Test full transfer
        let state = ChannelState::new(100);
        let amount = TransferAmount::new(100).expect("valid transfer");
        let full_transfer =
            apply_transfer_state_only(&state, &amount).expect("full transfer should succeed");
        assert_eq!(full_transfer.sender_balance, 0);
        assert_eq!(full_transfer.receiver_balance, 100);
        assert_eq!(full_transfer.nonce, 1);

        // Test transfer with metadata preservation
        let mut state_with_metadata = ChannelState::new(100);
        state_with_metadata.metadata = vec![1, 2, 3, 4, 5];
        let amount = TransferAmount::new(21).expect("valid transfer");
        let next_state = apply_transfer_state_only(&state_with_metadata, &amount)
            .expect("transfer should succeed");

        // Metadata should be preserved
        assert_eq!(next_state.metadata, vec![1, 2, 3, 4, 5]);

        // Balances should be updated
        assert_eq!(next_state.sender_balance, 79);
        assert_eq!(next_state.receiver_balance, 21);

        // Nonce should be incremented
        assert_eq!(next_state.nonce, 1);

        // Test balance overflow
        let mut overflow_state = ChannelState::new(100);
        overflow_state.receiver_balance = u64::MAX;
        let amount = TransferAmount::new(1).expect("valid transfer");
        let result = apply_transfer_state_only(&overflow_state, &amount);
        assert!(matches!(
            result,
            Err(crate::errors::Error::Channel(ChannelError::BalanceOverflow))
        ));

        // Test that original state is preserved on failure
        let mut original_state = ChannelState::new(100);
        original_state.metadata = vec![1, 2, 3, 4, 5];
        let original_metadata = original_state.metadata.clone();
        let original_sender_balance = original_state.sender_balance;
        let original_receiver_balance = original_state.receiver_balance;
        let original_nonce = original_state.nonce;

        // Attempt transfer that will fail (insufficient balance)
        let amount = TransferAmount::new(150).expect("valid amount");
        let transfer_result = apply_transfer_state_only(&original_state, &amount);
        assert!(matches!(
            transfer_result,
            Err(crate::errors::Error::Channel(ChannelError::InsufficientBalance))
        ));

        // Verify original state is unchanged (state is passed by reference, so this is implicit)
        // But we can verify the values we captured are still valid
        assert_eq!(original_state.metadata, original_metadata);
        assert_eq!(original_state.sender_balance, original_sender_balance);
        assert_eq!(original_state.receiver_balance, original_receiver_balance);
        assert_eq!(original_state.nonce, original_nonce);
    }

    #[test]
    fn test_apply_transfer() {
        let config = create_config().expect("Should create config");
        let channel_id = [0u8; 32];

        // Successful transfer: sender to receiver (with proof)
        let state = ChannelState::new(100);
        let amount = TransferAmount::new(30).expect("valid transfer");
        let result = apply_transfer(&state, &amount, &config, channel_id)
            .expect("valid transfer should succeed");
        assert_eq!(result.new_state.sender_balance, 70);
        assert_eq!(result.new_state.receiver_balance, 30);
        assert_eq!(result.new_state.nonce, 1);
        assert!(!result.new_state.is_closed);

        // Verify commitment matches
        let expected_commitment = compute_commitment(channel_id, &result.new_state);
        assert_eq!(result.commitment, expected_commitment);

        // Verify the proof
        use crate::zkp::{verify_channel_transition, ChannelPublicInputs};
        let public_inputs =
            ChannelPublicInputs { channel_id, channel_commitment: result.commitment };
        verify_channel_transition(&config, &public_inputs, &result.proof)
            .expect("proof should verify");

        // Test that each successful apply_transfer increments nonce by exactly 1
        let state1 =
            apply_transfer(&state, &TransferAmount::new(10).expect("valid"), &config, channel_id)
                .expect("transfer should succeed");
        assert_eq!(state1.new_state.nonce, 1);

        let state2 = apply_transfer(
            &state1.new_state,
            &TransferAmount::new(20).expect("valid"),
            &config,
            channel_id,
        )
        .expect("transfer should succeed");
        assert_eq!(state2.new_state.nonce, 2);

        let state3 = apply_transfer(
            &state2.new_state,
            &TransferAmount::new(30).expect("valid"),
            &config,
            channel_id,
        )
        .expect("transfer should succeed");
        assert_eq!(state3.new_state.nonce, 3);

        // Verify the progression is strictly monotonic
        assert!(state1.new_state.nonce < state2.new_state.nonce);
        assert!(state2.new_state.nonce < state3.new_state.nonce);

        // Test nonce overflow scenario
        let mut overflow_state = ChannelState::new(100);
        overflow_state.nonce = u32::MAX; // Set nonce to maximum value
        let amount = TransferAmount::new(10).expect("valid transfer");
        let overflow_result = apply_transfer(&overflow_state, &amount, &config, channel_id);
        assert!(matches!(
            overflow_result,
            Err(crate::errors::Error::Channel(ChannelError::ChannelNonceOverflow))
        ));
    }

    #[test]
    fn test_apply_close() {
        // Successful close
        let mut state = ChannelState::new(100);
        state.receiver_balance = 50;
        let closed_state = apply_close(&state).expect("close should succeed");
        assert!(closed_state.is_closed);
        assert_eq!(closed_state.sender_balance, 100);
        assert_eq!(closed_state.receiver_balance, 50);
        assert_eq!(closed_state.nonce, 1);

        // Close preserves balances
        assert_eq!(closed_state.sender_balance, state.sender_balance);
        assert_eq!(closed_state.receiver_balance, state.receiver_balance);

        // Close already closed channel
        let result = apply_close(&closed_state);
        assert!(matches!(result, Err(crate::errors::Error::Channel(ChannelError::ChannelClosed))));

        // Close increments nonce correctly
        let state = ChannelState::new(100);
        assert_eq!(state.nonce, 0);
        let closed_state = apply_close(&state).expect("close should succeed");
        assert_eq!(closed_state.nonce, 1);

        // Close after transfer increments nonce correctly
        let config = create_config().expect("Should create config");
        let channel_id = [0u8; 32];
        let amount = TransferAmount::new(10).expect("valid transfer");
        let transfer_result =
            apply_transfer(&state, &amount, &config, channel_id).expect("transfer should succeed");
        assert_eq!(transfer_result.new_state.nonce, 1);
        let closed_after_transfer =
            apply_close(&transfer_result.new_state).expect("close should succeed");
        assert_eq!(closed_after_transfer.nonce, 2);
    }

    #[test]
    fn test_calculate_cooperative_close_outputs() {
        // Opener (sender) has enough to pay full fee
        let (sender, receiver) = calculate_cooperative_close_outputs(100, 50, 10);
        assert_eq!(sender, 90);
        assert_eq!(receiver, 50);

        // Opener can't pay full fee, remainder from receiver
        let (sender, receiver) = calculate_cooperative_close_outputs(5, 50, 10);
        assert_eq!(sender, 0);
        assert_eq!(receiver, 45);

        // Opener can't pay full fee, receiver can cover remainder
        let (sender, receiver) = calculate_cooperative_close_outputs(3, 20, 10);
        assert_eq!(sender, 0);
        assert_eq!(receiver, 13);

        // Opener pays exact fee
        let (sender, receiver) = calculate_cooperative_close_outputs(10, 50, 10);
        assert_eq!(sender, 0);
        assert_eq!(receiver, 50);

        // Zero fee
        let (sender, receiver) = calculate_cooperative_close_outputs(100, 50, 0);
        assert_eq!(sender, 100);
        assert_eq!(receiver, 50);

        // Fee larger than opener balance, receiver covers
        let (sender, receiver) = calculate_cooperative_close_outputs(5, 100, 20);
        assert_eq!(sender, 0);
        assert_eq!(receiver, 85);

        // Neither can pay full fee - edge case
        let (sender, receiver) = calculate_cooperative_close_outputs(5, 10, 20);
        assert_eq!(sender, 0);
        assert_eq!(receiver, 0);

        // Total funds insufficient
        let (sender, receiver) = calculate_cooperative_close_outputs(5, 5, 20);
        assert_eq!(sender, 0);
        assert_eq!(receiver, 0);
    }

    #[test]
    fn test_calculate_force_close_outputs() {
        // Sender force closes - they pay full fee
        let (sender, receiver) = calculate_force_close_outputs(100, 50, 10, true);
        assert_eq!(sender, 90);
        assert_eq!(receiver, 50);

        // Receiver force closes - they pay full fee
        let (sender, receiver) = calculate_force_close_outputs(100, 50, 10, false);
        assert_eq!(sender, 100);
        assert_eq!(receiver, 40);

        // Sender force closes but can't pay full fee
        let (sender, receiver) = calculate_force_close_outputs(5, 50, 10, true);
        assert_eq!(sender, 0);
        assert_eq!(receiver, 45);

        // Receiver force closes but can't pay full fee
        let (sender, receiver) = calculate_force_close_outputs(100, 5, 10, false);
        assert_eq!(sender, 95);
        assert_eq!(receiver, 0);

        // Zero fee
        let (sender, receiver) = calculate_force_close_outputs(100, 50, 0, true);
        assert_eq!(sender, 100);
        assert_eq!(receiver, 50);

        // Fee larger than force-closer balance
        let (sender, receiver) = calculate_force_close_outputs(5, 50, 20, true);
        assert_eq!(sender, 0);
        assert_eq!(receiver, 35);
    }

    #[test]
    fn test_apply_close_with_fees() {
        // Successful cooperative close with fees
        let state = ChannelState::new(100);
        let closed_state = apply_close_with_fees(&state, 10).expect("close should succeed");
        assert!(closed_state.is_closed);
        assert_eq!(closed_state.sender_balance, 90); // Fee deducted from opener
        assert_eq!(closed_state.receiver_balance, 0);
        assert_eq!(closed_state.nonce, 1);

        // Opener can't pay full fee
        let mut state = ChannelState::new(5);
        state.receiver_balance = 50;
        let closed_state = apply_close_with_fees(&state, 10).expect("close should succeed");
        assert!(closed_state.is_closed);
        assert_eq!(closed_state.sender_balance, 0);
        assert_eq!(closed_state.receiver_balance, 45); // Remainder deducted from receiver
        assert_eq!(closed_state.nonce, 1);

        // Zero fee
        let state = ChannelState::new(100);
        let closed_state = apply_close_with_fees(&state, 0).expect("close should succeed");
        assert!(closed_state.is_closed);
        assert_eq!(closed_state.sender_balance, 100);
        assert_eq!(closed_state.receiver_balance, 0);

        // Close already closed channel
        let state = ChannelState::new(100);
        let closed_state = apply_close_with_fees(&state, 10).expect("close should succeed");
        let result = apply_close_with_fees(&closed_state, 10);
        assert!(matches!(result, Err(crate::errors::Error::Channel(ChannelError::ChannelClosed))));

        // Metadata preserved
        let mut state = ChannelState::new(100);
        state.metadata = vec![1, 2, 3];
        let closed_state = apply_close_with_fees(&state, 10).expect("close should succeed");
        assert_eq!(closed_state.metadata, vec![1, 2, 3]);
    }

    #[test]
    fn test_apply_force_close_with_fees() {
        // Sender force closes
        let mut state = ChannelState::new(100);
        state.receiver_balance = 50;
        let closed_state =
            apply_force_close_with_fees(&state, 10, true).expect("close should succeed");
        assert!(closed_state.is_closed);
        assert_eq!(closed_state.sender_balance, 90); // Sender pays fee
        assert_eq!(closed_state.receiver_balance, 50);
        assert_eq!(closed_state.nonce, 1);

        // Receiver force closes
        let mut state = ChannelState::new(100);
        state.receiver_balance = 50;
        let closed_state =
            apply_force_close_with_fees(&state, 10, false).expect("close should succeed");
        assert!(closed_state.is_closed);
        assert_eq!(closed_state.sender_balance, 100);
        assert_eq!(closed_state.receiver_balance, 40); // Receiver pays fee
        assert_eq!(closed_state.nonce, 1);

        // Sender force closes but can't pay full fee
        let mut state = ChannelState::new(5);
        state.receiver_balance = 50;
        let closed_state =
            apply_force_close_with_fees(&state, 10, true).expect("close should succeed");
        assert!(closed_state.is_closed);
        assert_eq!(closed_state.sender_balance, 0);
        assert_eq!(closed_state.receiver_balance, 45); // Remainder from receiver

        // Receiver force closes but can't pay full fee
        let mut state = ChannelState::new(100);
        state.receiver_balance = 5;
        let closed_state =
            apply_force_close_with_fees(&state, 10, false).expect("close should succeed");
        assert!(closed_state.is_closed);
        assert_eq!(closed_state.sender_balance, 95); // Remainder from sender
        assert_eq!(closed_state.receiver_balance, 0);

        // Zero fee
        let mut state = ChannelState::new(100);
        state.receiver_balance = 50;
        let closed_state =
            apply_force_close_with_fees(&state, 0, true).expect("close should succeed");
        assert_eq!(closed_state.sender_balance, 100);
        assert_eq!(closed_state.receiver_balance, 50);

        // Close already closed channel
        let state = ChannelState::new(100);
        let closed_state =
            apply_force_close_with_fees(&state, 10, true).expect("close should succeed");
        let result = apply_force_close_with_fees(&closed_state, 10, true);
        assert!(matches!(result, Err(crate::errors::Error::Channel(ChannelError::ChannelClosed))));

        // Metadata preserved
        let mut state = ChannelState::new(100);
        state.metadata = vec![4, 5, 6];
        let closed_state =
            apply_force_close_with_fees(&state, 10, true).expect("close should succeed");
        assert_eq!(closed_state.metadata, vec![4, 5, 6]);
    }
}
