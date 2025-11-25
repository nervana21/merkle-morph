//! Recovery transition
//!
//! This transition moves a channel from ForceClosingPending to Closed state.
//!
//! This transition specifies:
//! - Valid source and target states: ForceClosingPending → Closed
//! - Preconditions that must hold before the transition can be applied
//! - Postconditions that are guaranteed after a successful transition
//! - Input requirements and validation rules
//! - Nonce progression rules (nonce remains unchanged from force close state)
//! - Fee semantics and allocation policies

use crate::channel::commitment::state_commitment::compute_closed_commitment;
use crate::channel::state::{Closed, ForceClosingPending};
use crate::types::ChannelId;
use crate::Result;

/// Apply a recovery transition from ForceClosingPending to Closed state.
///
/// This transition is triggered when an older state is detected in a force close transaction,
/// indicating that the sender attempted to use a revoked state. When this occurs, all channel
/// funds are recovered by the receiver, and the sender's balance is set to zero.
///
/// In this unidirectional channel model, only the sender can commit old states because:
/// - Only the sender can initiate state transitions and sign them with their private key
/// - Only the sender has access to old signed states they previously created
/// - The receiver only receives state updates and cannot create or sign old states
///
/// **Fee Payment via P2A Anchor Outputs:**
/// The recovery transaction uses P2A (pay-to-anchor) outputs from the force close transaction
/// to pay fees dynamically. This allows the recovery transaction to "bring its own fees" without
/// requiring a static fee reserve in the channel balance. The state transition represents the
/// logical outcome where the receiver receives the full channel capacity; actual fee payment
/// is handled at the transaction level using anchor outputs.
///
/// # Arguments
/// * `state` - Current ForceClosingPending state containing the channel balances and metadata
/// * `channel_id` - Channel identifier used for commitment computation
///
/// # Returns
/// * `Ok(Closed)` - New Closed state with receiver receiving all funds and sender balance set to zero
/// * `Err(Error)` - Error if the transition cannot be applied (e.g., invalid state or commitment computation failure)
///
/// # Preconditions
/// - The state must be in `ForceClosingPending` state
/// - An older state must have been detected in the force close transaction
///
/// # Postconditions
/// - Channel is in `Closed` state
/// - Receiver balance equals total channel capacity
/// - Sender balance is zero
/// - Nonce remains unchanged from the force close state
/// - The invariant `sender_balance + receiver_balance == total_capacity` is preserved
pub fn apply_recover(state: &ForceClosingPending, channel_id: ChannelId) -> Result<Closed> {
    let mut closed_state = Closed::new(
        state.sender_pubkey,
        state.receiver_pubkey,
        state.total_capacity,
        0,                    // Sender gets 0
        state.total_capacity, // Receiver gets total capacity (fees paid via P2A anchor outputs)
        state.nonce,          // Nonce remains the same
    );

    closed_state.commitment = compute_closed_commitment(channel_id, &closed_state);

    Ok(closed_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::state::ForceClosingPendingParams;
    use crate::channel::test_utils::*;

    #[test]
    fn test_apply_recover() {
        let (sender_pubkey, receiver_pubkey) = test_keys();
        let state = ForceClosingPending::new(ForceClosingPendingParams {
            sender_pubkey,
            receiver_pubkey,
            total_capacity: 100,
            sender_balance: 90,
            receiver_balance: 0,
            total_fee: 10,
            nonce: 1,
            timeout_blocks: 144,
        });
        let channel_id = [0u8; 32];

        let result = apply_recover(&state, channel_id).expect("recover should succeed");

        assert_eq!(result.sender_balance, 0);
        assert_eq!(result.receiver_balance, 100);
        assert_eq!(result.total_capacity, 100);
        assert_eq!(result.nonce, 1);
    }
}
