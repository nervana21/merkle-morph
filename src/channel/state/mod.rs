//! Channel lifecycle states
//!
//! This module defines the channel lifecycle as a state machine with four discrete states:
//! - Open: Channel is active and can process transfers
//! - CooperativeClosing: Channel is being closed cooperatively
//! - ForceClosingPending: Channel is being force closed, waiting for timeout
//! - Closed: Channel is permanently closed, no further transitions allowed
//!
//! Each state is represented by a separate type that enforces its invariants.

pub mod closed;
pub mod cooperative_closing;
pub mod force_closing_pending;
pub mod open;

pub use closed::Closed;
pub use cooperative_closing::{CooperativeClosing, CooperativeClosingParams};
pub use force_closing_pending::{ForceClosingPending, ForceClosingPendingParams};
pub use open::Open;

/// Channel lifecycle enum
///
/// This enum represents the conceptual state machine structure.
/// It is used for type-level enforcement and documentation purposes.
/// At runtime, use the concrete state types (Open, CooperativeClosing,
/// ForceClosingPending, Closed).
///
/// State transitions:
/// - Open → Open (via transfer transition)
/// - Open → CooperativeClosing (via cooperative_close transition)
/// - Open → ForceClosingPending (via force_close transition)
/// - ForceClosingPending → Closed (via recover transition)
/// - CooperativeClosing → Closed (implicit, after transaction confirms)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelLifecycle {
    /// Channel is active and can process transfers
    Open,
    /// Channel is being closed cooperatively
    CooperativeClosing,
    /// Channel is being force closed, waiting for timeout
    ForceClosingPending,
    /// Channel is permanently closed, no further transitions allowed
    Closed,
}
