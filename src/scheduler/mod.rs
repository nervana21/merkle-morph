// SPDX-License-Identifier: CC0-1.0

//! Scheduler and batch orchestration module.
//!
//! Exposes the core abstractions for building and verifying batches. This layer
//! stays deliberately interface-only so implementations can evolve without
//! disturbing consumers or proof/DA backends.
//!
//! Reference: Fuel Core repository (https://github.com/FuelLabs/fuel-core) for
//! separation of ports/traits and block producer interfaces.

pub mod batch;
pub mod da;
pub mod executor;
pub mod partition;
pub mod proof;
pub mod query;
pub mod sequencer;
pub mod stream;
pub mod verifier;

pub use batch::{Batch, BatchProofBundle, FeeMetadata};
pub use da::{AsyncDAStore, DAStore};
pub use executor::{compute_global_root_from_wallets, AsyncExecutor, Executor, InMemoryExecutor};
pub use query::{AsyncStateQuery, StateQuery};
pub use sequencer::{
    AccessSet, OrderedUpdate, SchedulingRules, Sequencer, TransitionId, UpdateEnvelope,
};
pub use stream::{AsyncStateStream, StateStream, StateUpdate};
pub use verifier::BatchVerifier;
