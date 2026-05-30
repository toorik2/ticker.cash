//! Publisher cycle state machine.
//!
//! Each cycle is the explicit data type [`CycleState`], advanced by the pure
//! transition function [`step::step`] under an [`Env`] trait that abstracts all
//! I/O. The orchestrator loop in [`orchestrator::run_publisher`] drives `step`,
//! handles error severity, threads the cycle counter, and listens for
//! SIGINT/SIGTERM.
//!
//! Restart semantics: on boot we always return to [`CycleState::Idle`] and
//! re-derive intent from on-chain truth. Persisted `publisher-state-N.json` is
//! advisory only — used by `/stats` and post-mortem debugging, never load-bearing
//! for correctness.

pub mod env;
pub mod error;
pub mod orchestrator;
pub mod state;
pub mod step;
pub use env::{Env, FunderInfo, OracleInfo, PriceObservation, SlotInfo};
pub use error::{CycleError, Severity};
pub use orchestrator::{run_publisher, RunOpts, CYCLE_COUNT, CYCLE_ERROR_COUNT};
pub use state::{CycleConfig, CycleSnapshot, CycleState, PublisherState, Txid};
pub use step::step;
