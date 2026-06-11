//! CashScript covenant glue — embedded artifacts, redeem-script construction,
//! and P2SH-32 locking-bytecode derivation.
//!
//! Runtime daemon usage:
//!   1. At startup, parse the manifest to obtain constructor args (notary pubkeys,
//!      packed CN hashes, reversed categories, sibling-contract locking scripts).
//!   2. Build the redeem script for each contract by prepending arg pushes to the
//!      embedded artifact bytecode.
//!   3. Compute `p2sh32_locking(redeem) == manifest.contracts.X.lockingBytecodeHex`
//!      as a consistency check; refuse to start on mismatch.
//!   4. Use the redeem scripts when building unlock scripts for `slot.attest`,
//!      `slot.consume`, and `oracle.update`.
//!
//! The artifact JSON files are embedded at compile time via `include_str!()`.

pub mod artifacts;
pub mod locking;
pub mod redeem;

pub use artifacts::{
    oracle_bytecode, publisher_slot_bytecode, ticker_bytecode, ArtifactError,
};
pub use locking::{p2sh32_locking_bytecode, P2SH32_LEN};
pub use redeem::{
    redeem_oracle, redeem_ticker, specialize_oracle_body, specialize_slot_body,
    RedeemScriptError, ORACLE_SLOT_CAT_WITH_CAP_OFFSET, P2SH_REDEEM_CAP, P2S_STANDARDNESS_CAP,
    SLOT_PKH_OFFSET, SLOT_CN_HASH_OFFSET, SLOT_ORACLE_CAT_HASH_OFFSET,
};
