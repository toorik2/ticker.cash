//! CashTokens-aware BCH transaction encoder + sighash + builders.
//!
//! No existing Rust crate handles CashTokens (CHIP-2022-02). Hand-rolled from
//! the wire spec. Output is bit-exact compatible with the current TypeScript
//! daemon's `cashscript` `TransactionBuilder` output.

pub mod cashaddr;
pub mod encode;
pub mod script;
pub mod sighash;

pub use cashaddr::{encode_p2pkh_cashaddr, AddressPrefix};
pub use encode::{
    encode_tx, encode_varint, Input, Output, TokenPrefix, Tx, TxOutpoint, MUTABLE_CAPABILITY,
    MINTING_CAPABILITY, NO_CAPABILITY,
};
pub use script::{push_data, push_int, p2pkh_locking_script};
pub use sighash::{p2pkh_sighash_preimage, SIGHASH_ALL_BIP143, SIGHASH_FORKID, SIGHASH_BIT};
