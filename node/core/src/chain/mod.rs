//! On-chain byte layouts, signature digests, source registry, and protocol constants.
//!
//! Everything here matches the live v13 covenants at `contracts/Oracle.cash`,
//! `contracts/PublisherSlot.cash`, and `contracts/Ticker.cash`. Wire formats are
//! authoritative — encoders/decoders here must produce bytes identical to what
//! the covenants observe on chain.

pub mod consts;
pub mod digest;
pub mod oracle_commit;
pub mod slot_commit;
pub mod sources;
pub mod ticker_commit;

pub use consts::*;
pub use digest::publisher_sig_digest;
pub use oracle_commit::{decode_oracle_commit, encode_oracle_commit, OracleState};
pub use slot_commit::{decode_slot_commit, encode_slot_commit, SlotCommit};
pub use sources::{packed_cn_hashes, source_cn_hash, Source, SOURCES, SOURCE_COUNT};
pub use ticker_commit::encode_ticker_commit;
