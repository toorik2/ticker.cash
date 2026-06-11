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

/// v24 P01 — encode a u64 as 5-byte little-endian (low 40 bits). Asserts the
/// value fits in 40 bits in debug builds; release builds silently truncate.
/// Callers must enforce the `U40_CAP` bound before calling.
#[inline]
pub fn u40_to_le(value: u64) -> [u8; 5] {
    debug_assert!(value < (1u64 << 40), "value {value} exceeds u40 range");
    let b = value.to_le_bytes();
    [b[0], b[1], b[2], b[3], b[4]]
}

/// v24 P01 — decode a 5-byte little-endian buffer as a u64 (high 24 bits zero).
#[inline]
pub fn u40_from_le(bytes: &[u8; 5]) -> u64 {
    let mut buf = [0u8; 8];
    buf[..5].copy_from_slice(bytes);
    u64::from_le_bytes(buf)
}
