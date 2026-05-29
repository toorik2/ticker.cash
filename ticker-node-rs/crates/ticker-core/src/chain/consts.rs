//! Protocol constants. Each one is also enforced or referenced by the live v12 covenants.

/// Sats locked in the Oracle UTXO (minting NFT). Re-emitted unchanged each cycle.
pub const ORACLE_DUST: u64 = 2_000;

/// Sats locked in each Ticker head UTXO (mutable NFT). 2 emitted per cycle.
pub const TICKER_DUST: u64 = 1_500;

/// Quorum floor — covenant rejects an Oracle.update with fewer slot inputs.
/// `Oracle.cash:82-86`: `if (thr < 7) thr = 7;`.
pub const THR_FLOOR: usize = 7;

/// Federation size: 7 notary Schnorr keys in the slot covenant's OR-list.
pub const NOTARY_COUNT: usize = 7;

/// Federation size: 13 publishers, each pinned to one of [`SOURCES`](super::sources::SOURCES).
pub const PUBLISHER_COUNT: usize = 13;

/// `Oracle.cash` emits 2 Ticker heads per cycle (`Oracle.cash:174-177`).
pub const TICKER_HEAD_COUNT: usize = 2;

/// Stride floor between Oracle.update transactions, seconds.
/// `Oracle.cash:73-74`: `require(newTs - prevTs >= 30)`.
pub const STRIDE_FLOOR_SEC: u32 = 30;

// ─── Commit lengths ────────────────────────────────────────────────────────

/// Length of an Oracle NFT commit, bytes.
/// Layout: `0x60 | seq(u32 LE) | last_ts(u32 LE) | median_usd(u64 LE) | active_count(u16 LE)`.
pub const ORACLE_COMMIT_LEN: usize = 19;

/// Length of a Ticker NFT commit, bytes.
/// Layout: `0x80 | seq(u32 LE) | last_ts(u32 LE) | median_usd(u64 LE)`.
pub const TICKER_COMMIT_LEN: usize = 17;

/// Length of a PublisherSlot NFT commit, bytes.
/// Layout: `0x72 | source_id(u16 LE) | pkh(20 B) | price(u64 LE) | timestamp(u32 LE) | cycle_seq(u32 LE)`.
pub const SLOT_COMMIT_LEN: usize = 39;

// ─── Version bytes ─────────────────────────────────────────────────────────

/// Oracle NFT commit version byte (`Oracle.cash:24-30`).
pub const ORACLE_VERSION_BYTE: u8 = 0x60;

/// Ticker NFT commit version byte (`Oracle.cash:174-177`).
pub const TICKER_VERSION_BYTE: u8 = 0x80;

/// PublisherSlot NFT commit version byte. Distinct from v11's `0x70` for VerifiedAttestation.
pub const SLOT_VERSION_BYTE: u8 = 0x72;

// ─── Capability bytes ──────────────────────────────────────────────────────

/// CashTokens capability byte for a mutable NFT.
pub const CAPABILITY_MUTABLE: u8 = 0x01;

/// CashTokens capability byte for a minting NFT.
pub const CAPABILITY_MINTING: u8 = 0x02;

// ─── Fee buffers (sats) ────────────────────────────────────────────────────

/// Funder sats reserved for `slot.attest` tx (miner fee + dust margin).
pub const TX_FEE_BUFFER_ATTEST: u64 = 2_000;

/// Funder sats reserved for `Oracle.update` tx (miner fee + dust margin; covers up to 13 slot inputs).
pub const TX_FEE_BUFFER_UPDATE: u64 = 20_000;

/// Bitcoin Cash dust threshold (sats). Outputs below this are not produced.
pub const DUST_THRESHOLD: u64 = 546;

/// Bytes of `OP_0` padding added to the Oracle.update unlock script.
/// Reserves CashScript op-budget for the worst-case 13-slot loop path.
pub const BUDGET_PAD_LEN: usize = 1024;
