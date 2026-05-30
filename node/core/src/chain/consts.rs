//! Protocol constants. Each one is also enforced or referenced by the live v12 covenants.

/// Sats locked in the Oracle UTXO (minting NFT). Re-emitted unchanged each cycle.
pub const ORACLE_DUST: u64 = 2_000;

/// Sats locked in each Ticker head UTXO (mutable NFT). 2 emitted per cycle.
pub const TICKER_DUST: u64 = 1_500;

/// Quorum floor — covenant rejects an Oracle.update with fewer slot inputs.
/// `Oracle.cash:82-86`: `if (thr < 7) thr = 7;`.
pub const THR_FLOOR: usize = 7;

/// Federation size: 13 publishers, each pinned to one of [`SOURCES`](super::sources::SOURCES).
pub const PUBLISHER_COUNT: usize = 13;

/// `Oracle.cash` emits 2 Ticker heads per cycle (`Oracle.cash:174-177`).
pub const TICKER_HEAD_COUNT: usize = 2;

/// Stride floor between Oracle.update transactions, seconds.
/// `Oracle.cash:73-74`: `require(newTs - prevTs >= 60)`.
pub const STRIDE_FLOOR_SEC: u32 = 60;

// ─── Commit lengths ────────────────────────────────────────────────────────

/// Length of an Oracle NFT commit, bytes.
/// Layout: `0x60 | seq(u32 LE) | last_ts(u32 LE) | median_usd(u64 LE) | active_count(u16 LE)`.
pub const ORACLE_COMMIT_LEN: usize = 19;

/// Length of a Ticker NFT commit, bytes.
/// Layout: `0x80 | seq(u32 LE) | last_ts(u32 LE) | median_usd(u64 LE)`.
pub const TICKER_COMMIT_LEN: usize = 17;

/// Length of a PublisherSlot NFT commit, bytes.
/// Layout: `0x73 | source_id(u16 LE) | pkh(20 B) | price(u64 LE) | timestamp(u32 LE) | cycle_seq(u32 LE)`.
pub const SLOT_COMMIT_LEN: usize = 39;

// ─── Version bytes ─────────────────────────────────────────────────────────

/// Oracle NFT commit version byte (`Oracle.cash:24-30`).
pub const ORACLE_VERSION_BYTE: u8 = 0x60;

/// Ticker NFT commit version byte (`Oracle.cash:174-177`).
pub const TICKER_VERSION_BYTE: u8 = 0x80;

/// PublisherSlot NFT commit version byte. `0x73` is v13's tag, distinct from v12's `0x72`
/// and v11's `0x70` (VerifiedAttestation). The version-byte bump is the structural marker
/// of v13's dropped notary tier.
pub const SLOT_VERSION_BYTE: u8 = 0x73;

// ─── Capability bytes ──────────────────────────────────────────────────────

/// CashTokens capability byte for a mutable NFT.
pub const CAPABILITY_MUTABLE: u8 = 0x01;

/// CashTokens capability byte for a minting NFT.
pub const CAPABILITY_MINTING: u8 = 0x02;

// ─── Fee policy ────────────────────────────────────────────────────────────

/// Worst-case `slot.attest` fee budget — used only as the pre-broadcast
/// "do I have enough to even try?" gate. The actual fee paid is computed
/// dynamically from the encoded tx size (see `tx::attest::build_attest_tx`).
///
/// `slot.attest` is ~2.2 KB at 1 sat/byte (1,656-byte PublisherSlot redeem
/// dominates). 3,000 covers worst-case sizes (multi-funder, max server name)
/// without false-rejecting publishers whose balance is just-above-fee-but-
/// below-buffer.
pub const MAX_ATTEST_FEE_HINT: u64 = 3_000;

/// Worst-case `Oracle.update` fee budget — used only as the pre-broadcast
/// "do I have enough to even try?" gate. The actual fee paid is computed
/// dynamically from the encoded tx size (see `tx::update::build_oracle_update_tx`).
///
/// `Oracle.update` size varies 8–14 KB (7 vs 13 slot inputs), so a static
/// budget would either over-tip for small cycles or under-tip for large ones.
/// 8_000 covers the largest realistic case at 1 sat/byte without false-rejecting
/// publishers whose balance is just-above-fee-but-below-buffer.
pub const MAX_UPDATE_FEE_HINT: u64 = 8_000;

/// BCH relay-floor minimum fee rate (sats per encoded byte).
pub const SAT_PER_BYTE: u64 = 1;

/// Small additive margin on top of `size × SAT_PER_BYTE` — absorbs the 1-byte
/// variance in ECDSA-DER signature length per funder input.
pub const FEE_EPSILON_SATS: u64 = 50;

/// Bitcoin Cash dust threshold (sats). Outputs below this are not produced.
pub const DUST_THRESHOLD: u64 = 546;

/// Bytes of `OP_0` padding added to the Oracle.update unlock script.
/// Reserves CashScript op-budget for the worst-case 13-slot loop path.
pub const BUDGET_PAD_LEN: usize = 1024;
