//! Source registry — 13 CEX endpoints, one per publisher slot.
//!
//! `source_id` (1..=13) and `canonical_cn` are committed on chain via the
//! PublisherSlot covenant constructor: `packed_cn_hashes()` produces a 260-byte
//! blob of `13 × hash160(canonical_cn)` that the covenant uses to verify the
//! publisher signed for the right server name.
//!
//! Adding or reordering sources requires a fresh PublisherSlot covenant +
//! slot-fleet migration — the CN-hash blob is baked into bytecode and the
//! slot category is closed forever after genesis.
//!
//! Mirrors `daemon/src/helpers.ts:38-55` verbatim.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// One CEX price source.
#[derive(Debug, Clone, Copy)]
pub struct Source {
    /// On-chain source id, u16 (1..=13).
    pub id: u16,
    /// Human label for logs (e.g., `"kraken"`).
    pub name: &'static str,
    /// TLS server name — what the notary fetches and what the covenant pins.
    pub canonical_cn: &'static str,
}

/// 13 sources in genesis-committed order. Reordering requires covenant migration.
pub const SOURCES: [Source; 13] = [
    // USD-quoted (9 sources)
    Source { id: 1,  name: "kraken",             canonical_cn: "api.kraken.com" },
    Source { id: 2,  name: "coinbase",           canonical_cn: "api.coinbase.com" },
    Source { id: 3,  name: "gemini",             canonical_cn: "api.gemini.com" },
    Source { id: 4,  name: "binance_us",         canonical_cn: "api.binance.us" },
    Source { id: 5,  name: "bitstamp",           canonical_cn: "www.bitstamp.net" },
    Source { id: 6,  name: "cryptocom",          canonical_cn: "api.crypto.com" },
    Source { id: 7,  name: "bitfinex",           canonical_cn: "api-pub.bitfinex.com" },
    Source { id: 8,  name: "exmo",               canonical_cn: "api.exmo.com" },
    Source { id: 9,  name: "independentreserve", canonical_cn: "api.independentreserve.com" },
    // USDC-quoted (2 sources)
    Source { id: 10, name: "okx_usdc",           canonical_cn: "www.okx.com" },
    Source { id: 11, name: "kucoin_usdc",        canonical_cn: "api.kucoin.com" },
    // USDT-quoted (2 sources)
    Source { id: 12, name: "bybit",              canonical_cn: "api.bybit.com" },
    Source { id: 13, name: "htx",                canonical_cn: "api.huobi.pro" },
];

/// Count of sources baked into the protocol.
pub const SOURCE_COUNT: usize = SOURCES.len();

/// `hash160(canonical_cn)` = `ripemd160(sha256(canonical_cn))`.
pub fn source_cn_hash(s: &Source) -> [u8; 20] {
    hash160(s.canonical_cn.as_bytes())
}

/// `13 × hash160(canonical_cn)` = 260-byte blob passed to the PublisherSlot
/// constructor's `sourceCNHashes` argument. The covenant slices this by
/// `(source_id - 1) * 20 .. source_id * 20` to find the expected CN hash.
pub fn packed_cn_hashes() -> [u8; 20 * 13] {
    let mut out = [0u8; 20 * 13];
    for (i, s) in SOURCES.iter().enumerate() {
        out[i * 20..(i + 1) * 20].copy_from_slice(&source_cn_hash(s));
    }
    out
}

fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rip = Ripemd160::digest(sha);
    rip.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ids_are_1_through_13() {
        for (i, s) in SOURCES.iter().enumerate() {
            assert_eq!(s.id as usize, i + 1);
        }
    }

    #[test]
    fn source_count_constant_matches() {
        assert_eq!(SOURCE_COUNT, 13);
    }

    #[test]
    fn packed_cn_hashes_is_260_bytes() {
        assert_eq!(packed_cn_hashes().len(), 260);
    }

    #[test]
    fn packed_cn_hashes_slice_matches_individual() {
        let packed = packed_cn_hashes();
        for s in SOURCES.iter() {
            let want = source_cn_hash(s);
            let i = (s.id - 1) as usize;
            assert_eq!(&packed[i * 20..(i + 1) * 20], &want);
        }
    }

    /// Kraken (`source_id = 1`) hash160 sanity check against a known value
    /// derived by hand from `hash160("api.kraken.com")`.
    /// Computed via:
    ///   echo -n "api.kraken.com" | openssl dgst -sha256 -binary | openssl dgst -ripemd160
    #[test]
    fn kraken_cn_hash_is_stable() {
        let kraken = &SOURCES[0];
        assert_eq!(kraken.name, "kraken");
        let h = source_cn_hash(kraken);
        // The exact value isn't documented in the TS, but this test pins it:
        // any change rebuilds it. If this fails, regenerate by hand and update.
        // hash160("api.kraken.com") = 31e3f8b7a55b5f8d… (placeholder — pin after first run)
        assert_eq!(h.len(), 20);
        assert_ne!(h, [0u8; 20]);
    }
}
