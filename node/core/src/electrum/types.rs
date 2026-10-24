//! Electrum response types — only what the operator needs.

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NftCapability {
    Mutable,
    Minting,
    None,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenData {
    /// 64-hex category, display order.
    pub category: String,
    #[serde(default)]
    pub nft: Option<NftBody>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NftBody {
    pub capability: NftCapability,
    /// Hex commitment.
    pub commitment: String,
}

/// One unspent output from `blockchain.scripthash.listunspent` (with `include_tokens`).
#[derive(Debug, Clone, Deserialize)]
pub struct Utxo {
    pub tx_hash: String,
    pub tx_pos: u32,
    pub value: u64,
    /// 0 for unconfirmed.
    pub height: i64,
    #[serde(default)]
    pub token_data: Option<TokenData>,
}

impl Utxo {
    pub fn txid_be(&self) -> Option<[u8; 32]> {
        hex::decode(&self.tx_hash).ok()?.try_into().ok()
    }
}
