//! Electrum response types — only the fields the daemon needs.

use serde::Deserialize;

/// CashTokens NFT capability code (matching Fulcrum's `token_data.nft.capability` string values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NftCapability {
    Mutable,
    Minting,
    None,
}

/// Token data attached to a UTXO (Fulcrum's CashTokens extension).
#[derive(Debug, Clone, Deserialize)]
pub struct TokenData {
    /// 64-hex category (display order, big-endian).
    pub category: String,
    /// Optional NFT body.
    #[serde(default)]
    pub nft: Option<NftBody>,
    /// Optional fungible amount (we don't use; v12 tokens are NFT-only).
    /// Fulcrum sends as a string ("0"); we deliberately don't parse it.
    #[serde(default, skip)]
    pub amount: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NftBody {
    pub capability: NftCapability,
    /// Hex-encoded commitment bytes.
    pub commitment: String,
}

/// One unspent transaction output as returned by `blockchain.address.listunspent`.
#[derive(Debug, Clone, Deserialize)]
pub struct Utxo {
    /// Display-order (big-endian) txid hex.
    pub tx_hash: String,
    pub tx_pos: u32,
    pub value: u64,
    pub height: i64,
    #[serde(default)]
    pub token_data: Option<TokenData>,
}
