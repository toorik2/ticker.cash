//! Real notary `POST /sign` handler — looks up source, fetches price via
//! `HttpsPlainProver`, signs the notary digest, returns wire-shape response.

use std::time::Duration;

use ticker_core::chain::digest::notary_sig_digest;
use ticker_core::chain::sources::SOURCES;
use ticker_core::crypto::sign_schnorr;
use ticker_core::notary_server::{NotaryHandler, SignRequest, SignResponse};
use ticker_core::prover::{HttpsPlainProver, PriceProver};

/// Real notary handler. Owns the notary private key + pubkey + a prover.
pub struct RealNotaryHandler {
    pub slot: u8,
    pub address: String,
    pub privkey: [u8; 32],
    pub pubkey: [u8; 33],
    pub prover: HttpsPlainProver,
}

impl NotaryHandler for RealNotaryHandler {
    fn sign(&self, req: SignRequest) -> Result<SignResponse, String> {
        let source = SOURCES
            .iter()
            .find(|s| s.id == req.source_id)
            .ok_or_else(|| format!("unknown sourceId {}", req.source_id))?;
        if req.cycle_seq == 0 {
            return Err("cycleSeq must be ≥ 1".into());
        }
        if req.pubkey_hash.len() != 40 {
            return Err("pubkeyHash must be 40 hex chars".into());
        }
        let pkh_bytes = hex::decode(&req.pubkey_hash)
            .map_err(|e| format!("bad pubkeyHash hex: {e}"))?;
        let mut pkh: [u8; 20] = [0u8; 20];
        pkh.copy_from_slice(&pkh_bytes);

        let proof = self
            .prover
            .prove(source)
            .map_err(|e| format!("{e}"))?;

        let digest = notary_sig_digest(
            &proof.server_name,
            req.source_id,
            proof.price,
            proof.timestamp,
            req.cycle_seq,
            &pkh,
        );
        let sig = sign_schnorr(&self.privkey, &digest).map_err(|e| format!("sign: {e}"))?;

        Ok(SignResponse {
            source_id: req.source_id,
            cycle_seq: req.cycle_seq,
            price: proof.price.to_string(),
            timestamp: proof.timestamp,
            server_name: proof.server_name,
            notary_sig: hex::encode(sig),
            notary_pubkey: hex::encode(self.pubkey),
        })
    }

    fn health(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "slot": self.slot,
            "address": self.address,
            "pubkey": hex::encode(self.pubkey),
            "mode": "operator-key",
        })
    }
}

/// Default per-request timeout for prover fetches.
pub const DEFAULT_PROVER_TIMEOUT: Duration = Duration::from_secs(5);
