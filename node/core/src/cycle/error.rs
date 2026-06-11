//! Cycle error taxonomy with severity classes.
//!
//! The orchestrator matches on [`Severity`] to decide log level and whether to
//! count toward the `/stats` `errorsSinceStart` counter:
//!
//! | Severity   | Meaning                              | Log level | Counts? |
//! |------------|--------------------------------------|-----------|---------|
//! | `Soft`     | Race lost, price-fetch failed, etc.  | INFO      | no      |
//! | `Transient`| Fulcrum disconnect, state I/O        | WARN      | yes     |
//! | `Hard`     | Covenant rejected, manifest mismatch | ERROR     | yes     |

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Soft,
    Transient,
    Hard,
}

#[derive(Debug, thiserror::Error)]
pub enum CycleError {
    // ─── soft (info log, retry next cycle) ─────────────────────────────────
    #[error("no oracle UTXO at scripthash {scripthash}")]
    OracleNotFound { scripthash: String },
    #[error("my slot not found in {count} mutable slot UTXOs")]
    MySlotNotFound { count: usize },
    #[error("slot already at cycleSeq {at}, can't progress to {new}")]
    SlotAheadOfNew { at: u64, new: u64 },
    #[error("stride floor: waiting {wait_sec} s")]
    StrideFloor { wait_sec: u64 },
    #[error("price fetch failed for source {source_id}: {reason}")]
    PriceFetchFailed { source_id: u16, reason: String },
    #[error("insufficient funder balance {have} < need {need}")]
    InsufficientFunds { have: u64, need: u64 },
    #[error("attest race lost (mempool-conflict)")]
    AttestRaceLost,
    #[error("Oracle.update race lost (mempool-conflict) — OK")]
    UpdateRaceLostOk,
    #[error("quorum timeout: {got}/{need}")]
    QuorumTimeout { got: usize, need: usize },

    // ─── transient (warn log, retry with backoff) ──────────────────────────
    #[error("Fulcrum disconnected: {0}")]
    FulcrumDisconnected(String),
    #[error("persistence I/O failed: {0}")]
    StateIo(String),

    // ─── hard (error log, no retry within this process lifetime) ───────────
    #[error("oracle commit malformed: {0}")]
    OracleCommitMalformed(String),
    #[error("slot commit malformed at outpoint {txid}/{vout}")]
    SlotCommitMalformed { txid: String, vout: u32 },
    #[error("my pkh {pkh_hex} not in manifest publisherPkhs")]
    PkhNotInManifest { pkh_hex: String },
    #[error("covenant rejected attest tx: {reason}")]
    CovenantRejectedAttest { reason: String },
    #[error("covenant rejected Oracle.update: {reason}")]
    CovenantRejectedUpdate { reason: String },
    #[error("internal: {0}")]
    Internal(String),
}

impl CycleError {
    pub fn severity(&self) -> Severity {
        use CycleError::*;
        match self {
            OracleNotFound { .. }
            | MySlotNotFound { .. }
            | SlotAheadOfNew { .. }
            | StrideFloor { .. }
            | PriceFetchFailed { .. }
            | InsufficientFunds { .. }
            | AttestRaceLost
            | UpdateRaceLostOk
            | QuorumTimeout { .. } => Severity::Soft,
            FulcrumDisconnected(_) | StateIo(_) => Severity::Transient,
            _ => Severity::Hard,
        }
    }

    /// Whether this error should bump the `errorsSinceStart` counter surfaced by `/stats`.
    pub fn counts_toward_error_counter(&self) -> bool {
        matches!(self.severity(), Severity::Transient | Severity::Hard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn race_lost_is_soft_and_does_not_count() {
        let e = CycleError::UpdateRaceLostOk;
        assert_eq!(e.severity(), Severity::Soft);
        assert!(!e.counts_toward_error_counter());
    }

    #[test]
    fn covenant_reject_is_hard_and_counts() {
        let e = CycleError::CovenantRejectedAttest {
            reason: "bad sig".to_string(),
        };
        assert_eq!(e.severity(), Severity::Hard);
        assert!(e.counts_toward_error_counter());
    }

    #[test]
    fn fulcrum_disconnect_is_transient_and_counts() {
        let e = CycleError::FulcrumDisconnected("eof".to_string());
        assert_eq!(e.severity(), Severity::Transient);
        assert!(e.counts_toward_error_counter());
    }
}
