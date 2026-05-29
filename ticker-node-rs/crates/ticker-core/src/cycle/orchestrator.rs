//! Cycle orchestrator — the outer loop that drives [`step`].
//!
//! Responsibilities:
//!   * Increment `cycle_counter` at the top of each cycle (only on `Idle`).
//!   * Match on the returned `CycleState` to decide whether to continue, reset,
//!     or exit (in `--once` mode).
//!   * Handle errors by severity: route to the right log level, decide whether
//!     to bump the `errorsSinceStart` counter, and apply sleep-with-backoff.
//!   * Poll the supplied `shutdown` flag between phases to honour SIGINT/SIGTERM.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::cycle::env::Env;
use crate::cycle::error::{CycleError, Severity};
use crate::cycle::state::{CycleConfig, CycleState};
use crate::cycle::step::step;
use crate::log_error;
use crate::log_info;
use crate::log_warn;

/// Process-lifetime error counter, surfaced by the opt-in `/stats` HTTP endpoint.
pub static CYCLE_ERROR_COUNT: AtomicU64 = AtomicU64::new(0);

/// Process-lifetime cycle counter (top-of-cycle increments only).
pub static CYCLE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Options passed to [`run_publisher`].
#[derive(Debug, Clone, Copy)]
pub struct RunOpts {
    /// Exit after one successful cycle (for testing / single-shot mode).
    pub once: bool,
}

/// Drive the publisher cycle loop until `shutdown.load() == true`.
///
/// Returns:
///   * `Ok(())` on graceful shutdown (SIGINT/SIGTERM) or in `--once` mode after
///     one successful Updated transition.
///   * `Err(e)` if a `Hard` error fires in `--once` mode (used by tests + CI).
///     In non-once mode hard errors are logged and the cycle resets to `Idle`.
pub fn run_publisher<E: Env>(
    env: &mut E,
    cfg: &CycleConfig,
    shutdown: &AtomicBool,
    opts: RunOpts,
) -> Result<(), CycleError> {
    let mut state = CycleState::Idle;
    let mut cycle_counter: u64 = 0;
    while !shutdown.load(Ordering::Relaxed) {
        if matches!(state, CycleState::Idle) {
            cycle_counter += 1;
            CYCLE_COUNT.store(cycle_counter, Ordering::Relaxed);
            log_info!("cycle start", "n" => cycle_counter, "slot" => cfg.slot);
        }
        match step(state, env, cfg, cycle_counter) {
            Ok(CycleState::Updated { new_seq, update_txid }) => {
                let txid_hex = update_txid.map(hex::encode);
                if let Some(t) = &txid_hex {
                    log_info!(
                        "Oracle.update ok",
                        "n" => cycle_counter,
                        "new_seq" => new_seq,
                        "txid" => t.clone(),
                    );
                } else {
                    log_info!(
                        "Oracle.update race lost — OK",
                        "n" => cycle_counter,
                        "new_seq" => new_seq,
                    );
                }
                if opts.once {
                    return Ok(());
                }
                state = CycleState::Idle;
            }
            Ok(next) => {
                state = next;
            }
            Err(e) => {
                let sev = e.severity();
                let counts = e.counts_toward_error_counter();
                let msg = e.to_string();
                let stride_wait = if let CycleError::StrideFloor { wait_sec } = e {
                    Some(wait_sec)
                } else {
                    None
                };
                match sev {
                    Severity::Soft => log_info!("cycle soft", "msg" => msg, "n" => cycle_counter),
                    Severity::Transient => {
                        log_warn!("cycle transient", "msg" => msg, "n" => cycle_counter)
                    }
                    Severity::Hard => {
                        log_error!("cycle hard", "msg" => msg, "n" => cycle_counter)
                    }
                }
                if counts {
                    CYCLE_ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
                }
                if let Some(wait_sec) = stride_wait {
                    env.sleep(std::time::Duration::from_secs(wait_sec as u64));
                } else {
                    env.sleep(cfg.poll_interval);
                }
                if opts.once && sev == Severity::Hard {
                    return Err(CycleError::Internal(msg));
                }
                state = CycleState::Idle;
            }
        }
    }
    log_info!("shutdown", "n" => cycle_counter);
    Ok(())
}
