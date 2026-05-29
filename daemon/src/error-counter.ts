// Shared in-memory counter for cycle-level errors in the publisher daemon.
// Read by ticker-node's optional /stats endpoint (--stats-bind) to surface
// how many publisher cycles have failed since process start. Reset to 0
// implicitly on every process start (= systemd restart).
//
// The publisher daemon increments this from its OUTER cycle catch block —
// not from inner per-step handlers (lost-race recoveries, transient notary
// hiccups). It counts genuine cycle aborts, not noisy retries.
//
// Module-level state is acceptable here: ticker-node runs ONE notary +
// ONE publisher per process (per the unified single-process model), so the
// counter has a single producer and a single consumer.

let cycleErrors = 0;

export const incrementCycleError = (): void => {
  cycleErrors += 1;
};

export const getCycleErrorCount = (): number => cycleErrors;
