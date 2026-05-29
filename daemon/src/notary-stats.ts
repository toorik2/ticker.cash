// Shared notary-side state for ticker-node's optional /stats endpoint.
//
// Two things live here, both module-level singletons:
//
//   1. The notary's identity (slot, address, pubkey, mode, port). Set once
//      by notary.ts at runtime after resolveIdentity + resolvePort. Read by
//      ticker-node.ts's /stats handler so it can surface "I'm notary slot
//      N" alongside the per-publisher data already exposed.
//
//   2. A sign-request counter. notary.ts increments it once per *successful*
//      POST /sign response (success = price fetched + signed). Failed signs
//      (CEX 5xx, timeout, malformed body) don't count. The counter is process-
//      lifetime — reset to 0 on every restart.
//
// Single producer per process, single consumer; no locking needed.

import type { Mode } from './operator-key.js';

export interface NotaryIdentity {
  readonly slot: number;
  readonly port: number;
  readonly address: string;
  readonly pubkeyHex: string;
  readonly mode: Mode;
}

let identity: NotaryIdentity | null = null;
let signRequests = 0;

export const setNotaryIdentity = (id: NotaryIdentity): void => {
  identity = id;
};

export const getNotaryIdentity = (): NotaryIdentity | null => identity;

export const incrementNotarySignRequest = (): void => {
  signRequests += 1;
};

export const getNotarySignRequestCount = (): number => signRequests;
