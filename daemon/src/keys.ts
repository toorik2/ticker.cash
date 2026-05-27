// Federation key layout.
//
// Roles (one wallet per role, all derived from the same seed):
//   "master"        — hot wallet for deploy ceremony + treasury top-ups.
//   "notary-N"      — 7 federation Schnorr keys, the OR-list in the Gateway.
//   "publisher-N"   — 13 publisher wallets (one per source).
//
// Each operator runs ONE binary that holds ONE of these private keys.
// Federation operators typically run notary + publisher for the same slot
// (no HTTP round-trip for their own attestations); community operators run
// publisher-only.

import { binToHex } from '@bitauth/libauth';
import { deriveWallet, loadSeed, stripWallet, type Wallet, type PublicWallet } from './seed.js';

export const NOTARY_COUNT = 7;
export const PUBLISHER_COUNT = 13;

export interface Wallets {
  readonly master: Wallet;
  readonly notaries: ReadonlyArray<Wallet>;
  readonly publishers: ReadonlyArray<Wallet>;
}

export const deriveWallets = (seed: Uint8Array): Wallets => ({
  master:     deriveWallet(seed, 'master'),
  notaries:   Array.from({ length: NOTARY_COUNT },    (_, i) => deriveWallet(seed, `notary-${i}`)),
  publishers: Array.from({ length: PUBLISHER_COUNT }, (_, i) => deriveWallet(seed, `publisher-${i}`)),
});

export interface Manifest {
  readonly master: PublicWallet;
  readonly notaries: ReadonlyArray<PublicWallet>;
  readonly publishers: ReadonlyArray<PublicWallet>;
}

export const walletsManifest = (wallets: Wallets): Manifest => ({
  master:     stripWallet(wallets.master),
  notaries:   wallets.notaries.map(stripWallet),
  publishers: wallets.publishers.map(stripWallet),
});

export const printWalletAddresses = (wallets: Wallets): void => {
  const m = walletsManifest(wallets);
  console.log('wallet addresses:');
  console.log(`  master: ${m.master.address}`);
  console.log(`  ${NOTARY_COUNT} notaries (OR-list):`);
  m.notaries.forEach((n, i) => {
    console.log(`    [${i}] ${n.label}: ${n.address}  pubkey=${binToHex(n.publicKey)}`);
  });
  console.log(`  ${PUBLISHER_COUNT} publishers:`);
  m.publishers.forEach((p, i) => {
    console.log(`    [${String(i).padStart(2, '0')}] ${p.label}: ${p.address}`);
  });
};

export { loadSeed };
