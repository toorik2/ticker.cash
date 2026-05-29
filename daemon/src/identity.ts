// Shared identity resolver — picks the operator's slot + Wallet from one of
// two on-disk credential layouts:
//
//   New (per-operator install):
//     .ticker/manifest.json
//     .ticker/{notary,publisher}.key    one 32-byte key for the role we run
//   Slot = indexOf(my pubkey or pkh) in the manifest's per-role array.
//   --slot may be supplied for sanity, but must match the derived slot.
//
//   Legacy (coordinator's seed-derived bundle):
//     .ticker/seed.hex                  produces all 20 federation keys
//   Slot comes from --slot N (defaults to 0).
//
// notary.ts and publisher.ts both used to carry near-identical resolveIdentity
// blocks. They differ only in:
//   - which keyfile they look for
//   - which manifest array indexes them
//   - whether the slot id is the pubkey (notary) or hash160(pubkey) (publisher)
//   - which seed-derived wallet array contains their slot
//
// Those four bits are captured in `RoleSpec`. The two pre-baked specs
// (NOTARY_ROLE, PUBLISHER_ROLE) drive `resolveOperatorIdentity`.

import { existsSync } from 'node:fs';
import { binToHex, hash160 } from '@bitauth/libauth';
import { loadOperatorKey, type Wallet, type Mode } from './operator-key.js';
import { loadManifest, type Manifest } from './manifest.js';
import { loadSeed } from './master-seed.js';
import { deriveWallets, NOTARY_COUNT, PUBLISHER_COUNT, type Wallets } from './keys.js';

const MANIFEST_PATH = '.ticker/manifest.json';
const SEED_PATH     = '.ticker/seed.hex';

export interface RoleSpec {
  readonly name: 'notary' | 'publisher';
  readonly keyPath: string;
  /** Number of slots this role has. */
  readonly count: number;
  /** Per-role slot identifier list inside a manifest. */
  readonly manifestSlots: (m: Manifest) => readonly string[];
  /** How this role identifies a slot in `manifestSlots` from a public key. */
  readonly slotIdOfKey: (publicKey: Uint8Array) => string;
  /** Legacy: pull this role's wallet for slot N out of the seed-derived bundle. */
  readonly legacyWallet: (wallets: Wallets, slot: number) => Wallet;
}

export const NOTARY_ROLE: RoleSpec = {
  name: 'notary',
  keyPath: '.ticker/notary.key',
  count: NOTARY_COUNT,
  manifestSlots: (m) => m.notaryPubkeys,
  slotIdOfKey: (pk) => binToHex(pk),
  legacyWallet: (w, slot) => w.notaries[slot]!,
};

export const PUBLISHER_ROLE: RoleSpec = {
  name: 'publisher',
  keyPath: '.ticker/publisher.key',
  count: PUBLISHER_COUNT,
  manifestSlots: (m) => m.publisherPkhs,
  slotIdOfKey: (pk) => binToHex(hash160(pk)),
  legacyWallet: (w, slot) => w.publishers[slot]!,
};

export interface BaseIdentity {
  readonly slot: number;
  readonly wallet: Wallet;
  readonly mode: Mode;
  /** Set on operator-key mode; null on seed-derived. */
  readonly manifest: Manifest | null;
  /** Set on seed-derived mode; null on operator-key. */
  readonly wallets: Wallets | null;
}

export const resolveOperatorIdentity = (
  role: RoleSpec,
  slotFlag: string | undefined,
): BaseIdentity => {
  if (existsSync(MANIFEST_PATH)) {
    if (!existsSync(role.keyPath)) {
      throw new Error(
        `manifest is present but ${role.keyPath} is not.\n` +
        `if you are running the other role, use that binary instead.\n` +
        `if you should be running a ${role.name}, re-install or restore the keyfile.`,
      );
    }
    const manifest = loadManifest();
    const wallet = loadOperatorKey(role.keyPath, role.name, manifest.network);
    const id = role.slotIdOfKey(wallet.publicKey);
    const slot = role.manifestSlots(manifest).indexOf(id);
    if (slot < 0) {
      throw new Error(
        `${role.name} key id ${id} is not in this manifest's ${role.name} list.\n` +
        `wrong installer? wrong manifest? verify with your coordinator.`,
      );
    }
    if (slotFlag !== undefined) {
      const supplied = parseInt(slotFlag, 10);
      if (supplied !== slot) {
        throw new Error(
          `--slot ${supplied} disagrees with derived slot ${slot} (from key); ` +
          `omit --slot in the per-operator install layout.`,
        );
      }
    }
    return { slot, wallet, mode: 'operator-key', manifest, wallets: null };
  }

  if (existsSync(SEED_PATH)) {
    const slot = parseInt(slotFlag ?? '0', 10);
    if (!Number.isInteger(slot) || slot < 0 || slot >= role.count) {
      throw new Error(`--slot must be 0..${role.count - 1}`);
    }
    const seed = loadSeed();
    const wallets = deriveWallets(seed);
    return {
      slot,
      wallet: role.legacyWallet(wallets, slot),
      mode: 'seed-derived',
      manifest: null,
      wallets,
    };
  }

  throw new Error(
    `no credentials found. expected one of:\n` +
    `  ${role.keyPath} + ${MANIFEST_PATH}    (per-operator install)\n` +
    `  ${SEED_PATH}                          (legacy seed-derived layout)\n`,
  );
};
