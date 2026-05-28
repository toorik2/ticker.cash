// Operator key — a single 32-byte private key for ONE federation role.
//
// In the multi-operator install model, each operator holds:
//   - ~/.ticker/notary.key      (if running a notary slot)
//   - ~/.ticker/publisher.key   (if running a publisher slot)
//   - ~/.ticker/manifest.json   (public bundle: contracts + 7 notary pubkeys
//                                + 13 publisher pkhs + electrum default)
//
// Notary key and publisher key are DIFFERENT — the genesis tx baked separate
// pubkeys into the notary OR-list (covenant constructor arg) and into the
// per-slot publisher pkh (slot NFT commit bytes [3..23]). An operator running
// "bundled" (notary + publisher for the same slot index) holds two files,
// one per role.
//
// File format: 64 hex characters (32 bytes), trailing newline OK. Same shape
// as the coordinator's seed.hex but holds a single role-key, not the master.
//
// `loadOperatorKey` returns a Wallet-shaped object so existing call-sites that
// expect `wallets.notaries[slot]` or `wallets.publishers[slot]` can use it
// interchangeably during the backwards-compat window.

import { existsSync, readFileSync } from 'node:fs';
import {
  hexToBin,
  encodeCashAddress,
  hash160,
  secp256k1,
  CashAddressNetworkPrefix,
  CashAddressType,
} from '@bitauth/libauth';
import type { Wallet } from './master-seed.js';

export type Network = 'chipnet' | 'mainnet';

const networkPrefix = (network: Network): CashAddressNetworkPrefix =>
  network === 'mainnet'
    ? CashAddressNetworkPrefix.mainnet
    : CashAddressNetworkPrefix.testnet;

/**
 * Load a 32-byte private key from disk and derive the matching pubkey + P2PKH
 * address for the given network.
 *
 * @param path   absolute or repo-relative path to the keyfile
 * @param label  logging label, e.g. 'notary' or 'publisher'
 * @param network 'chipnet' or 'mainnet' — determines the address prefix
 * @throws if the file is missing, wrong length, or contains non-hex characters
 */
export const loadOperatorKey = (
  path: string,
  label: string,
  network: Network,
): Wallet => {
  if (!existsSync(path)) {
    throw new Error(
      `no operator key at ${path}.\n` +
      `your installer should have placed this file — re-run the installer ` +
      `or restore from backup.`,
    );
  }
  const hex = readFileSync(path, 'utf8').trim();
  if (hex.length !== 64) {
    throw new Error(
      `operator key at ${path} is not 32 bytes (got ${hex.length / 2})`,
    );
  }
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    // hexToBin silently coerces non-hex characters to 0x00 — a corrupted file
    // could otherwise yield the all-zeros key (publicly precomputable). Reject
    // any non-hex content here.
    throw new Error(
      `operator key at ${path} contains non-hex characters; expected 64 hex chars`,
    );
  }

  const privateKey = hexToBin(hex);
  const pubResult = secp256k1.derivePublicKeyCompressed(privateKey);
  if (typeof pubResult === 'string') {
    throw new Error(`derive pubkey for ${label}: ${pubResult}`);
  }
  const address = encodeCashAddress({
    payload: hash160(pubResult),
    prefix: networkPrefix(network),
    type: CashAddressType.p2pkh,
  }).address;

  return { label, privateKey, publicKey: pubResult, address };
};
