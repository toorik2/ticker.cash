// Seed-derived wallet primitives.
//
// The seed is a 32-byte secret that lives at .ticker/seed.hex (local-only,
// gitignored). All federation keys (master, notaries, publishers) are derived
// deterministically from this seed via labeled hashing:
//
//   privateKey = sha256(seed || utf8(label))
//
// Anyone with the seed can produce ANY of the wallets. Operators should
// generate a fresh seed per deployment instance:
//
//   head -c 32 /dev/urandom | xxd -p -c 64 > .ticker/seed.hex
//   chmod 600 .ticker/seed.hex

import { readFileSync } from 'node:fs';
import {
  hexToBin,
  encodeCashAddress,
  hash160,
  secp256k1,
  sha256,
  CashAddressNetworkPrefix,
  CashAddressType,
  type Sha256,
} from '@bitauth/libauth';

const sha256Hash = (data: Uint8Array): Uint8Array => (sha256 as Sha256).hash(data);

const DEFAULT_SEED_PATH = '.ticker/seed.hex';

export interface Wallet {
  readonly label: string;
  readonly privateKey: Uint8Array;   // 32 B
  readonly publicKey: Uint8Array;    // 33 B compressed
  readonly address: string;          // chipnet P2PKH (bchtest:q...)
}

export interface PublicWallet {
  readonly label: string;
  readonly publicKey: Uint8Array;
  readonly address: string;
}

const p2pkhAddrFromPubkey = (pubKey: Uint8Array): string =>
  encodeCashAddress({
    payload: hash160(pubKey),
    prefix: CashAddressNetworkPrefix.testnet,
    type: CashAddressType.p2pkh,
  }).address;

/** Load the 32-byte seed from disk. Throws if missing. */
export const loadSeed = (path: string = DEFAULT_SEED_PATH): Uint8Array => {
  let hex: string;
  try {
    hex = readFileSync(path, 'utf8').trim();
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(
        `no seed at ${path}. generate one with:\n` +
        `  head -c 32 /dev/urandom | xxd -p -c 64 > ${path}\n` +
        `  chmod 600 ${path}`,
      );
    }
    throw e;
  }
  if (hex.length !== 64) throw new Error(`seed at ${path} is not 32 bytes (got ${hex.length / 2})`);
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    // hexToBin silently coerces non-hex characters to 0x00 — a 64-char passphrase
    // would otherwise become the all-zeros seed (and the federation addresses
    // are publicly precomputable from that). Reject any non-hex content here.
    throw new Error(`seed at ${path} contains non-hex characters; expected 64 hex chars`);
  }
  return hexToBin(hex);
};

/** Derive a labeled keypair: privateKey = sha256(seed || label). */
export const deriveWallet = (seed: Uint8Array, label: string): Wallet => {
  const buf = new Uint8Array(seed.length + label.length);
  buf.set(seed, 0);
  buf.set(new TextEncoder().encode(label), seed.length);
  const privateKey = sha256Hash(buf);
  const pubResult = secp256k1.derivePublicKeyCompressed(privateKey);
  if (typeof pubResult === 'string') throw new Error(`derive ${label}: ${pubResult}`);
  return { label, privateKey, publicKey: pubResult, address: p2pkhAddrFromPubkey(pubResult) };
};

export const stripWallet = (w: Wallet): PublicWallet => ({
  label: w.label, publicKey: w.publicKey, address: w.address,
});
