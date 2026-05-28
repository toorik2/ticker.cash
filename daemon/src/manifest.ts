// Manifest — the public bundle shipped to every operator.
//
// Contents (no private material):
//   - network selector ('chipnet' or 'mainnet')
//   - covenant addresses + categories + locking bytecodes (Oracle, PublisherSlot,
//     Ticker), as produced by the coordinator's deploy.ts run
//   - the 7 notary compressed pubkeys (PublisherSlot constructor OR-list)
//   - the 13 publisher PKHs (slot NFT commit identity bytes)
//   - default electrum endpoint (the operator can override via env)
//
// The manifest is identical for every operator of a given deploy. The
// coordinator generates it once at genesis and embeds it in each baked
// installer. At daemon start-up the runtime validates that the operator's
// own pubkey matches one of the manifest's `notaryPubkeys` or `publisherPkhs`
// slots, refusing to start on mismatch — that catches "wrong key for the
// wrong slot" before any covenant call.
//
// Path convention: `.ticker/manifest.json` (sibling of operator.key).

import { existsSync, readFileSync } from 'node:fs';
import type { Network } from './operator-key.js';

export interface ContractInfo {
  readonly address: string;            // bch... or bchtest... P2SH-32
  readonly lockingBytecodeHex: string; // 35-byte aa20<sha256>87
}

export interface TokenContractInfo extends ContractInfo {
  readonly category: string;           // 64-hex (txid of the genesis outpoint)
}

export interface ElectrumDefault {
  readonly host: string;
  readonly port: number;
  readonly tls: boolean;
}

export interface Manifest {
  readonly version: 1;
  readonly network: Network;
  readonly contracts: {
    readonly ticker: ContractInfo;
    readonly oracle: TokenContractInfo;
    readonly slot:   TokenContractInfo;
  };
  /** 7 compressed pubkeys (66 hex chars each), in slot order. */
  readonly notaryPubkeys: ReadonlyArray<string>;
  /** 13 PKHs (40 hex chars each), in slot order — slot N is publisherPkhs[N]. */
  readonly publisherPkhs: ReadonlyArray<string>;
  readonly electrum: ElectrumDefault;
}

const DEFAULT_MANIFEST_PATH = '.ticker/manifest.json';
const NOTARY_COUNT = 7;
const PUBLISHER_COUNT = 13;
const HEX66 = /^[0-9a-f]{66}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/;
const LOCKING_RE = /^aa20[0-9a-f]{64}87$/; // P2SH-32 OP_HASH256 <32B> OP_EQUAL

const isString = (v: unknown): v is string => typeof v === 'string';
const isNumber = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v);
const isBoolean = (v: unknown): v is boolean => typeof v === 'boolean';

const ensure = (cond: unknown, msg: string): void => {
  if (!cond) throw new Error(`manifest: ${msg}`);
};

const validateContractInfo = (label: string, c: unknown): ContractInfo => {
  ensure(c && typeof c === 'object', `${label} missing`);
  const obj = c as Record<string, unknown>;
  ensure(isString(obj.address), `${label}.address must be a string`);
  ensure(isString(obj.lockingBytecodeHex), `${label}.lockingBytecodeHex must be a string`);
  const lbh = (obj.lockingBytecodeHex as string).toLowerCase();
  ensure(LOCKING_RE.test(lbh), `${label}.lockingBytecodeHex is not a P2SH-32 script`);
  return { address: obj.address as string, lockingBytecodeHex: lbh };
};

const validateTokenContractInfo = (label: string, c: unknown): TokenContractInfo => {
  const base = validateContractInfo(label, c);
  const obj = c as Record<string, unknown>;
  ensure(isString(obj.category), `${label}.category must be a string`);
  const cat = (obj.category as string).toLowerCase();
  ensure(HEX64.test(cat), `${label}.category must be 64 hex chars (got "${obj.category}")`);
  return { ...base, category: cat };
};

const validateElectrum = (e: unknown): ElectrumDefault => {
  ensure(e && typeof e === 'object', `electrum missing`);
  const obj = e as Record<string, unknown>;
  ensure(isString(obj.host) && (obj.host as string).length > 0, `electrum.host must be a non-empty string`);
  ensure(isNumber(obj.port) && (obj.port as number) >= 1 && (obj.port as number) <= 65535,
    `electrum.port must be 1..65535`);
  ensure(isBoolean(obj.tls), `electrum.tls must be boolean`);
  return { host: obj.host as string, port: obj.port as number, tls: obj.tls as boolean };
};

/**
 * Load and validate a manifest from disk. Returns a strongly-typed,
 * lower-cased-hex normalized object.
 *
 * @throws on missing file, wrong version, or any field-level validation error
 *         (the daemon refuses to start; the operator must restore from the
 *         installer or re-fetch the bundle).
 */
export const loadManifest = (path: string = DEFAULT_MANIFEST_PATH): Manifest => {
  if (!existsSync(path)) {
    throw new Error(
      `no manifest at ${path}.\n` +
      `your installer should have placed this file — re-run the installer ` +
      `or fetch the current manifest from the coordinator.`,
    );
  }
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new Error(`manifest at ${path} is not valid JSON: ${(e as Error).message}`);
  }
  ensure(raw && typeof raw === 'object', `top level must be an object`);
  const m = raw as Record<string, unknown>;

  ensure(m.version === 1, `unsupported version (expected 1, got ${JSON.stringify(m.version)})`);

  const network = m.network;
  ensure(network === 'chipnet' || network === 'mainnet',
    `network must be "chipnet" or "mainnet" (got ${JSON.stringify(network)})`);

  ensure(m.contracts && typeof m.contracts === 'object', `contracts missing`);
  const contracts = m.contracts as Record<string, unknown>;
  const ticker = validateContractInfo('contracts.ticker', contracts.ticker);
  const oracle = validateTokenContractInfo('contracts.oracle', contracts.oracle);
  const slot   = validateTokenContractInfo('contracts.slot',   contracts.slot);

  ensure(Array.isArray(m.notaryPubkeys), `notaryPubkeys must be an array`);
  const nps = m.notaryPubkeys as unknown[];
  ensure(nps.length === NOTARY_COUNT,
    `notaryPubkeys must have ${NOTARY_COUNT} entries (got ${nps.length})`);
  const notaryPubkeys = nps.map((v, i) => {
    ensure(isString(v), `notaryPubkeys[${i}] must be a string`);
    const lc = (v as string).toLowerCase();
    ensure(HEX66.test(lc), `notaryPubkeys[${i}] must be 66 hex chars (compressed secp256k1)`);
    return lc;
  });

  ensure(Array.isArray(m.publisherPkhs), `publisherPkhs must be an array`);
  const pps = m.publisherPkhs as unknown[];
  ensure(pps.length === PUBLISHER_COUNT,
    `publisherPkhs must have ${PUBLISHER_COUNT} entries (got ${pps.length})`);
  const publisherPkhs = pps.map((v, i) => {
    ensure(isString(v), `publisherPkhs[${i}] must be a string`);
    const lc = (v as string).toLowerCase();
    ensure(HEX40.test(lc), `publisherPkhs[${i}] must be 40 hex chars (RIPEMD-160 of compressed pubkey)`);
    return lc;
  });

  const electrum = validateElectrum(m.electrum);

  return {
    version: 1,
    network: network as Network,
    contracts: { ticker, oracle, slot },
    notaryPubkeys,
    publisherPkhs,
    electrum,
  };
};
