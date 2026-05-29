#!/usr/bin/env tsx
/**
 * bake-installer — coordinator tool that produces a single self-contained
 * bash installer for one operator.
 *
 * Inputs (from this machine, the coordinator's box):
 *   - .ticker/seed.hex            master seed; all 20 federation keys derive
 *                                 from this label-hashed.
 *   - .ticker/deploy-state.json   on-chain contract addresses + categories.
 *
 * Inputs (from CLI):
 *   --label NAME                  operator's label, e.g. "alice"
 *   --notary-slot N               0..6 (omit if operator is publisher-only)
 *   --publisher-slot M            0..12 (omit if operator is notary-only)
 *   --network chipnet|mainnet     default: chipnet
 *   --fulcrum-host HOST           default: fulcrum.layer1.cash
 *   --fulcrum-port PORT           default: 50001
 *   --fulcrum-tls                 default: false (omit flag for plain TCP)
 *   --repo-url URL                default: https://github.com/toorik2/ticker.cash
 *   --out PATH                    default: ./ticker-install-<label>.sh
 *
 * Output:
 *   A bash file with the operator's keyfile(s) + manifest baked inline, plus
 *   the install-payload that clones the repo, installs deps, writes
 *   credentials, installs a systemd unit, and starts the daemon.
 *
 *   Mode 0700 (executable by owner only). Hand to the operator via secure
 *   channel — anyone with the .sh file has the operator's keys.
 *
 * Example:
 *   tsx scripts/bake-installer.ts --label alice --notary-slot 2 --publisher-slot 5
 *   tsx scripts/bake-installer.ts --label bob --publisher-slot 3   # publisher only
 */

import {
  existsSync,
  readFileSync,
  writeFileSync,
  chmodSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { binToHex, hash160 } from '@bitauth/libauth';
import { deriveWallets, NOTARY_COUNT, PUBLISHER_COUNT } from '../src/keys.js';
import { loadSeed } from '../src/master-seed.js';
import type { Manifest } from '../src/manifest.js';
import type { Network } from '../src/operator-key.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PAYLOAD_PATH = join(__dirname, 'install-payload.sh');
const SEED_PATH = '.ticker/seed.hex';
const DEPLOY_STATE_PATH = '.ticker/deploy-state.json';

interface BakeOptions {
  readonly label: string;
  readonly notarySlot?: number;
  readonly publisherSlot?: number;
  readonly network: Network;
  readonly fulcrumHost: string;
  readonly fulcrumPort: number;
  readonly fulcrumTls: boolean;
  readonly repoUrl: string;
  readonly outPath: string;
}

interface DeployState {
  readonly tickerAddress: string;
  readonly tickerLockingBytecodeHex: string;
  readonly slotCategory: string;
  readonly slotAddress: string;
  readonly slotLockingBytecodeHex: string;
  readonly oracleCategory: string;
  readonly oracleAddress: string;
  readonly oracleLockingBytecodeHex: string;
}

const LABEL_RE = /^[a-zA-Z0-9_.-]{1,40}$/;

const parseArgs = (): BakeOptions => {
  const argv = process.argv.slice(2);
  const flagValue = (name: string): string | undefined => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const flagPresent = (name: string): boolean => argv.includes(name);

  const label = flagValue('--label');
  if (!label) throw new Error('--label NAME is required');
  if (!LABEL_RE.test(label)) {
    throw new Error(`--label must match ${LABEL_RE.source} (alphanumerics + . _ -, 1-40 chars)`);
  }

  const parseSlot = (flag: string, max: number): number | undefined => {
    const v = flagValue(flag);
    if (v === undefined) return undefined;
    const n = parseInt(v, 10);
    if (!Number.isInteger(n) || n < 0 || n >= max) {
      throw new Error(`${flag} must be 0..${max - 1} (got ${v})`);
    }
    return n;
  };
  const notarySlot    = parseSlot('--notary-slot',    NOTARY_COUNT);
  const publisherSlot = parseSlot('--publisher-slot', PUBLISHER_COUNT);
  if (notarySlot === undefined && publisherSlot === undefined) {
    throw new Error('at least one of --notary-slot or --publisher-slot is required');
  }

  const network = (flagValue('--network') ?? 'chipnet') as Network;
  if (network !== 'chipnet' && network !== 'mainnet') {
    throw new Error(`--network must be "chipnet" or "mainnet" (got "${network}")`);
  }

  const fulcrumHost = flagValue('--fulcrum-host') ?? 'fulcrum.layer1.cash';
  const fulcrumPort = parseInt(flagValue('--fulcrum-port') ?? '50001', 10);
  if (!Number.isInteger(fulcrumPort) || fulcrumPort < 1 || fulcrumPort > 65535) {
    throw new Error(`--fulcrum-port must be 1..65535 (got ${fulcrumPort})`);
  }
  const fulcrumTls  = flagPresent('--fulcrum-tls');

  const repoUrl = flagValue('--repo-url') ?? 'https://github.com/toorik2/ticker.cash';
  const outPath = flagValue('--out')      ?? `./ticker-install-${label}.sh`;

  return {
    label, notarySlot, publisherSlot, network,
    fulcrumHost, fulcrumPort, fulcrumTls,
    repoUrl, outPath,
  };
};

const loadDeployState = (): DeployState => {
  if (!existsSync(DEPLOY_STATE_PATH)) {
    throw new Error(
      `no deploy state at ${DEPLOY_STATE_PATH}.\n` +
      `run scripts/deploy.ts --broadcast on this box first, or copy a known-good ` +
      `deploy-state.json into .ticker/`,
    );
  }
  const s = JSON.parse(readFileSync(DEPLOY_STATE_PATH, 'utf8')) as Partial<DeployState>;
  const required = [
    'tickerAddress', 'tickerLockingBytecodeHex',
    'slotCategory', 'slotAddress', 'slotLockingBytecodeHex',
    'oracleCategory', 'oracleAddress', 'oracleLockingBytecodeHex',
  ] as const;
  for (const k of required) {
    if (!s[k]) throw new Error(`deploy-state.json missing ${k}`);
  }
  return s as DeployState;
};

const gitRev = (): string => {
  // execFile (no shell) — args are fixed literals, no injection surface.
  try {
    return execFileSync('git', ['rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
};

const shellSingleQuote = (s: string): string =>
  `'${s.replace(/'/g, `'\\''`)}'`;

const buildManifest = (
  notaryPubkeysHex: ReadonlyArray<string>,
  publisherPkhsHex: ReadonlyArray<string>,
  deploy: DeployState,
  opts: BakeOptions,
): Manifest => ({
  version: 1,
  network: opts.network,
  contracts: {
    ticker: {
      address:           deploy.tickerAddress,
      lockingBytecodeHex: deploy.tickerLockingBytecodeHex,
    },
    oracle: {
      address:           deploy.oracleAddress,
      category:          deploy.oracleCategory,
      lockingBytecodeHex: deploy.oracleLockingBytecodeHex,
    },
    slot: {
      address:           deploy.slotAddress,
      category:          deploy.slotCategory,
      lockingBytecodeHex: deploy.slotLockingBytecodeHex,
    },
  },
  notaryPubkeys: notaryPubkeysHex,
  publisherPkhs: publisherPkhsHex,
  electrum: {
    host: opts.fulcrumHost,
    port: opts.fulcrumPort,
    tls:  opts.fulcrumTls,
  },
});

const renderInstaller = (opts: BakeOptions, vars: Record<string, string>): string => {
  if (!existsSync(PAYLOAD_PATH)) {
    throw new Error(`install-payload.sh not found at ${PAYLOAD_PATH}`);
  }
  const payload = readFileSync(PAYLOAD_PATH, 'utf8');
  const header = [
    '#!/usr/bin/env bash',
    '#',
    `# ticker.cash node installer · operator: ${opts.label}`,
    `# baked at:        ${new Date().toISOString()}`,
    `# repo rev (HEAD): ${vars.TICKER_REPO_REV}`,
    `# network:         ${opts.network}`,
    `# notary slot:     ${opts.notarySlot ?? '-'}`,
    `# publisher slot:  ${opts.publisherSlot ?? '-'}`,
    '#',
    `# Anyone with this file has this operator's slot key(s). Hand-deliver via`,
    '# secure channel; do not paste into logs, chat, or third-party services.',
    '',
    'set -euo pipefail',
    '',
  ];
  const varBlock = Object.entries(vars).map(([k, v]) => `${k}=${shellSingleQuote(v)}`);
  return [
    ...header,
    ...varBlock,
    '',
    '# ─── install payload (verbatim from daemon/scripts/install-payload.sh) ───',
    payload,
  ].join('\n');
};

const main = (): void => {
  const opts = parseArgs();
  const seed = loadSeed(SEED_PATH);
  const wallets = deriveWallets(seed);
  const deploy = loadDeployState();
  const rev = gitRev();

  if (wallets.notaries.length !== NOTARY_COUNT) {
    throw new Error(`expected ${NOTARY_COUNT} notaries derivable from seed`);
  }
  if (wallets.publishers.length !== PUBLISHER_COUNT) {
    throw new Error(`expected ${PUBLISHER_COUNT} publishers derivable from seed`);
  }

  const notaryPubkeysHex = wallets.notaries.map((n) => binToHex(n.publicKey));
  const publisherPkhsHex = wallets.publishers.map((p) => binToHex(hash160(p.publicKey)));

  const notaryKeyHex    = opts.notarySlot    !== undefined ? binToHex(wallets.notaries[opts.notarySlot]!.privateKey)    : '';
  const publisherKeyHex = opts.publisherSlot !== undefined ? binToHex(wallets.publishers[opts.publisherSlot]!.privateKey) : '';

  const manifest = buildManifest(notaryPubkeysHex, publisherPkhsHex, deploy, opts);
  const manifestB64 = Buffer.from(JSON.stringify(manifest, null, 2), 'utf8').toString('base64');

  const vars: Record<string, string> = {
    TICKER_OPERATOR_LABEL: opts.label,
    TICKER_NETWORK:        opts.network,
    TICKER_NOTARY_SLOT:    opts.notarySlot    !== undefined ? String(opts.notarySlot)    : '',
    TICKER_PUBLISHER_SLOT: opts.publisherSlot !== undefined ? String(opts.publisherSlot) : '',
    TICKER_NOTARY_KEY_HEX:    notaryKeyHex,
    TICKER_PUBLISHER_KEY_HEX: publisherKeyHex,
    TICKER_MANIFEST_B64:   manifestB64,
    TICKER_REPO_URL:       opts.repoUrl,
    TICKER_REPO_REV:       rev,
  };

  const installerText = renderInstaller(opts, vars);
  writeFileSync(opts.outPath, installerText);
  chmodSync(opts.outPath, 0o700);

  // Sanity output (no secrets leaked).
  console.log(`baked: ${opts.outPath}`);
  console.log(`  operator:        ${opts.label}`);
  console.log(`  network:         ${opts.network}`);
  console.log(`  notary slot:     ${opts.notarySlot    ?? '-'}`);
  console.log(`  publisher slot:  ${opts.publisherSlot ?? '-'}`);
  console.log(`  fulcrum:         ${opts.fulcrumHost}:${opts.fulcrumPort}${opts.fulcrumTls ? ' (tls)' : ''}`);
  console.log(`  manifest:        ${manifestB64.length} chars (base64)`);
  console.log(`  bytes:           ${installerText.length}`);
  console.log();
  console.log(`hand-deliver to ${opts.label} via secure channel.`);
  console.log(`operator runs:   bash ${opts.outPath}`);
};

main();
