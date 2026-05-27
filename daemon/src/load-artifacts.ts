import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Artifact } from 'cashscript';

const __dirname = dirname(fileURLToPath(import.meta.url));
const artifactsDir = join(__dirname, '..', '..', 'contracts', 'artifacts');

const loadArtifact = (name: string): Artifact =>
  JSON.parse(readFileSync(join(artifactsDir, `${name}.json`), 'utf8')) as Artifact;

// v12 contract set:
//   Oracle.cash         — walks PublisherSlot inputs, re-emits each unchanged,
//                         mints 2 Tickers per cycle.
//   PublisherSlot.cash  — per-publisher persistent mutable NFT; replaces
//                         v11's TLSNotaryGateway + VerifiedAttestation.
//   Ticker.cash         — unchanged from v11; consumer-side chain head.
export const OracleArtifact = loadArtifact('Oracle');
export const PublisherSlotArtifact = loadArtifact('PublisherSlot');
export const TickerArtifact = loadArtifact('Ticker');

// Oracle commit (19 B): 0x60 | seq(4) | lastTs(4) | medianUsd(8) | activeCount(2)
export const ORACLE_COMMIT_LEN = 19;
// Ticker commit (17 B): 0x80 | seq(4) | lastTs(4) | medianPrice(8)
export const TICKER_COMMIT_LEN = 17;
// Slot commit (39 B): 0x72 | sourceId(2) | publisherPkh(20) | price(8) | timestamp(4) | cycleSeq(4)
export const SLOT_COMMIT_LEN = 39;
// Per Oracle.cash: 2 Mutable Ticker NFTs minted at outputs[N+1, N+2].
export const TICKER_HEAD_COUNT = 2;
// v12 slot version byte
export const SLOT_VERSION_BYTE = 0x72;
