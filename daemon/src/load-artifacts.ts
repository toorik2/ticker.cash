import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Artifact } from 'cashscript';

const __dirname = dirname(fileURLToPath(import.meta.url));
const artifactsDir = join(__dirname, '..', '..', 'contracts', 'artifacts');

const loadArtifact = (name: string): Artifact =>
  JSON.parse(readFileSync(join(artifactsDir, `${name}.json`), 'utf8')) as Artifact;

export const OracleArtifact = loadArtifact('Oracle');
export const TickerArtifact = loadArtifact('Ticker');
export const VerifiedAttestationArtifact = loadArtifact('VerifiedAttestation');
export const TLSNotaryGatewayArtifact = loadArtifact('TLSNotaryGateway');

// Oracle commit (19 B): 0x60 | seq(4) | lastTs(4) | medianUsd(8) | activeCount(2)
export const ORACLE_COMMIT_LEN = 19;
// Ticker commit (17 B): 0x80 | seq(4) | lastTs(4) | medianPrice(8)
export const TICKER_COMMIT_LEN = 17;
// Per Oracle.cash: 4 Mutable Ticker NFTs minted at outputs[1..5).
export const TICKER_HEAD_COUNT = 2;
