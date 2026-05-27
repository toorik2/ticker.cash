/**
 * v7 state queries — fetch the current Oracle UTXO from Fulcrum and decode
 * its 115-byte commitment per the v7 contract layout.
 *
 * Commitment layouts (locked in contracts/v7/Oracle.cash):
 *   Oracle (115 B):
 *     0x60 || seq(u32 LE) || locktime(u32 LE) || medianPrice(u64 LE)
 *       || activeCount(u16 LE) || history(12 × u64 LE) = 1+4+4+8+2+96 = 115
 *
 * Quote (113 B) is defined in v7.contracts/Quote.cash but currently UNUSED
 * by Oracle.update (cashscript dual-loop issue under investigation; v7.1
 * will re-enable). Until then, consumers read price directly from Oracle.
 */
import { electrumRequest } from './electrum.js';
import contracts from './contracts.json';

export interface DecodedOracle {
  version: number;
  seq: number;
  lastLocktime: number;          // v9: now lastTs (notary-attested wall-clock); name kept for API stability
  medianPriceScaled: bigint;
  medianUsd: number;
  activeCount: number;
}

const PRICE_DIVISOR = 100_000_000n;  // USD × 1e8 → USD
const V9_ORACLE_COMMIT_LEN = 19;

function decodeOracleCommitment(hex: string): DecodedOracle {
  const buf = Buffer.from(hex, 'hex');
  if (buf.length !== V9_ORACLE_COMMIT_LEN) {
    throw new Error(`expected ${V9_ORACLE_COMMIT_LEN}-byte Oracle commit, got ${buf.length}`);
  }
  const version = buf.readUInt8(0);
  if (version !== 0x60) throw new Error(`expected Oracle version 0x60, got 0x${version.toString(16)}`);

  return {
    version,
    seq: buf.readUInt32LE(1),
    lastLocktime: buf.readUInt32LE(5),
    medianPriceScaled: buf.readBigUInt64LE(9),
    medianUsd: Number(buf.readBigUInt64LE(9)) / Number(PRICE_DIVISOR),
    activeCount: buf.readUInt16LE(17),
  };
}

interface ScripthashUtxo {
  tx_hash: string;
  tx_pos: number;
  value: number;
  height: number;
  token_data?: {
    category: string;
    amount: string;
    nft?: {
      capability: string;
      commitment: string;
    };
  };
}

async function getAddressUtxos(address: string): Promise<ScripthashUtxo[]> {
  return electrumRequest<ScripthashUtxo[]>(
    'blockchain.address.listunspent',
    address,
    'include_tokens',
  );
}

/**
 * Returns the current Oracle UTXO + decoded commitment.
 * Throws if Fulcrum is unreachable or the UTXO is missing.
 */
export async function getOracleState(): Promise<{
  utxo: ScripthashUtxo;
  decoded: DecodedOracle;
}> {
  const utxos = await getAddressUtxos(contracts.oracle.address);
  const oracleUtxo = utxos.find(
    (u) =>
      u.token_data?.category === contracts.oracle.category &&
      u.token_data?.nft?.commitment != null,
  );
  if (!oracleUtxo || !oracleUtxo.token_data?.nft?.commitment) {
    throw new Error('Oracle UTXO not found at address');
  }
  const decoded = decodeOracleCommitment(oracleUtxo.token_data.nft.commitment);
  return { utxo: oracleUtxo, decoded };
}

export { decodeOracleCommitment };
