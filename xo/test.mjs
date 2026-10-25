// Compile the templates' CashASM with XO's own compiler against a real Ticker commitment and check
// every decoded field, then check the genesis commitment script against a reference built in JS.
import { compileCashAssemblyString } from '@xo-cash/utils';
import { createCompilerBch, hexToBin, binToHex, sha256, secp256k1 } from '@bitauth/libauth';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { tickerStampTemplate } from './templates/ticker-stamp.mjs';
import { tickerReadTemplate } from './templates/ticker-read.mjs';
import { tickerGenesisTemplate } from './templates/ticker-genesis.mjs';
import { tickerRotateTemplate } from './templates/ticker-rotate.mjs';

const hex = (u8) => Buffer.from(u8).toString('hex');
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const hash160 = (b) => createHash('ripemd160').update(createHash('sha256').update(b).digest()).digest();

let failed = 0;
const check = (label, got, want) => {
  const ok = String(got) === String(want);
  if (!ok) failed++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}: ${got}${ok ? '' : ` (want ${want})`}`);
};

// Live head at 16:14 UTC on 2026-10-25: ts 1792944840, counter 23, 275.80 USD, 13 rows.
const TS = 1792944840, SEQ = 23, CENTS = 27580, K = 13;
const commitment = Buffer.concat([u32(TS), u32(SEQ), u32(SEQ), u32(CENTS), Buffer.from([K])]);
check('commitment length', commitment.length, 17);

for (const [name, template] of [['stamp', tickerStampTemplate], ['read', tickerReadTemplate]]) {
  // Variables arrive as text in the engine; the decoders ask the nft_commitment primitive for its bytes.
  const ctx = { variables: { tickerCommitment: hex(commitment) }, templateVariables: template.variables, templateScripts: template.scripts };
  const evalInt = (script) => compileCashAssemblyString({ ...ctx, cashAssemblyText: `$(${script})`, evaluationDecodeMode: 'bigint' });
  check(`${name} tickerTimestamp`, evalInt('tickerTimestamp'), TS);
  check(`${name} tickerSequence`, evalInt('tickerSequence'), SEQ);
  check(`${name} tickerPriceCents`, evalInt('tickerPriceCents'), CENTS);
  check(`${name} tickerRows`, evalInt('tickerRows'), K);
  check(`${name} dollars.cents`, `${evalInt('tickerDollars')}.${evalInt('tickerCentsTens')}${evalInt('tickerCentsOnes')}`, '275.80');
  for (const [field, def] of Object.entries(template.data)) {
    check(`${name} data.${field}`, compileCashAssemblyString({ ...ctx, cashAssemblyText: def.value, evaluationDecodeMode: 'bigint' }), { timestamp: TS, sequence: SEQ, priceCents: CENTS, rowsSigned: K }[field]);
  }
  // Descriptions render with the live numbers.
  const action = Object.values(template.actions)[0];
  console.log(`     ${name} action text: ${compileCashAssemblyString({ ...ctx, variables: { ...ctx.variables, paymentSatoshis: 123456n }, cashAssemblyText: action.description, evaluationDecodeMode: 'bigint' })}`);
}

// Price with cents below 10 keeps its leading zero.
{
  const c = Buffer.concat([u32(TS), u32(SEQ), u32(SEQ), u32(30005), Buffer.from([7])]);
  const ctx = { variables: { tickerCommitment: hex(c) }, templateVariables: tickerReadTemplate.variables, templateScripts: tickerReadTemplate.scripts };
  const text = compileCashAssemblyString({ ...ctx, cashAssemblyText: '$(tickerDollars).$(tickerCentsTens)$(tickerCentsOnes)', evaluationDecodeMode: 'bigint' });
  check('read 300.05 renders', text, '300.05');
}

// Genesis commitment computed by the template from text variables (as the engine supplies them):
// timestamp ‖ 13 zero bytes ‖ hash160(table), returned as hex text for the engine's token decoder.
{
  const table = Buffer.alloc(34 * 13, 0x11);
  const want = hex(Buffer.concat([u32(TS), Buffer.alloc(13, 0), hash160(table)]));
  const ctx = { variables: { startTimestamp: BigInt(TS), tableBytes: hex(table), reserveSatoshis: 1000000n }, templateVariables: tickerGenesisTemplate.variables, templateScripts: tickerGenesisTemplate.scripts };
  const t0 = Date.now();
  check('genesis commitment on-template', compileCashAssemblyString({ ...ctx, cashAssemblyText: tickerGenesisTemplate.outputs.headOutput.token.nft.commitment, evaluationDecodeMode: 'utf8' }), want);
  console.log(`     (${Date.now() - t0} ms to decode 442 bytes of table text, hash it and encode the commitment)`);
  check('genesis action text', compileCashAssemblyString({ ...ctx, cashAssemblyText: tickerGenesisTemplate.actions.create.description, evaluationDecodeMode: 'utf8' }), `Mint the head over the notary table whose hash160 is ${hex(hash160(table))}. The category is the funding coin's txid.`);
  check('genesis transaction text', compileCashAssemblyString({ ...ctx, cashAssemblyText: tickerGenesisTemplate.transactions.createTransaction.description, evaluationDecodeMode: 'bigint' }), 'Minted an oracle head with a reserve of 1000000 satoshis.');
}

// Rotation: the template's unlocking script, compiled the way the engine compiles it (libauth, hex variables as
// raw bytes), against the Rust-built vector; the next commitment and the approval message against the same vector.
{
  const v = JSON.parse(fs.readFileSync(new URL('../contracts/test/v27-vectors.json', import.meta.url), 'utf8'));
  const T = tickerRotateTemplate;
  const tx = hexToBin(v.rotate.tx);
  // input 0 unlocking script: version(4) count(1) outpoint(36) varint length
  const len = tx[41] === 0xfd ? tx[42] | (tx[43] << 8) : tx[41]; const start = tx[41] === 0xfd ? 44 : 42;
  const want = binToHex(tx.subarray(start, start + len));
  const compiler = createCompilerBch({ scripts: T.scripts, variables: Object.fromEntries(Object.keys(T.variables).map(k => [k, { type: 'WalletData' }])), lockingScriptTypes: { oracleLockingBytecode: 'standard' }, unlockingScripts: { rotateUnlock: 'oracleLockingBytecode' } });
  const bytecode = { oldTable: hexToBin(v.table) };
  for (let n = 0; n < 13; n++) bytecode[`approval${n}`] = new Uint8Array(0);
  v.rotate.signers.forEach((row, i) => bytecode[`approval${row}`] = hexToBin(v.rotate.approvals[i]));
  const r = compiler.generateBytecode({ data: { bytecode }, scriptId: 'rotateUnlock' });
  check('rotate unlocking script (libauth) == Rust vector', r.success ? binToHex(r.bytecode) : 'compile failed', want);
  const vars = { category: v.category, headCommitment: '40cdd26ae8030000e8030000487100000d' + v.table_hash, newTable: v.rotate.new_table };
  const ctx = { variables: vars, templateVariables: T.variables, templateScripts: T.scripts };
  check('rotate next commitment == vector output', compileCashAssemblyString({ ...ctx, cashAssemblyText: T.outputs.headOutput.token.nft.commitment, evaluationDecodeMode: 'utf8' }), '40cdd26ae8030000e8030000487100000d5593ac88fed94b694cff51f42a1e2d308e9a58ab');
  const msg = compileCashAssemblyString({ ...ctx, cashAssemblyText: '$(approvalMessage)', evaluationDecodeMode: 'hex' });
  const digest = sha256.hash(hexToBin(msg));
  const verified = v.rotate.signers.filter((row, i) => secp256k1.verifySignatureSchnorr(hexToBin(v.rotate.approvals[i]), secp256k1.derivePublicKeyCompressed(hexToBin(v.keys[row])), digest)).length;
  check('rotate approval message verifies the 7 vector approvals', verified, 7);
}

// Ticker re-emission adds the toll.
{
  // The engine merges constant values into the variable map before compiling (mergeTemplateConstantsWithInvitationVariables).
  const constants = Object.fromEntries(Object.entries(tickerStampTemplate.constants).map(([k, c]) => [k, c.value]));
  const ctx = { variables: { ...constants, tickerSatoshis: 792n }, templateScripts: tickerStampTemplate.scripts, templateVariables: tickerStampTemplate.variables };
  check('stamp re-emitted value', compileCashAssemblyString({ ...ctx, cashAssemblyText: tickerStampTemplate.outputs.tickerOutput.valueSatoshis, evaluationDecodeMode: 'bigint' }), 1792);
}
process.exit(failed ? 1 : 0);
