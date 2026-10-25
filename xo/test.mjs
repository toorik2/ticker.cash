// Compile the templates' CashASM with XO's own compiler against a real Ticker commitment and check
// every decoded field, then check the genesis commitment script against a reference built in JS.
import { compileCashAssemblyString } from '@xo-cash/utils';
import { createHash } from 'node:crypto';
import { tickerStampTemplate } from './templates/ticker-stamp.mjs';
import { tickerReadTemplate } from './templates/ticker-read.mjs';
import { tickerGenesisTemplate } from './templates/ticker-genesis.mjs';

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
  const ctx = { variables: { tickerCommitment: new Uint8Array(commitment) }, templateVariables: template.variables, templateScripts: template.scripts };
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
  const ctx = { variables: { tickerCommitment: new Uint8Array(c) }, templateScripts: tickerReadTemplate.scripts };
  const text = compileCashAssemblyString({ ...ctx, cashAssemblyText: '$(tickerDollars).$(tickerCentsTens)$(tickerCentsOnes)', evaluationDecodeMode: 'bigint' });
  check('read 300.05 renders', text, '300.05');
}

// Genesis commitment: timestamp ‖ 0 ‖ 0 ‖ 0 ‖ 0 ‖ hash160(table), 37 bytes.
{
  const table = Buffer.alloc(34 * 13, 0x11); // any 13-row table works for the layout check
  const ctx = { variables: { startTimestamp: BigInt(TS), tableBytes: new Uint8Array(table) }, templateVariables: tickerGenesisTemplate.variables, templateScripts: tickerGenesisTemplate.scripts };
  const got = compileCashAssemblyString({ ...ctx, cashAssemblyText: '$(genesisCommitment)', evaluationDecodeMode: 'hex' });
  const want = hex(Buffer.concat([u32(TS), Buffer.alloc(13, 0), hash160(table)]));
  check('genesis commitment', got, want);
  check('genesis rows in description', compileCashAssemblyString({ ...ctx, variables: { ...ctx.variables, reserveSatoshis: 1000000n }, cashAssemblyText: tickerGenesisTemplate.actions.create.description, evaluationDecodeMode: 'bigint' }), 'Mint the head: reserve 1000000 satoshis, 13 notary rows. The category is the funding coin\'s txid.');
}

// Ticker re-emission adds the toll.
{
  // The engine merges constant values into the variable map before compiling (mergeTemplateConstantsWithInvitationVariables).
  const constants = Object.fromEntries(Object.entries(tickerStampTemplate.constants).map(([k, c]) => [k, c.value]));
  const ctx = { variables: { ...constants, tickerSatoshis: 792n }, templateScripts: tickerStampTemplate.scripts, templateVariables: tickerStampTemplate.variables };
  check('stamp re-emitted value', compileCashAssemblyString({ ...ctx, cashAssemblyText: tickerStampTemplate.outputs.tickerOutput.valueSatoshis, evaluationDecodeMode: 'bigint' }), 1792);
}
process.exit(failed ? 1 : 0);
