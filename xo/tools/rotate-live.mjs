#!/usr/bin/env node
// Change an oracle's notary table by majority approval through XO, on chipnet, with the ticker-rotate template.
//
//   node tools/rotate-live.mjs <category> <newTableHex> --signers 0,1,2,3,4,5,6 --keys keys.json [--broadcast]
//
// Several wallets take part, as they would over XO's relay: the operator (this tool's ~/.ticker-xo wallet) creates
// the invitation; each approving row accepts it in its own wallet (a throwaway engine per row here), joins role
// rowN and commits its approval; the invitation returns to the operator, who records absent rows as empty
// approvals, lets the engine compile the covenant's unlocking script, and posts the rotation.
//
// --keys points at a JSON file with the rows' private keys (hex, by row index), used here to sign the approval
// message in place of `ticker-notary sign-rotate`; a real notary operator signs on their own machine and pastes the
// 64-byte approval into their wallet.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Engine, fetchUnspentOutputsForLockingBytecode } from '@xo-cash/engine';
import { StorageType } from '@xo-cash/state';
import { compileCashAssemblyString, serializeInvitation, deserializeInvitation } from '@xo-cash/utils';
import { spawnSync } from 'node:child_process';
import { hexToBin, binToHex, decodeTransaction, generateBip39Mnemonic, sha256, hash256, secp256k1 } from '@bitauth/libauth';
import { ORACLE_LOCKING_BYTECODE } from '../templates/common.mjs';

const args = process.argv.slice(2);
const HOME = path.join(os.homedir(), '.ticker-xo');
const templateJson = fs.readFileSync(new URL('../dist/ticker-rotate.json', import.meta.url), 'utf8');
const template = JSON.parse(templateJson);
const openEngine = async (dir, mnemonicFile) => {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (!fs.existsSync(mnemonicFile)) fs.writeFileSync(mnemonicFile, generateBip39Mnemonic() + '\n', { mode: 0o600 });
  const engine = await Engine.create(fs.readFileSync(mnemonicFile, 'utf8').trim(), { network: 'chipnet', storageType: StorageType.INDEXEDDB, databasePath: dir + '/' });
  const { templateIdentifier } = await engine.importTemplate(templateJson);
  return { engine, templateIdentifier };
};

// A row's wallet, run as its own process (the engine keeps one Electrum connection pool per process):
//   rotate-live.mjs row <n> <approvalHex> <invitationFile>   — accepts the invitation as rowN, commits the approval
if (args[0] === 'row') {
  const [, rowText, approval, wireFile] = args; const row = Number(rowText);
  const dir = path.join(HOME, 'rows', `row${row}`);
  const r = await openEngine(dir, path.join(dir, 'mnemonic'));
  try {
    const accepted = await r.engine.acceptInvitation(deserializeInvitation(fs.readFileSync(wireFile, 'utf8')), { roleIdentifier: `row${row}`, variables: [{ variableIdentifier: `approval${row}`, value: approval, roleIdentifier: `row${row}` }] });
    fs.writeFileSync(wireFile, serializeInvitation(accepted.invitation));
    console.log(`row ${row} joined and approved in its own wallet (commits now ${accepted.invitation.commits.length})`);
  } catch (e) { console.error(`row ${row} error: ${e.constructor?.name ?? ''} ${e.message}`); await r.engine.stop(); process.exit(1); }
  await r.engine.stop(); process.exit(0);
}

const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const positional = args.filter((a, i) => !a.startsWith('--') && (i === 0 || !args[i - 1].startsWith('--') || args[i - 1] === '--broadcast'));
const [category, newTable] = positional;
const BROADCAST = args.includes('--broadcast');
const signers = (opt('--signers') ?? '0,1,2,3,4,5,6').split(',').map(Number);
const keys = opt('--keys') ? JSON.parse(fs.readFileSync(opt('--keys'), 'utf8')) : null;
if (!category || !newTable) { console.error('usage: rotate-live.mjs <category> <newTableHex> --signers 0,1,… --keys keys.json [--broadcast]'); process.exit(2); }

const j = (v) => JSON.stringify(v, (k, x) => typeof x === 'bigint' ? String(x) : x instanceof Uint8Array ? binToHex(x) : x);
const engines = [];
try {
  // --- operator
  const op = await openEngine(path.join(HOME, 'db'), path.join(HOME, 'mnemonic')); engines.push(op.engine);
  const heads = (await fetchUnspentOutputsForLockingBytecode(ORACLE_LOCKING_BYTECODE, op.templateIdentifier)).filter(u => u.tokenCategory === category);
  const head = heads[0]; if (!head) throw new Error(`no head with category ${category} at the Oracle lock`);
  const c = Buffer.from(head.tokenNftCommitment, 'hex');
  console.log(`head ${head.outpointTransactionHash}:${head.outpointIndex} ${head.valueSatoshis} sats · counter ${c.readUInt32LE(8)} · table ${c.subarray(17).toString('hex')}`);
  const oldTable = opt('--old-table') ?? (await (async () => {
    // the operator must know the current table; for ticker.cash it is in the manifest, for this test it is passed in
    const f = opt('--old-table-file'); if (!f) throw new Error('--old-table <hex> or --old-table-file <path> required');
    return fs.readFileSync(f, 'utf8').trim();
  })());
  const rotationFee = BigInt(opt('--fee') ?? 1700);
  const operatorVariables = [
    { variableIdentifier: 'category', value: category },
    { variableIdentifier: 'headCommitment', value: head.tokenNftCommitment },
    { variableIdentifier: 'headValue', value: BigInt(head.valueSatoshis) },
    { variableIdentifier: 'rotationFee', value: rotationFee },
    { variableIdentifier: 'oldTable', value: oldTable },
    { variableIdentifier: 'newTable', value: newTable },
  ];
  // What the rows sign, computed by the template (the same text every row's wallet shows).
  const vars = Object.fromEntries(operatorVariables.map(v => [v.variableIdentifier, v.value]));
  const message = compileCashAssemblyString({ cashAssemblyText: '$(approvalMessage)', variables: vars, templateVariables: template.variables, templateScripts: template.scripts, evaluationDecodeMode: 'hex' });
  console.log(`approval message (${message.length / 2} B): ${message.slice(0, 24)}…${message.slice(-16)}`);

  // Release anything an earlier interrupted run left reserved.
  for (const inv of await op.engine.listInvitations()) if (!inv.isArchived && inv.invitation.templateIdentifier === op.templateIdentifier) await op.engine.archiveInvitation(inv.invitation.invitationIdentifier);
  let stored = await op.engine.createInvitation({
    templateIdentifier: op.templateIdentifier, actionIdentifier: 'rotate', intent: template.start[0], variables: operatorVariables,
    inputs: [{ inputIdentifier: 'headInput', transactionIndex: 0, outpointTransactionHash: hexToBin(head.outpointTransactionHash), outpointIndex: head.outpointIndex, valueSatoshis: BigInt(head.valueSatoshis),
      token: { category: hexToBin(category), amount: 0n, nft: { capability: 'minting', commitment: hexToBin(head.tokenNftCommitment) } } }],
  });
  const id = stored.invitation.invitationIdentifier;
  stored = await op.engine.appendInvitation(id, { templateIdentifier: op.templateIdentifier, actionIdentifier: 'rotate', outputs: [{ outputIdentifier: 'headOutput', transactionIndex: 0 }] });
  console.log(`invitation ${id.slice(0, 16)}… created by the operator; open roles: ${(await op.engine.listAvailableRoles(stored.invitation)).length}`);

  // --- rows: each in its own wallet, sequentially (as a relay would order them)
  const wireFile = path.join(HOME, 'rotation-invitation.json');
  fs.writeFileSync(wireFile, serializeInvitation(stored.invitation));
  const digest = sha256.hash(hexToBin(message));
  for (const row of signers) {
    let approval;
    if (keys) approval = binToHex(secp256k1.signMessageHashSchnorr(hexToBin(keys[row]), digest));
    else approval = fs.readFileSync(path.join(HOME, 'approvals', `row${row}.hex`), 'utf8').trim();
    const child = spawnSync(process.execPath, [new URL(import.meta.url).pathname, 'row', String(row), approval, wireFile], { encoding: 'utf8', timeout: 120000 });
    process.stdout.write(child.stdout.split('\n').filter(l => l.startsWith('row ')).join('\n') + '\n');
    if (child.status !== 0) throw new Error(`row ${row} failed: ${child.stderr.split('\n').filter(l => l.includes('error')).join(' | ').slice(0, 300)}`);
  }

  // --- back to the operator
  stored = await op.engine.updateInvitation(deserializeInvitation(fs.readFileSync(wireFile, 'utf8')));
  const absent = Array.from({ length: 13 }, (_, n) => n).filter(n => !signers.includes(n));
  stored = await op.engine.appendInvitation(id, { templateIdentifier: op.templateIdentifier, actionIdentifier: 'rotate', variables: absent.map(n => ({ variableIdentifier: `approval${n}`, value: '' })) });
  console.log(`operator merged ${signers.length} approvals, recorded ${absent.length} absent rows; missing: ${j(await op.engine.listMissingRequirements(id)).slice(0, 200)}`);

  // The head is a coin of the template's Oracle lock, which the operator's wallet tracks once the invitation names it.
  for (let i = 0; i < 30; i++) { const seen = (await op.engine.listUnspentOutputs()).some(u => u.outpointTransactionHash === head.outpointTransactionHash && u.outpointIndex === head.outpointIndex); if (seen) break; await new Promise(r => setTimeout(r, 1000)); if (i === 29) throw new Error('the head did not appear in the operator wallet\'s outputs'); }
  await op.engine.signInvitation(id, 0);   // compiles rotateUnlock from the merged approvals; no key involved
  const built = await op.engine.buildInvitationTransactionFromMergedCommit(id);
  const tx = decodeTransaction(hexToBin(built.serializedTransaction)); if (typeof tx === 'string') throw new Error(tx);
  console.log(`rotation transaction ${built.serializedTransaction.length / 2} B: unlocking data ${tx.inputs[0].unlockingBytecode.length} B, output ${tx.outputs[0].valueSatoshis} sats, commitment ${binToHex(tx.outputs[0].token.nft.commitment)}`);
  const txid = binToHex(hash256(hexToBin(built.serializedTransaction)).reverse());
  fs.writeFileSync(path.join(HOME, 'rotation-last.hex'), built.serializedTransaction + '\n');
  if (!BROADCAST) { console.log(`dry run; add --broadcast to send (would be ${txid}; hex saved to ~/.ticker-xo/rotation-last.hex)`); await op.engine.archiveInvitation(id); }
  else {
    try { const res = await op.engine.executeAction(id, { broadcastTransaction: true }); console.log(`broadcast ${res.builtTransaction.transactionHash}`); }
    catch (e) {
      // The engine drops the spent head from its store as soon as Electrum reports the spend, and its post-broadcast
      // bookkeeping can lose that race. The transaction itself is out; say so and point at the saved hex.
      if (e.constructor?.name === 'UnspentOutputNotFoundInStoreError') console.log(`broadcast ${txid} (the engine's bookkeeping raced the spend notice; hex saved to ~/.ticker-xo/rotation-last.hex)`);
      else throw e;
    }
  }
} catch (e) { console.error(`error: ${e.constructor?.name ?? ''} ${e.message}`); if (e.cause) console.error('  cause:', String(e.cause).slice(0, 300)); }
for (const e of engines) await e.stop().catch(() => {});
process.exit(0);
