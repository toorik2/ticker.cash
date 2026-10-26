#!/usr/bin/env node
// Instantiate an oracle from a headless XO engine, on chipnet, with the ticker-genesis template.
//
//   node tools/genesis-live.mjs fund <satoshis> [--broadcast]        # coin at the founder key, output 0 of its tx
//   node tools/genesis-live.mjs create <reserve> [--broadcast]       # spend that coin at input 0 into a new head
//   node tools/genesis-live.mjs variables <reserve> --funding <txid>:0 [--funding-sats N]
//                                                                    # the JSON a Dev Wallet user pastes for `create`
//   options: --manifest <url|path>   table to instantiate over (default: ticker.cash's live manifest)
//            --funding <txid:index>  the funding coin (default: the newest coin at the founder lock)
//
// Same throwaway wallet as stamp-live.mjs (~/.ticker-xo). The category of the new oracle is the txid of the
// funding coin, which must sit at output 0 of its transaction: `fund` pins its output there, `create` pins
// the coin at input 0 and supplies the txid as the `category` variable. A mismatch is a consensus-invalid
// transaction, nothing more.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { Engine } from '@xo-cash/engine';
import { StorageType } from '@xo-cash/state';
import { p2pkhTemplate } from '@xo-cash/templates';
import { hexToBin, binToHex, decodeTransaction, generateBip39Mnemonic, lockingBytecodeToCashAddress } from '@bitauth/libauth';

const HOME = path.join(os.homedir(), '.ticker-xo');
fs.mkdirSync(path.join(HOME, 'db'), { recursive: true, mode: 0o700 });
const mnemonicPath = path.join(HOME, 'mnemonic');
if (!fs.existsSync(mnemonicPath)) fs.writeFileSync(mnemonicPath, generateBip39Mnemonic() + '\n', { mode: 0o600 });
const mnemonic = fs.readFileSync(mnemonicPath, 'utf8').trim();

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const [cmd, amountArg] = args.filter(a => !a.startsWith('--') && a !== opt('--manifest') && a !== opt('--funding') && a !== opt('--funding-sats'));
const BROADCAST = args.includes('--broadcast');
const MANIFEST = opt('--manifest') ?? 'https://usd.ticker.cash/manifest.json';
const genesisJson = fs.readFileSync(new URL('../dist/ticker-genesis.json', import.meta.url), 'utf8');
const startIntent = (action) => JSON.parse(genesisJson).start.find(s => s.action === action);   // carries generate: ['founderKey']
const hash160 = (b) => createHash('ripemd160').update(createHash('sha256').update(b).digest()).digest();
/** A manifest's notary table as the template's `tableBytes`, with its hash160 checked against the manifest. */
const loadTable = async (manifest) => {
  const m = manifest.startsWith('http') ? await (await fetch(manifest)).json() : JSON.parse(fs.readFileSync(manifest, 'utf8'));
  const rows = [...m.table].sort((a, b) => a.row - b.row);
  const tableBytes = Buffer.concat(rows.map(r => Buffer.concat([Buffer.from(r.pubkey, 'hex'), Buffer.from([r.source])])));
  const tableHash = hash160(tableBytes).toString('hex');
  if (m.table_hash && tableHash !== m.table_hash) throw new Error(`table hash ${tableHash} does not match the manifest's ${m.table_hash}`);
  return { rows, tableBytes, tableHash };
};

// `variables`: the object a Dev Wallet user pastes into "Paste variables JSON" on `create`, started from the funding
// coin in that wallet. The category is the coin's txid, handed over as a variable until the engine can read input 0
// itself (General Protocols' interim advice, 2026-10-26). Needs no wallet here.
if (cmd === 'variables') {
  const pick = opt('--funding');
  if (!amountArg || !/^[0-9a-f]{64}:0$/.test(pick ?? '')) { console.error('usage: genesis-live.mjs variables <reserve> --funding <txid>:0 [--funding-sats N] [--manifest …]'); process.exit(2); }
  const { rows, tableBytes, tableHash } = await loadTable(MANIFEST);
  const vars = { category: pick.slice(0, 64), tableBytes: tableBytes.toString('hex'), reserveSatoshis: amountArg, startTimestamp: String(Math.floor(Date.now() / 60000) * 60) };
  if (opt('--funding-sats')) vars.fundingSatoshis = opt('--funding-sats');
  console.error(`table: ${rows.length} rows, hash160 ${tableHash}. In the Dev Wallet, start \`create\` from the funding coin and paste:`);
  console.log(JSON.stringify(vars, null, 2));
  process.exit(0);
}
const show = (label, serialized) => {
  const tx = decodeTransaction(hexToBin(serialized)); if (typeof tx === 'string') throw new Error(tx);
  console.log(`${label}: ${serialized.length / 2} B, ${tx.inputs.length} inputs, ${tx.outputs.length} outputs`);
  tx.outputs.forEach((o, n) => console.log(`  out${n} ${o.valueSatoshis} sats lock ${binToHex(o.lockingBytecode).slice(0, 20)}…${o.token ? ` token ${binToHex(o.token.category)} ${o.token.nft?.capability} ${binToHex(o.token.nft?.commitment ?? new Uint8Array())}` : ''}`));
  return tx;
};

const engine = await Engine.create(mnemonic, { network: 'chipnet', storageType: StorageType.INDEXEDDB, databasePath: path.join(HOME, 'db') + '/' });
const quit = async (code) => { await engine.stop(); process.exit(code); };
try {
  const { templateIdentifier: p2pkhId } = await engine.importTemplate(p2pkhTemplate);
  if (!(await engine.getDefaultPolicies()).address) {
    await engine.setDefaultPolicies({ address: { templateIdentifier: p2pkhId, ...p2pkhTemplate.defaults.address }, change: { templateIdentifier: p2pkhId, ...p2pkhTemplate.defaults.change }, receive: { templateIdentifier: p2pkhId, ...p2pkhTemplate.defaults.receive } });
  }
  const { templateIdentifier } = await engine.importTemplate(genesisJson);
  if (cmd === 'release') {
    let n = 0;
    for (const inv of await engine.listInvitations()) if (!inv.isArchived) { await engine.archiveInvitation(inv.invitation.invitationIdentifier); n++; }
    console.log(`archived ${n} open invitation(s); their coins are spendable again`);
    await quit(0);
  }
  const all = await engine.listSpendableUnspentOutputs();
  const walletCoins = all.filter(u => u.templateIdentifier === p2pkhId);
  // Coins at founder keys (also from earlier versions of this template). Token-bearing coins are oracle heads the
  // wallet tracks for the rotate template; they are never funding coins.
  const founderCoins = all.filter(u => u.templateIdentifier !== p2pkhId && u.tokenCategory === undefined);
  console.log(`wallet: ${walletCoins.reduce((a, u) => a + BigInt(u.valueSatoshis), 0n)} sats in ${walletCoins.length} coins; at the founder key: ${founderCoins.map(u => `${u.outpointTransactionHash.slice(0, 12)}…:${u.outpointIndex} ${u.valueSatoshis}`).join(', ') || 'none'}`);

  if (cmd === 'fund') {
    const amount = BigInt(amountArg);
    const coin = walletCoins.find(u => BigInt(u.valueSatoshis) >= amount + 1000n);
    if (!coin) throw new Error('no wallet coin covers the funding amount plus fee');
    const stored = await engine.createInvitation({ templateIdentifier, actionIdentifier: 'fund', intent: startIntent('fund'), variables: [{ variableIdentifier: 'fundingSatoshis', value: amount }] });
    const id = stored.invitation.invitationIdentifier;
    // The founder's output is locked to a key this invitation generated; the engine resolves it into the invitation.
    await engine.appendOwnOutputResolutions(id, 'fundingOutput', 'founder').catch(() => {});
    await engine.appendInvitation(id, { templateIdentifier, actionIdentifier: 'fund', outputs: [{ outputIdentifier: 'fundingOutput', transactionIndex: 0, roleIdentifier: 'founder' }] });
    await engine.appendInvitation(id, { templateIdentifier, actionIdentifier: 'fund', inputs: [{ outpointTransactionHash: hexToBin(coin.outpointTransactionHash), outpointIndex: coin.outpointIndex, valueSatoshis: BigInt(coin.valueSatoshis) }] });
    await engine.addChangeToInvitation(id);
    for (const i of await engine.listOwnInputIndexes(id)) await engine.signInvitation(id, i);
    const built = await engine.buildInvitationTransactionFromMergedCommit(id);
    const tx = show('fund transaction', built.serializedTransaction);
    const addr = lockingBytecodeToCashAddress({ bytecode: tx.outputs[0].lockingBytecode, prefix: 'bchtest' });
    console.log(`  founder key address ${typeof addr === 'string' ? addr : addr.address}`);
    if (!BROADCAST) { console.log('dry run; add --broadcast to send'); await engine.archiveInvitation(id); await quit(0); }
    const res = await engine.executeAction(id, { broadcastTransaction: true });
    console.log(`broadcast ${res.builtTransaction.transactionHash}  ← the future category`);
    await quit(0);
  }

  if (cmd === 'create') {
    const reserve = BigInt(amountArg);
    const { rows, tableBytes, tableHash } = await loadTable(MANIFEST);
    console.log(`table: ${rows.length} rows, hash160 ${tableHash}`);
    const pick = opt('--funding');
    const funding = pick ? founderCoins.find(u => `${u.outpointTransactionHash}:${u.outpointIndex}` === pick) : founderCoins.sort((a, b) => b.minedAtHeight - a.minedAtHeight)[0];
    if (!funding) throw new Error('no coin at the founder key; run `fund` first');
    if (funding.outpointIndex !== 0) throw new Error(`the funding coin must be output 0 of its transaction, this one is output ${funding.outpointIndex}`);
    if (BigInt(funding.valueSatoshis) < reserve + 300n) throw new Error('funding coin too small for the reserve plus fee');
    const startTimestamp = BigInt(Math.floor(Date.now() / 60000) * 60);
    const stored = await engine.createInvitation({
      templateIdentifier, actionIdentifier: 'create', intent: startIntent('create'),
      variables: [
        { variableIdentifier: 'fundingSatoshis', value: BigInt(funding.valueSatoshis) },
        { variableIdentifier: 'category', value: funding.outpointTransactionHash },
        { variableIdentifier: 'tableBytes', value: tableBytes.toString('hex') },
        { variableIdentifier: 'reserveSatoshis', value: reserve },
        { variableIdentifier: 'startTimestamp', value: startTimestamp },
      ],
      inputs: [{ inputIdentifier: 'fundingInput', transactionIndex: 0, roleIdentifier: 'founder', outpointTransactionHash: hexToBin(funding.outpointTransactionHash), outpointIndex: 0, valueSatoshis: BigInt(funding.valueSatoshis) }],
    });
    const id = stored.invitation.invitationIdentifier;
    await engine.appendInvitation(id, { templateIdentifier, actionIdentifier: 'create', outputs: [{ outputIdentifier: 'headOutput', transactionIndex: 0 }] });
    // A remainder under 1,000 sats is left as the fee: the engine's estimate undershoots token outputs and it would
    // otherwise emit a dust change output.
    if (BigInt(funding.valueSatoshis) - reserve >= 1000n) await engine.addChangeToInvitation(id);
    for (const i of await engine.listOwnInputIndexes(id)) await engine.signInvitation(id, i);
    const missing = await engine.listMissingRequirements(id);
    if (missing.inputsMissingSignatures.length || Object.keys(missing.templateRequirements).length) throw new Error('still missing: ' + JSON.stringify(missing));
    const built = await engine.buildInvitationTransactionFromMergedCommit(id);
    const tx = show('genesis transaction', built.serializedTransaction);
    const commitment = binToHex(tx.outputs[0].token.nft.commitment);
    console.log(`  head commitment ${commitment} (timestamp ${startTimestamp}, counter 0, price 0, k 0, table ${commitment.slice(34)})`);
    console.log(`  category ${binToHex(tx.outputs[0].token.category)} = funding txid ${funding.outpointTransactionHash}: ${binToHex(tx.outputs[0].token.category) === funding.outpointTransactionHash ? 'ok' : 'MISMATCH'}`);
    if (!BROADCAST) { console.log('dry run; add --broadcast to send'); await engine.archiveInvitation(id); await quit(0); }
    const res = await engine.executeAction(id, { broadcastTransaction: true });
    console.log(`broadcast ${res.builtTransaction.transactionHash}  ← a new oracle, category ${funding.outpointTransactionHash}`);
    await quit(0);
  }
  console.error('usage: genesis-live.mjs release | fund <satoshis> | create <reserve> [--manifest …] [--funding txid:0] [--broadcast] | variables <reserve> --funding txid:0');
  await quit(2);
} catch (e) { console.error(`error: ${e.constructor?.name ?? ''} ${e.message}`); await quit(1); }
