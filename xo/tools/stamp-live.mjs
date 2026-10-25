#!/usr/bin/env node
// Pay at the oracle price from a headless XO engine, on chipnet, with the ticker-stamp template.
//
//   node tools/stamp-live.mjs address                       # print this wallet's receive address (fund it)
//   node tools/stamp-live.mjs pay <bchtest:…> <satoshis>    # dry run: build the transaction and show it
//   node tools/stamp-live.mjs pay <bchtest:…> <satoshis> --broadcast
//
// The wallet is a throwaway: its mnemonic lives in ~/.ticker-xo/mnemonic (created on first run, mode 0600)
// and its database in ~/.ticker-xo/db. The flow is the one the XO Web Dev Wallet performs: create the
// invitation with the Ticker input (found through Electrum, newest counter wins) and the variables, append
// the two template outputs (the engine derives value, lock and token from the variables), append a wallet
// coin as the funding input, add change, sign own inputs, execute.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Engine, fetchUnspentOutputsForLockingBytecode } from '@xo-cash/engine';
import { StorageType } from '@xo-cash/state';
import { p2pkhTemplate } from '@xo-cash/templates';
import { hexToBin, binToHex, cashAddressToLockingBytecode, lockingBytecodeToCashAddress, decodeTransaction, generateBip39Mnemonic } from '@bitauth/libauth';
import { ORACLE_CATEGORY, TICKER_LOCKING_BYTECODE } from '../templates/common.mjs';

const HOME = path.join(os.homedir(), '.ticker-xo');
fs.mkdirSync(path.join(HOME, 'db'), { recursive: true, mode: 0o700 });
const mnemonicPath = path.join(HOME, 'mnemonic');
if (!fs.existsSync(mnemonicPath)) fs.writeFileSync(mnemonicPath, generateBip39Mnemonic() + '\n', { mode: 0o600 });
const mnemonic = fs.readFileSync(mnemonicPath, 'utf8').trim();

const [cmd, arg1, arg2] = process.argv.slice(2);
const BROADCAST = process.argv.includes('--broadcast');
const stampJson = fs.readFileSync(new URL('../dist/ticker-stamp.json', import.meta.url), 'utf8');

const engine = await Engine.create(mnemonic, { network: 'chipnet', storageType: StorageType.INDEXEDDB, databasePath: path.join(HOME, 'db') + '/' });
const quit = async (code) => { await engine.stop(); process.exit(code); };
try {
  // A plain p2pkh wallet to hold the funds, set as the default policy so the engine can derive addresses.
  const { templateIdentifier: p2pkhId } = await engine.importTemplate(p2pkhTemplate);
  if (!(await engine.getDefaultPolicies()).address) {
    await engine.setDefaultPolicies({ address: { templateIdentifier: p2pkhId, ...p2pkhTemplate.defaults.address }, change: { templateIdentifier: p2pkhId, ...p2pkhTemplate.defaults.change }, receive: { templateIdentifier: p2pkhId, ...p2pkhTemplate.defaults.receive } });
  }
  const { templateIdentifier } = await engine.importTemplate(stampJson);

  if (cmd === 'address' || cmd === undefined) {
    const lock = await engine.generateLockingBytecodeFromDefaultPolicy('address');
    const addr = lockingBytecodeToCashAddress({ bytecode: hexToBin(lock), prefix: 'bchtest' });
    const coins = await engine.listSpendableUnspentOutputs();
    console.log(`receive address ${typeof addr === 'string' ? addr : addr.address}`);
    console.log(`spendable ${coins.reduce((a, u) => a + BigInt(u.valueSatoshis), 0n)} sats in ${coins.length} coins`);
    await quit(0);
  }
  if (cmd !== 'pay' || !arg1 || !arg2) { console.error('usage: stamp-live.mjs address | pay <address> <satoshis> [--broadcast]'); await quit(2); }
  const recipient = cashAddressToLockingBytecode(arg1); if (typeof recipient === 'string') throw new Error(recipient);
  const amount = BigInt(arg2);

  // The newest Ticker of the category: highest dataSequence (commitment bytes 8..12).
  const tickers = (await fetchUnspentOutputsForLockingBytecode(TICKER_LOCKING_BYTECODE, templateIdentifier))
    .filter(u => u.tokenCategory === ORACLE_CATEGORY && u.tokenNftCommitment?.length === 34);
  const seqOf = (u) => Buffer.from(u.tokenNftCommitment, 'hex').readUInt32LE(8);
  tickers.sort((a, b) => seqOf(b) - seqOf(a));
  const ticker = tickers[0]; if (!ticker) throw new Error('no live Ticker found');
  const c = Buffer.from(ticker.tokenNftCommitment, 'hex');
  console.log(`ticker ${ticker.outpointTransactionHash}:${ticker.outpointIndex} ${ticker.valueSatoshis} sats · counter ${seqOf(ticker)} · minute ${c.readUInt32LE(0)} · ${(c.readUInt32LE(12) / 100).toFixed(2)} USD/BCH · ${c[16]} rows`);

  const coins = (await engine.listSpendableUnspentOutputs()).filter(u => u.templateIdentifier === p2pkhId);   // unconfirmed coins are spendable on BCH
  const coin = coins.find(u => BigInt(u.valueSatoshis) >= amount + 1000n + 2000n);
  if (!coin) throw new Error(`no wallet coin covers ${amount} sats + toll + fee; fund the address first`);

  const stored = await engine.createInvitation({
    templateIdentifier, actionIdentifier: 'pay', roleIdentifier: 'payer',
    variables: [
      { variableIdentifier: 'tickerCommitment', value: ticker.tokenNftCommitment },
      { variableIdentifier: 'tickerSatoshis', value: BigInt(ticker.valueSatoshis) },
      { variableIdentifier: 'paymentSatoshis', value: amount },
      { variableIdentifier: 'recipientLockingScript', value: binToHex(recipient.bytecode) },
    ],
    inputs: [{
      inputIdentifier: 'tickerInput', transactionIndex: 0,
      outpointTransactionHash: hexToBin(ticker.outpointTransactionHash), outpointIndex: ticker.outpointIndex,
      valueSatoshis: BigInt(ticker.valueSatoshis),
      token: { category: hexToBin(ORACLE_CATEGORY), amount: 0n, nft: { capability: 'none', commitment: hexToBin(ticker.tokenNftCommitment) } },
      unlockingBytecode: new Uint8Array([0x00]),   // consume(): the unlocking script is a single OP_0
      sequenceNumber: 0xfffffffe,
    }],
  });
  const id = stored.invitation.invitationIdentifier;
  await engine.appendInvitation(id, { templateIdentifier, actionIdentifier: 'pay', outputs: [{ outputIdentifier: 'tickerOutput', transactionIndex: 0 }, { outputIdentifier: 'paymentOutput', transactionIndex: 1 }] });
  await engine.appendInvitation(id, { templateIdentifier, actionIdentifier: 'pay', inputs: [{ outpointTransactionHash: hexToBin(coin.outpointTransactionHash), outpointIndex: coin.outpointIndex, valueSatoshis: BigInt(coin.valueSatoshis), transactionIndex: 1 }] });
  await engine.addChangeToInvitation(id);
  for (const i of await engine.listOwnInputIndexes(id)) await engine.signInvitation(id, i);
  const missing = await engine.listMissingRequirements(id);
  if (missing.inputsMissingSignatures.length || Object.keys(missing.templateRequirements).length) throw new Error('still missing: ' + JSON.stringify(missing));

  const built = await engine.buildInvitationTransactionFromMergedCommit(id);
  const tx = decodeTransaction(hexToBin(built.serializedTransaction)); if (typeof tx === 'string') throw new Error(tx);
  console.log(`transaction ${built.serializedTransaction.length / 2} B, ${tx.inputs.length} inputs, ${tx.outputs.length} outputs`);
  tx.outputs.forEach((o, n) => console.log(`  out${n} ${o.valueSatoshis} sats${o.token ? ` · Ticker ${binToHex(o.token.nft.commitment)}` : ''}`));
  const fee = BigInt(ticker.valueSatoshis) + BigInt(coin.valueSatoshis) - tx.outputs.reduce((a, o) => a + o.valueSatoshis, 0n);
  console.log(`  fee ${fee} sats`);
  if (!BROADCAST) { console.log('dry run; add --broadcast to send'); await quit(0); }
  const res = await engine.executeAction(id, { broadcastTransaction: true });
  console.log(`broadcast ${res.builtTransaction.transactionHash}`);
  await quit(0);
} catch (e) { console.error(`error: ${e.constructor?.name ?? ''} ${e.message}`); await quit(1); }
