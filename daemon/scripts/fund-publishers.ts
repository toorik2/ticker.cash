#!/usr/bin/env tsx
// Send a chunk of BCH to each of the 13 publisher addresses from master.
import { ElectrumClient } from '@electrum-cash/network';
import { ElectrumTcpSocket } from '@electrum-cash/tcp-socket';
import { ElectrumNetworkProvider, Network, SignatureTemplate, TransactionBuilder } from 'cashscript';
import { deriveWallets } from '../src/keys.js';
import { loadSeed } from '../src/master-seed.js';

const host = process.env.TICKER_ELECTRUM_HOST ?? '127.0.0.1';
const port = Number(process.env.TICKER_ELECTRUM_PORT ?? 50001);
const sock = new ElectrumTcpSocket(host, port, false, 5000);
const client = new ElectrumClient('fund-pubs', '1.4.1', sock);
const provider = new ElectrumNetworkProvider(Network.CHIPNET, { electrum: client });

const PER_PUB_SATS = 200_000n;  // 200k sats each — covers ~100 attest tx fees
const broadcast = process.argv.includes('--broadcast');

const seed = loadSeed();
const wallets = deriveWallets(seed);
const masterSig = new SignatureTemplate(wallets.master.privateKey);

const utxos = (await provider.getUtxos(wallets.master.address)).filter(u => !u.token);
const bal = utxos.reduce((s, u) => s + u.satoshis, 0n);
const total = PER_PUB_SATS * 13n + 5_000n;
console.log(`master: ${bal} sats, sending ${total} (${PER_PUB_SATS} × 13 + fee)`);
if (bal < total) throw new Error(`master too low`);

const tb = new TransactionBuilder({ provider });
for (const u of utxos) tb.addInput(u, masterSig.unlockP2PKH());
for (let i = 0; i < 13; i++) {
  tb.addOutput({ to: wallets.publishers[i]!.address, amount: PER_PUB_SATS });
}
const change = bal - PER_PUB_SATS * 13n - 5_000n;
if (change >= 546n) tb.addOutput({ to: wallets.master.address, amount: change });

if (!broadcast) { console.log('plan only'); process.exit(0); }
const tx = await tb.send();
console.log(`✓ funded: ${tx.txid}`);
console.log(`  https://chipnet.imaginary.cash/tx/${tx.txid}`);
process.exit(0);
