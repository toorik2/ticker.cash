import { decodePrivateKeyWif, encodeCashAddress, hash160, secp256k1, CashAddressNetworkPrefix, CashAddressType } from '@bitauth/libauth';
import { ElectrumClient } from '@electrum-cash/network';
import { ElectrumTcpSocket } from '@electrum-cash/tcp-socket';
import { ElectrumNetworkProvider, Network, SignatureTemplate, TransactionBuilder, type Utxo } from 'cashscript';
import fs from 'node:fs';
import path from 'node:path';
import { loadSeed } from '../src/seed.js';
import { deriveWallets } from '../src/keys.js';

const KEY_DIR = '/tmp/recovered-keys/projects/cashlink/publisher-v6/keys';
const broadcast = process.argv.includes('--broadcast');

const sock = new ElectrumTcpSocket('159.195.80.214', 50001, false, 5000);
const client = new ElectrumClient('sweep-v6', '1.4.1', sock);
const provider = new ElectrumNetworkProvider(Network.CHIPNET, { electrum: client });

const seed = loadSeed();
const wallets = deriveWallets(seed);
const masterAddress = wallets.master.address;
console.log('sweep destination (new master):', masterAddress);

const wifFiles = fs.readdirSync(KEY_DIR).filter(f => /^funding-\d+\.wif$/.test(f));
console.log('wifs:', wifFiles.length);

interface SignedUtxo { utxo: Utxo; sig: SignatureTemplate; wifAddr: string; }
const all: SignedUtxo[] = [];
let total = 0n;

for (const f of wifFiles) {
  const wif = fs.readFileSync(path.join(KEY_DIR, f), 'utf8').trim();
  const dec = decodePrivateKeyWif(wif);
  if (typeof dec === 'string') { console.error(f, dec); continue; }
  const pub = secp256k1.derivePublicKeyCompressed(dec.privateKey);
  if (typeof pub === 'string') { console.error(f, pub); continue; }
  const addr = encodeCashAddress({ prefix: CashAddressNetworkPrefix.testnet, type: CashAddressType.p2pkh, payload: hash160(pub) }).address;
  const us = await provider.getUtxos(addr);
  const nt = us.filter(u => !u.token);
  const bal = nt.reduce((s, u) => s + u.satoshis, 0n);
  if (bal > 0n) {
    const sig = new SignatureTemplate(dec.privateKey);
    for (const u of nt) all.push({ utxo: u, sig, wifAddr: addr });
    total += bal;
    console.log(' ', f, addr, bal.toString(), 'sats');
  }
}
console.log('TOTAL:', total.toString(), 'sats =', Number(total) / 1e8, 'BCH');

if (all.length === 0) { console.log('nothing to sweep'); process.exit(0); }

// Build a single tx: all inputs → 1 output (master) minus fee
const FEE = BigInt(200 + 150 * all.length); // ~150B per input
const out = total - FEE;
console.log('outputs:', masterAddress, out.toString(), 'sats (fee', FEE.toString(), ')');

const tb = new TransactionBuilder({ provider });
for (const s of all) tb.addInput(s.utxo, s.sig.unlockP2PKH());
tb.addOutput({ to: masterAddress, amount: out });

if (!broadcast) {
  console.log('plan mode (no --broadcast)');
  process.exit(0);
}
const raw = tb.build();
console.log('tx size:', raw.length / 2, 'bytes');
const txid = await provider.sendRawTransaction(raw);
console.log('✓ swept:', txid);
console.log('  explorer: https://chipnet.imaginary.cash/tx/' + txid);
process.exit(0);
