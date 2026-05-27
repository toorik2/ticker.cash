#!/usr/bin/env tsx
/**
 * ticker-node — unified daemon wrapping the notary + publisher
 *
 * Operationally bundles both roles into one systemd unit. Conceptually
 * keeps them separate: notary holds a federation Schnorr key + signs
 * (price, ts, cycleSeq); publisher relays via Gateway + Oracle.update.
 *
 * Usage:
 *   ticker-node --notary --slot 0                       # notary only
 *   ticker-node --publisher --slot 0                    # publisher only
 *   ticker-node --notary --publisher --slot 0           # both, same slot
 *   ticker-node --notary --notary-slot 0 \
 *               --publisher --publisher-slot 5          # both, different slots
 *
 * Optional flags:
 *   --notary-port 8081       (default per slot: 8081 + slot)
 *   --notary-url URL         (publisher: notary endpoints; repeatable;
 *                             default: http://127.0.0.1:8081, :8082, :8083)
 *
 * Lifecycle: SIGINT / SIGTERM propagate to both child processes. If
 * either child exits non-zero, the other gets SIGTERM and ticker-node
 * exits with the same code.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);

function flagValue(...names: string[]): string | undefined {
  for (const n of names) {
    const i = argv.indexOf(n);
    if (i >= 0 && argv[i + 1] !== undefined) return argv[i + 1];
  }
  return undefined;
}
function flagPresent(name: string): boolean {
  return argv.includes(name);
}
function flagAll(name: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === name && argv[i + 1] !== undefined) out.push(argv[i + 1]!);
  }
  return out;
}

const wantNotary = flagPresent('--notary');
const wantPublisher = flagPresent('--publisher');

if (!wantNotary && !wantPublisher) {
  console.error('ticker-node: must specify --notary and/or --publisher');
  console.error('  examples:');
  console.error('    ticker-node --notary --slot 0');
  console.error('    ticker-node --publisher --slot 0');
  console.error('    ticker-node --notary --publisher --slot 0');
  process.exit(2);
}

const sharedSlot = flagValue('--slot');
const children: ChildProcess[] = [];
let shuttingDown = false;

function spawnChild(label: string, scriptRel: string, scriptArgs: string[]): ChildProcess {
  const tsx = join(__dirname, '..', 'node_modules', '.bin', 'tsx');
  const script = join(__dirname, scriptRel);
  console.log(`[ticker-node] starting ${label}: ${scriptRel} ${scriptArgs.join(' ')}`);
  const c = spawn(tsx, [script, ...scriptArgs], { stdio: 'inherit', env: process.env });
  c.on('exit', (code, signal) => {
    if (shuttingDown) return;
    console.error(`[ticker-node] ${label} exited ${code ?? signal}; shutting down`);
    shutdown(code ?? 1);
  });
  return c;
}

if (wantNotary) {
  const slot = flagValue('--notary-slot') ?? sharedSlot ?? '0';
  const port = flagValue('--notary-port');
  const args = ['--slot', slot];
  if (port) args.push('--port', port);
  children.push(spawnChild('notary', 'notary.ts', args));
}

if (wantPublisher) {
  const slot = flagValue('--publisher-slot') ?? sharedSlot ?? '0';
  const args = ['--slot', slot];
  const urls = flagAll('--notary-url');
  for (const u of urls) args.push('--notary-url', u);
  if (flagPresent('--once')) args.push('--once');
  children.push(spawnChild('publisher', 'publisher.ts', args));
}

function shutdown(code: number): void {
  if (shuttingDown) return;
  shuttingDown = true;
  for (const c of children) {
    try { c.kill('SIGTERM'); } catch {}
  }
  // Give kids 5s to clean up, then hard-exit.
  setTimeout(() => process.exit(code), 5000).unref();
}

process.on('SIGINT', () => { console.log('[ticker-node] SIGINT'); shutdown(130); });
process.on('SIGTERM', () => { console.log('[ticker-node] SIGTERM'); shutdown(143); });
