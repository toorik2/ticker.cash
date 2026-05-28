#!/usr/bin/env tsx
/**
 * ticker-node — unified single-process entry point.
 *
 * Runs notary + publisher (one of each, or both) IN THIS process. Replaces
 * the previous child-spawning model: one Node, one PID, one log stream,
 * one systemd unit per operator.
 *
 * Credentials are loaded by each role's resolveIdentity helper from the
 * standard .ticker/ paths (notary.key + manifest.json on the new install;
 * seed.hex + deploy-state.json on the legacy layout). All flags below are
 * optional in the new layout — slot is derived from the operator's key.
 *
 * Usage:
 *   ticker-node --notary                          # notary only, slot from key
 *   ticker-node --publisher                       # publisher only, slot from key
 *   ticker-node --notary --publisher              # both roles, one process
 *
 *   ticker-node --notary --publisher --slot 0     # legacy: explicit slot for both
 *   ticker-node --notary --notary-slot 0 \
 *               --publisher --publisher-slot 5    # legacy: different slots per role
 *
 * Optional flags:
 *   --notary-port 8081       (default per slot: 8081 + slot)
 *   --notary-url URL         (publisher: notary endpoints; repeatable;
 *                             default: http://127.0.0.1:8081..8087)
 *
 * Lifecycle: SIGINT / SIGTERM trigger a clean exit. Either role throwing
 * during start-up or runtime takes the process down — systemd handles
 * restart per Restart=on-failure.
 */
import { runNotary } from './notary.js';
import { runPublisher } from './publisher.js';

const argv = process.argv.slice(2);

const flagPresent = (name: string): boolean => argv.includes(name);
const flagValue = (...names: string[]): string | undefined => {
  for (const n of names) {
    const i = argv.indexOf(n);
    if (i >= 0 && argv[i + 1] !== undefined) return argv[i + 1];
  }
  return undefined;
};
const flagAll = (name: string): string[] => {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === name && argv[i + 1] !== undefined) out.push(argv[i + 1]!);
  }
  return out;
};

const wantNotary = flagPresent('--notary');
const wantPublisher = flagPresent('--publisher');

if (!wantNotary && !wantPublisher) {
  console.error('ticker-node: must specify --notary and/or --publisher');
  console.error('  examples:');
  console.error('    ticker-node --notary');
  console.error('    ticker-node --publisher');
  console.error('    ticker-node --notary --publisher');
  process.exit(2);
}

// Per-role argv assembly. Both runners parse their own flags; we pass only
// what's relevant to each. --slot is forwarded only when the operator
// supplied an explicit override (the new layout derives it from the key).
const sharedSlot = flagValue('--slot');
const notaryPort = flagValue('--notary-port');
const notaryUrls = flagAll('--notary-url');

const notaryArgv: string[] = [];
const notarySlot = flagValue('--notary-slot') ?? sharedSlot;
if (notarySlot !== undefined) notaryArgv.push('--slot', notarySlot);
if (notaryPort !== undefined) notaryArgv.push('--port', notaryPort);

const publisherArgv: string[] = [];
const publisherSlot = flagValue('--publisher-slot') ?? sharedSlot;
if (publisherSlot !== undefined) publisherArgv.push('--slot', publisherSlot);
for (const u of notaryUrls) publisherArgv.push('--notary-url', u);
if (flagPresent('--once')) publisherArgv.push('--once');

const tasks: Array<{ label: string; promise: Promise<void> }> = [];

if (wantNotary) {
  console.log(`[ticker-node] starting notary: ${notaryArgv.join(' ') || '(no flags)'}`);
  tasks.push({ label: 'notary', promise: runNotary(notaryArgv) });
}
if (wantPublisher) {
  console.log(`[ticker-node] starting publisher: ${publisherArgv.join(' ') || '(no flags)'}`);
  tasks.push({ label: 'publisher', promise: runPublisher(publisherArgv) });
}

// If either role exits (resolves or rejects), bring the whole process down.
// On rejection, log the error; on resolve, log a notice — both are unusual
// (these are meant to be long-running) and warrant systemd noticing.
let shuttingDown = false;
const shutdown = (code: number): void => {
  if (shuttingDown) return;
  shuttingDown = true;
  // Give in-flight HTTP responses + tx broadcasts a brief window, then exit.
  setTimeout(() => process.exit(code), 1500).unref();
};

for (const { label, promise } of tasks) {
  promise
    .then(() => {
      if (shuttingDown) return;
      console.error(`[ticker-node] ${label} resolved unexpectedly; shutting down`);
      shutdown(1);
    })
    .catch((err) => {
      if (shuttingDown) return;
      console.error(`[ticker-node] ${label} failed:`, err instanceof Error ? err.message : String(err));
      shutdown(1);
    });
}

process.on('SIGINT',  () => { console.log('[ticker-node] SIGINT');  shutdown(130); });
process.on('SIGTERM', () => { console.log('[ticker-node] SIGTERM'); shutdown(143); });
