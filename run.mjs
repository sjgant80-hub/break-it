#!/usr/bin/env node
// run.mjs — one command stands it up.
//
//   node run.mjs                 one node on http://127.0.0.1:8787, plus a legitimate client sending real traffic
//   node run.mjs --mesh 3        three nodes (8787, 8788, 8789), each pinned to the others: attack one, watch the
//                                others become immune to it without ever seeing it
//   node run.mjs --quiet         no client traffic (the ledger only grows when you send valid packets yourself)
//
// Keys are made on first run: secrets/ holds the private keys (git-ignored, never served); config/pubkeys.json and
// config/nodes.json are public. Each node keeps its own ledger, attack journal and loot under data/node-<n>/.
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startNode } from './src/server.mjs';
import { loadOrCreate, rawPublic } from './src/keys.mjs';
import { makeClient, nextOp, send } from './src/client.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : d; };
const MESH = Math.max(1, Math.min(9, Number(arg('--mesh', '1')) || 1));
const BASE = Number(arg('--port', '8787')) || 8787;
const QUIET = process.argv.includes('--quiet');
const hex = (u8) => Buffer.from(u8).toString('hex');

const secrets = join(ROOT, 'secrets'), config = join(ROOT, 'config');
mkdirSync(config, { recursive: true });
const sender = loadOrCreate(secrets, 'sender-1');
const pubkeys = { 1: hex(rawPublic(sender)) };
writeFileSync(join(config, 'pubkeys.json'), JSON.stringify(pubkeys, null, 2) + '\n');
const nodeKeys = Array.from({ length: MESH }, (_, i) => loadOrCreate(secrets, 'node-' + (i + 1)));
const nodes = nodeKeys.map((k, i) => ({ n: i + 1, url: 'http://127.0.0.1:' + (BASE + i), key: hex(rawPublic(k)) }));
writeFileSync(join(config, 'nodes.json'), JSON.stringify(nodes, null, 2) + '\n');

const started = [];
for (const [i, k] of nodeKeys.entries()) {
  const data = join(ROOT, 'data', 'node-' + (i + 1));
  started.push(await startNode({
    port: BASE + i, ledgerPath: join(data, 'ledger.jsonl'), journalPath: join(data, 'journal.jsonl'), lootPath: join(data, 'loot.jsonl'),
    pubkeys, nodeKey: k, peers: nodes.filter((p) => p.n !== i + 1).map((p) => ({ url: p.url, key: p.key })),
    log: (m) => console.log('[node ' + (i + 1) + '] ' + m),
  }));
}

console.log('\nBREAK IT — ' + MESH + ' node' + (MESH > 1 ? 's' : '') + ' up. Reach the app with anything malicious and you win.');
for (const s of started) console.log('  ' + s.url + '   GET /referee /immune /loot /journal /state /pubkeys');
console.log('  captured traffic → data/captured.hex     attack kit → attack-kit/     log what you find → FINDINGS.md\n');

if (!QUIET) {
  // the legitimate client: sends to node 1, resuming from the ledger's counter so restarts stay in sequence
  const health = await (await fetch(started[0].url + '/health')).json();
  const client = makeClient({ privateKey: sender, sender: 1, startCounter: BigInt(health.ledger) + 1n, capturePath: join(ROOT, 'data', 'captured.hex') });
  let i = health.ledger;
  setInterval(async () => {
    const p = client.next(nextOp(i++));
    for (const s of started) { try { await send(s.url, p); } catch { /* a node that is down misses it */ } }
  }, 2000);
}

process.on('SIGINT', async () => { for (const s of started) await s.close(); process.exit(0); });
