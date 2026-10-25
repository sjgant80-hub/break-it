// pilot/lib.mjs — what pilot/measure.mjs and pilot/check.mjs share: the pilot's keys (derived from a public seed, so
// anyone can re-derive its ledger; never use them for anything else), the node in its own metered process, a
// keep-alive sender, and the offline derivation of the ledger and the books from the feed alone.
import http from 'node:http';
import { fork } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { keyFromSeed, rawPublic } from '../src/keys.mjs';
import { makeClient } from '../src/client.mjs';
import { entryFor, GENESIS } from '../src/chain.mjs';
import { OPS } from '../src/wire.mjs';
import { recordsFrom, books } from '../src/feed.mjs';

export const ROOT = fileURLToPath(new URL('..', import.meta.url));
export const sha = (s) => createHash('sha256').update(s).digest('hex');
export const hex = (u8) => Buffer.from(u8).toString('hex');
const seedOf = (name) => createHash('sha256').update('BREAK-IT/pilot/v1|' + name).digest();
export const SENDER = keyFromSeed(seedOf('sender-1'));
export const PUBKEYS = { 1: hex(rawPublic(SENDER)) };
const NODE_SEED = hex(seedOf('node'));

/** The feed, checked against its recorded hash before a byte of it is read as records. */
export function loadFeed() {
  const src = JSON.parse(readFileSync(new URL('../feeds/SOURCES.json', import.meta.url), 'utf8')).files[0];
  const text = readFileSync(new URL('../' + src.path, import.meta.url), 'utf8');
  const got = sha(text);
  if (got !== src.sha256) throw new Error('the feed is not the one SOURCES.json names (' + got + ')');
  const r = recordsFrom(text);
  if (!r.ok) throw new Error('the feed is refused at line ' + r.line + ': ' + r.why);
  return { sha256: got, records: r.records, accounts: r.accounts };
}

/** Fork the node (or the canary) with the egress meter loaded first. → { child, first message } */
export function startMetered(dir, { canary = false } = {}) {
  const trap = pathToFileURL(fileURLToPath(new URL('./egress-trap.mjs', import.meta.url))).href;
  const child = fork(fileURLToPath(new URL('./node.mjs', import.meta.url)), canary ? ['--canary'] : [], {
    execArgv: ['--import', trap], stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
    env: { ...process.env, PILOT: JSON.stringify({ dir, pubkeys: PUBKEYS, nodeSeed: NODE_SEED }) },
  });
  return new Promise((resolve, reject) => {
    child.once('message', (m) => resolve({ child, first: m }));
    child.once('exit', (code) => reject(new Error('the metered process exited (' + code + ') before it spoke')));
  });
}

/** Ask the node to close; → its egress meter, stats and antibody counts. */
export const stopMetered = (child) => new Promise((resolve) => { child.once('message', resolve); child.send({ bye: true }); });

const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
/** POST raw bytes to /packet on one kept-alive socket. → { status, body } */
export function post(url, bytes) {
  return new Promise((resolve, reject) => {
    const req = http.request(new URL('/packet', url), { method: 'POST', agent, headers: { 'content-type': 'application/octet-stream', 'content-length': bytes.length } }, (res) => {
      const parts = [];
      res.on('data', (c) => parts.push(c));
      res.on('end', () => { let body = null; try { body = JSON.parse(Buffer.concat(parts).toString('utf8')); } catch { body = null; } resolve({ status: res.statusCode, body }); });
    });
    req.on('error', reject);
    req.end(Buffer.from(bytes));
  });
}
export async function getJson(url, path) { const r = await fetch(new URL(path, url)); return r.json(); }
export const closeAgent = () => agent.destroy();

/** The genuine sender: the same deterministic packets on the wire and offline. */
export const genuine = () => makeClient({ privateKey: SENDER });
export const packetFor = (client, rec) => client.next({ op: OPS.REC, account: rec.account, period: rec.period, amount: rec.amount });

/** The ledger head a faithful node must end with, from the feed alone: sign each record, chain it. No node. */
export function deriveHead(records) {
  const c = genuine();
  let head = GENESIS;
  for (let i = 0; i < records.length; i++) head = entryFor(head, i, hex(packetFor(c, records[i])), sha).hash;
  return head;
}

/** One hash over a set of books, key-sorted, so two runs (or a node and the feed) compare in one line. */
export const booksHash = (b) => sha(JSON.stringify(Object.keys(b).sort().map((k) => [k, b[k]])));
export const booksOf = books;
