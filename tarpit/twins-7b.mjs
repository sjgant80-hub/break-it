#!/usr/bin/env node
// tarpit/twins-7b.mjs — p-7b, measured after its seal (tarpit/claims-7b.json): the twin phase of tarpit/run.mjs alone.
// A tarpit node at its shipped settings and a twin with it off, each in its own process (tarpit/node.mjs); the same
// sequence of the attack kit's forgeries from 127.0.0.2 to both (500 refusals, then 3 more), paying the rebound's work
// with its own solve() in a worker (tarpit/solver.mjs). Then the libraries and the journals, compared.
//   node tarpit/twins-7b.mjs           → receipts/tarpit-7b.json
//   node tarpit/twins-7b.mjs --check   → re-run; refuse unless the verdict and every fact is the receipt's
// It refuses to run if tarpit/claims-7b.json differs from the commit that sealed it.
import { fork, execFileSync } from 'node:child_process';
import { Worker } from 'node:worker_threads';
import http from 'node:http';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { message, signRaw } from '../attack-kit/lib.mjs';
import { keyFromSeed } from '../src/keys.mjs';
import { OPS } from '../src/wire.mjs';
import { loadJournal } from '../src/journal.mjs';
import { TARPIT } from '../src/tarpit.mjs';

const ROOT = new URL('../', import.meta.url);
const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
const sha = (s) => createHash('sha256').update(s).digest('hex');
const path = 'tarpit/claims-7b.json', text = readFileSync(new URL(path, ROOT), 'utf8');
const commit = git('log', '-1', '--format=%H', '--', path).trim();
if (!commit || git('show', commit + ':' + path) !== text) { console.log(path + ' differs from the commit that sealed it — refusing to measure'); process.exit(1); }

const AKEY = keyFromSeed(new Uint8Array(32).fill(0xa7));   // the same fixed, unpinned key as tarpit/run.mjs
const forgery = (i) => signRaw(message({ sender: 1, counter: BigInt(i), op: OPS.SET, key: 'name', value: 'forged', delta: 1 }), AKEY);
const solver = new Worker(new URL('./solver.mjs', import.meta.url));
let ids = 0; const waiting = new Map();
solver.on('message', ({ id, nonce }) => { waiting.get(id)(nonce); waiting.delete(id); });
const pay = (challenge, bits) => new Promise((ok) => { const id = ids++; waiting.set(id, ok); solver.postMessage({ id, challenge, bits }); });
const request = (url, bytes, work) => new Promise((resolve, reject) => {
  const headers = { 'content-type': 'application/octet-stream', 'content-length': bytes.length };
  if (work !== null) headers['x-rebound'] = work;
  const req = http.request(new URL('/packet', url), { method: 'POST', agent: false, localAddress: '127.0.0.2', headers }, (r) => { const p = []; r.on('data', (c) => p.push(c)); r.on('end', () => resolve({ status: r.statusCode, raw: Buffer.concat(p) })); });
  req.on('error', reject); req.end(Buffer.from(bytes));
});
async function send(url, bytes) {
  let work = null;
  for (let t = 0; t < 100; t++) {
    const r = await request(url, bytes, work);
    if (r.status === 402) { const b = JSON.parse(r.raw.toString('utf8')); work = await pay(b.challenge, b.bits); continue; }
    if (r.status === 429) { await new Promise((ok) => setTimeout(ok, 20)); continue; }
    return r;
  }
  throw new Error('asked to pay or rate-limited 100 times in a row');
}
async function startNode(tarpit) {
  const dir = mkdtempSync(join(tmpdir(), 'tarpit7b-'));
  const paths = { ledgerPath: join(dir, 'ledger.jsonl'), journalPath: join(dir, 'journal.jsonl'), lootPath: join(dir, 'loot.jsonl') };
  const child = fork(new URL('./node.mjs', import.meta.url), [JSON.stringify({ ...paths, tarpit })], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  const ask = (m, key) => new Promise((ok) => { const f = (x) => { if (x && x[key] !== undefined) { child.off('message', f); ok(x[key]); } }; child.on('message', f); if (m) child.send(m); });
  const url = await ask(null, 'url');
  return { url, paths, report: () => ask('report', 'report'), close: async () => { await ask('close', 'closed'); rmSync(dir, { recursive: true, force: true }); } };
}

const t0 = Date.now(), on = await startNode(true), off = await startNode(null), N = TARPIT.CONFIRM + 3;
const heldOn = [];
for (let i = 1; i <= N; i++) { const r = await send(on.url, forgery(i)); if (r.raw[0] === 0x20) heldOn.push(i); }
for (let i = 1; i <= N; i++) await send(off.url, forgery(i));
const [libOn, libOff] = [(await on.report()).library, (await off.report()).library];
// read while the nodes still hold their folders (a record is appended to its file before the node answers)
const [jOn, jOff] = [loadJournal(on.paths.journalPath), loadJournal(off.paths.journalPath)];
await on.close(); await off.close(); await solver.terminate();
const LEFT_OUT = ['at', 'hash', 'prev'];
const content = (r) => JSON.stringify(Object.fromEntries(Object.entries(r).filter(([k]) => !LEFT_OUT.includes(k))));
const recsOn = jOn.ok ? jOn.records : [], recsOff = jOff.ok ? jOff.records : [];
const firstDiff = recsOn.findIndex((r, k) => !recsOff[k] || content(r) !== content(recsOff[k]));
const facts = {
  sent: N, heldOn: heldOn.length, heldFrom: heldOn[0] || null,
  libraryEqual: JSON.stringify(libOn) === JSON.stringify(libOff), exact: Object.keys(libOn.exact).length, shapes: libOn.shapes.length,
  journals: { on: recsOn.length, off: recsOff.length, onChainVerifies: jOn.ok === true, offChainVerifies: jOff.ok === true, equalRecordForRecord: recsOn.length === recsOff.length && firstDiff < 0, firstDiff, leftOut: LEFT_OUT },
};
const held = facts.libraryEqual && facts.journals.onChainVerifies && facts.journals.offChainVerifies && facts.journals.equalRecordForRecord && recsOn.length > 0;
const claim = JSON.parse(text).claims[0];
const verdict = { id: claim.id, role: claim.role, claim: claim.claim, held,
  measured: 'antibody libraries equal: ' + facts.libraryEqual + ' (' + facts.exact + ' exact, ' + facts.shapes + ' shapes); journals ' + facts.journals.on + ' and ' + facts.journals.off + ' records, equal on every field but time, hash and prev: ' + facts.journals.equalRecordForRecord
    + '; each chain verifies: ' + facts.journals.onChainVerifies + ', ' + facts.journals.offChainVerifies + '; the tarpit node held ' + facts.heldOn + ' (from forgery ' + facts.heldFrom + ')' };
const receipt = { kind: 'break-it.tarpit.receipt-7b', v: 1, sealed: { path, commit, claimsSha256: sha(text) }, facts, verdicts: [verdict], held: held ? 1 : 0, failed: held ? 0 : 1 };
const out = JSON.stringify(receipt, null, 1) + '\n';
if (process.argv.includes('--check')) {
  const was = readFileSync(new URL('receipts/tarpit-7b.json', ROOT), 'utf8');
  console.log(was === out ? 'TARPIT 7b REPRODUCED · ' + (held ? 'held' : 'failed') : 'TARPIT 7b DRIFT · the re-run differs from the receipt');
  process.exit(was === out ? 0 : 1);
}
writeFileSync(new URL('receipts/tarpit-7b.json', ROOT), out);
console.log((held ? 'HELD   ' : 'FAILED ') + verdict.id + ' · ' + verdict.measured);
console.log('wrote receipts/tarpit-7b.json · ' + Math.round((Date.now() - t0) / 1000) + ' s');
