// tarpit-node.test.mjs — the tarpit wired into a real node, on small settings so it runs in a second: a confirmed
// source's forged packet is held and its body is the spaces then the same refusal; a genuine packet from the same
// address is admitted at once; past the cap the refusal goes out at once; a source that gives up ends its hold; off
// unless switched on; close() ends every hold. (The sealed measurement runs the shipped settings: tarpit/.)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startNode } from '../src/server.mjs';
import { packet, S1, ATTACKER, pubHex } from './helpers.mjs';

const T = { CONFIRM: 3, HOLD_MS: 300, DRIP_MS: 100, CAP: 2 };
async function node(tarpit) {
  const dir = mkdtempSync(join(tmpdir(), 'tarpit-'));
  const n = await startNode({ port: 0, ledgerPath: join(dir, 'l.jsonl'), journalPath: join(dir, 'j.jsonl'), lootPath: join(dir, 'x.jsonl'), pubkeys: { 1: pubHex(S1) }, tarpit });
  return Object.assign(n, { done: async () => { await n.close(); rmSync(dir, { recursive: true, force: true }); } });   // not a spread: holding is a getter
}
/** POST on a fresh connection; the raw body and how long the answer took; abortAfter ends the request early */
const post = (url, bytes, abortAfter) => new Promise((resolve) => {
  const t0 = Date.now();
  const req = http.request(new URL('/packet', url), { method: 'POST', agent: false, headers: { 'content-type': 'application/octet-stream', 'content-length': bytes.length } }, (res) => {
    const parts = [];
    res.on('data', (c) => parts.push(c));
    res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, raw: Buffer.concat(parts).toString('latin1'), ms: Date.now() - t0 }));
    res.on('error', () => resolve({ aborted: true, ms: Date.now() - t0 }));
  });
  req.on('error', () => resolve({ aborted: true, ms: Date.now() - t0 }));
  if (abortAfter) setTimeout(() => req.destroy(), abortAfter);
  req.end(Buffer.from(bytes));
});
const forged = (c) => packet({ counter: BigInt(c), signer: ATTACKER });
const genuine = (c) => packet({ counter: BigInt(c), value: 'v' + c });
const wait = (ms) => new Promise((ok) => setTimeout(ok, ms));

test('a confirmed source’s forgery is held, then refused exactly; a genuine packet from the same address goes through at once', async () => {
  const n = await node(T);
  try {
    for (let i = 1; i <= T.CONFIRM; i++) { const r = await post(n.url, forged(i)); assert.equal(r.status, 403); assert.ok(r.ms < T.HOLD_MS, 'not yet confirmed: answered at once'); assert.equal(r.raw[0], '{'); }
    const held = await post(n.url, forged(9));
    assert.equal(held.status, 403);
    assert.ok(held.ms >= T.HOLD_MS - 20, 'held for the hold: ' + held.ms + ' ms');
    assert.equal(held.raw.slice(0, 3), '   ', 'three ticks of one space');
    assert.ok(/^ {3}\{/.test(held.raw), 'spaces only, then the refusal');
    const body = JSON.parse(held.raw);
    assert.equal(body.stage, 'signature'); assert.equal(body.dropped, true);
    assert.equal(Number(held.headers['content-length']), Buffer.byteLength(held.raw, 'latin1'), 'the length counts the spaces');
    assert.deepEqual(Object.keys(held.headers).filter((h) => !['date', 'connection', 'keep-alive'].includes(h)).sort(), ['cache-control', 'content-length', 'content-type', 'x-content-type-options']);
    const ok = await post(n.url, genuine(1));
    assert.equal(ok.status, 200); assert.equal(JSON.parse(ok.raw).accepted, true);
    assert.ok(ok.ms < T.HOLD_MS, 'a genuine packet is never held: ' + ok.ms + ' ms');
    assert.equal(n.stats.tarpitHeld, 1); assert.equal(n.stats.tarpitFinished, 1); assert.equal(n.stats.tarpitDripped, 3); assert.equal(n.holding, 0);
  } finally { await n.done(); }
});

test('past the cap the refusal goes out at once; a source that gives up ends its hold and nothing is kept for it', async () => {
  const n = await node(T);
  try {
    for (let i = 1; i <= T.CONFIRM; i++) await post(n.url, forged(i));
    const three = [post(n.url, forged(20)), post(n.url, forged(21)), wait(50).then(() => post(n.url, forged(22)))];
    await wait(120);
    assert.equal(n.holding, T.CAP, 'at most the cap held');
    const rs = await Promise.all(three);
    assert.equal(rs.filter((r) => r.ms >= T.HOLD_MS - 20).length, T.CAP);
    assert.equal(rs.filter((r) => r.ms < T.HOLD_MS - 20).length, 1);
    assert.equal(n.stats.tarpitFull, 1);
    const gone = await post(n.url, forged(30), 150);
    assert.equal(gone.aborted, true, 'it gave up before the refusal came');
    await wait(50);
    assert.equal(n.holding, 0); assert.equal(n.stats.tarpitAbandoned, 1);
  } finally { await n.done(); }
});

test('off unless switched on: the same confirmed forgery is answered at once', async () => {
  const n = await node(undefined);
  try {
    for (let i = 1; i <= T.CONFIRM + 2; i++) { const r = await post(n.url, forged(i)); assert.ok(r.ms < T.HOLD_MS); assert.equal(r.raw[0], '{'); }
    assert.equal(n.stats.tarpitHeld, 0);
  } finally { await n.done(); }
});

test('close ends every hold at once', async () => {
  const n = await node({ ...T, HOLD_MS: 60000, DRIP_MS: 1000 });
  for (let i = 1; i <= T.CONFIRM; i++) await post(n.url, forged(i));
  const p = post(n.url, forged(40));
  await wait(100);
  assert.equal(n.holding, 1);
  const t0 = Date.now();
  await n.done();
  assert.ok(Date.now() - t0 < 2000, 'closed without waiting out the hold');
  assert.equal((await p).aborted || (await p).status === 403, true);
  assert.equal(n.holding, 0);
});
