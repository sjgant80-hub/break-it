// herd/run.mjs — the herd measurement's runner, in a child process of herd/measure.mjs. Five real break-it nodes
// (src/server.mjs startNode) in one mesh over loopback HTTP, each on its own ledger and journal in a fresh folder.
//   node herd/run.mjs real                          → h-1: the shipped gate
//   node --import ./herd/flaw.mjs herd/run.mjs flawed → h-2 … h-7: the planted flaw (herd/flaw.mjs)
// It prints one JSON object of facts on its last line. Every packet is built from the pilot's genuine sender or the
// attack kit's out-of-range shape; nothing here generates attacks.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { startNode } from '../src/server.mjs';
import { keyFromSeed, rawPublic, signWith } from '../src/keys.mjs';
import { makeClient } from '../src/client.mjs';
import { books } from '../src/feed.mjs';
import { REASON } from '../src/patch.mjs';
import { rawPacket, signRaw } from '../attack-kit/lib.mjs';
import { loadFeed, hex, SENDER, PUBKEYS, booksHash, packetFor } from '../pilot/lib.mjs';
import { OPS } from '../src/wire.mjs';

const MODE = process.argv[2];
const SMOKE = process.env.HERD_SMOKE === '1';                 // plumbing only: a few of each, the facts' shape printed, never judged
export const N = 5, PREFIX = 50, VARIANTS = SMOKE ? 2 : 20, GENUINE = SMOKE ? 20 : 3000, PATCH_MS = 2000;
const FEED = loadFeed().records;
const be = (v, n) => Array.from({ length: n }, (_, i) => (v >>> (8 * (n - 1 - i))) & 0xff);
const wait = (ms) => new Promise((ok) => setTimeout(ok, ms));
const freePort = () => new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); });
const tally = (xs) => xs.reduce((a, x) => ({ ...a, [x]: (a[x] || 0) + 1 }), {});
const NODE_KEYS = Array.from({ length: N }, (_, i) => keyFromSeed(new Uint8Array(32).fill(0x60 + i)));
const SHARE_DOMAIN = 'BREAK-IT/share/v1|';

/** the attack kit's out-of-range shape: period 1200, signed by the ingest key (pilot/measure.mjs, attack 'out-of-range') */
export const zeroDay = (counter, account = 1, amount = 1) => signRaw(rawPacket({ sender: 1, counter, payload: [OPS.REC, ...be(account, 4), ...be(1200, 2), ...be(amount, 4)] }), SENDER);

// one kept-alive socket per node (as pilot/lib.mjs, which explains the keep-alive buffer), a fresh set for every herd and
// for every restarted node: a socket kept from a closed node would be reset
let agent = null;
const freshAgent = () => { if (agent) agent.destroy(); agent = new http.Agent({ keepAlive: true, maxSockets: 1, agentKeepAliveTimeoutBuffer: 0 }); };
const post = (url, bytes) => new Promise((resolve, reject) => {
  const req = http.request(new URL('/packet', url), { method: 'POST', agent, headers: { 'content-type': 'application/octet-stream', 'content-length': bytes.length } }, (res) => {
    const parts = [];
    res.on('data', (c) => parts.push(c));
    res.on('end', () => { let body = null; try { body = JSON.parse(Buffer.concat(parts).toString('utf8')); } catch { body = null; } resolve({ status: res.statusCode, body }); });
  });
  req.on('error', reject);
  req.end(Buffer.from(bytes));
});
/** POST, retrying a rate-limit answer (429) or a reset socket — each counted, never hidden (a resend the node had already
 *  taken would come back refused at its counter, so a retry cannot turn a refusal into an admission) */
const retried = { rate: 0, reset: 0 };
async function send(url, bytes) {
  for (let t = 0; t < 100; t++) {
    let r;
    try { r = await post(url, bytes); } catch (e) { if (e.code !== 'ECONNRESET') throw e; retried.reset++; freshAgent(); continue; }
    if (r.status !== 429) return r;
    retried.rate++; await wait(20);
  }
  throw new Error('rate-limited or reset 100 times in a row');
}
const outcome = (r) => (r.status === 200 && r.body && r.body.accepted ? 'admitted' : (r.body && r.body.stage ? r.body.stage + (r.body.reason === REASON ? ' (door)' : '') : 'status ' + r.status));

async function herd({ herdPatch = true } = {}) {
  freshAgent();
  const ports = []; for (let i = 0; i < N; i++) ports.push(await freePort());
  const info = NODE_KEYS.map((k, i) => ({ url: 'http://127.0.0.1:' + ports[i], key: hex(rawPublic(k)) }));
  const dirs = NODE_KEYS.map(() => mkdtempSync(join(tmpdir(), 'herd-')));
  const opts = (i) => ({ port: ports[i], ledgerPath: join(dirs[i], 'ledger.jsonl'), journalPath: join(dirs[i], 'journal.jsonl'), lootPath: join(dirs[i], 'loot.jsonl'),
    pubkeys: PUBKEYS, nodeKey: NODE_KEYS[i], peers: info.filter((_, j) => j !== i), herdPatch });
  const nodes = [];
  for (let i = 0; i < N; i++) nodes.push(await startNode(opts(i)));
  // the same genuine prefix to every node, so every node expects the same next counter
  const c = makeClient({ privateKey: SENDER });
  const prefix = FEED.slice(0, PREFIX).map((rec) => packetFor(c, rec));
  for (const n of nodes) for (const p of prefix) { const r = await send(n.url, p); if (outcome(r) !== 'admitted') throw new Error('the genuine prefix was refused: ' + outcome(r)); }
  return { nodes, info, dirs, opts, close: async () => { for (const n of nodes) await n.close(); for (const d of dirs) rmSync(d, { recursive: true, force: true }); } };
}
const breaches = (h) => h.nodes.reduce((a, n) => a + n.stats.breaches, 0);

async function real() {
  const h = await herd();
  const out = [];
  for (const n of h.nodes) out.push(outcome(await send(n.url, zeroDay(BigInt(PREFIX + 1)))));
  const facts = { h1: { sent: N, outcomes: tally(out), breaches: breaches(h) } };
  await h.close();
  return facts;
}

async function flawed() {
  const facts = {};
  // h-2: the node as it was — no herd patch
  { const h = await herd({ herdPatch: false });
    const out = [];
    for (const n of h.nodes) out.push(outcome(await send(n.url, zeroDay(BigInt(PREFIX + 1)))));
    facts.h2 = { sent: N, outcomes: tally(out), breaches: breaches(h), patched: h.nodes.filter((n) => n.patch.on).length };
    await h.close(); }

  // h-3 … h-7: the herd patch on
  const h = await herd();
  const z = zeroDay(BigInt(PREFIX + 1));
  const first = outcome(await send(h.nodes[0].url, z)), t0 = Date.now();
  const at = Array(N).fill(null);
  while (Date.now() - t0 <= PATCH_MS + 500 && h.nodes.slice(1).some((n, i) => at[i + 1] === null)) {
    for (let i = 1; i < N; i++) if (at[i] === null && h.nodes[i].patch.on) at[i] = Date.now() - t0;
    await wait(5);
  }
  const peers = [];
  for (let i = 1; i < N; i++) peers.push({ node: i + 1, patchedAfterMs: at[i], by: h.nodes[i].patch.by ? h.nodes[i].patch.by.split(':')[0] : null, same: outcome(await send(h.nodes[i].url, z)) });
  facts.h3 = { first, node1: { patch: h.nodes[0].patch.on, by: h.nodes[0].patch.by }, peers, breaches: breaches(h) };

  // h-4: twenty variants to every node, each at the counter that node expects (a refused packet moves no counter)
  const expect = (i) => BigInt(PREFIX + 1 + (i === 0 ? 1 : 0));
  const v4 = [];
  for (let i = 0; i < N; i++) for (let k = 0; k < VARIANTS; k++) v4.push(outcome(await send(h.nodes[i].url, zeroDay(expect(i), 2 + k, 100 * (k + 1)))));
  facts.h4 = { sent: v4.length, outcomes: tally(v4), breaches: breaches(h) };

  // h-6: the next 3,000 genuine records to every patched node; books against exactly the records each node holds
  const held = Array.from({ length: N }, (_, i) => [...FEED.slice(0, PREFIX), ...(i === 0 ? [{ account: 1, period: 1200, amount: 1 }] : [])]);
  const g6 = [], t6 = Date.now();
  for (let i = 0; i < N; i++) {
    const ci = makeClient({ privateKey: SENDER, startCounter: expect(i) });
    for (const rec of FEED.slice(PREFIX, PREFIX + GENUINE)) { const r = outcome(await send(h.nodes[i].url, packetFor(ci, rec))); g6.push(r); if (r === 'admitted') held[i].push(rec); }
  }
  const booksMatch = h.nodes.map((n, i) => booksHash(n.app.state()) === booksHash(books(held[i])));
  facts.h6 = { sent: g6.length, outcomes: tally(g6), booksMatch, refusalsPerNodeMax: Math.max(...h.nodes.map((n) => n.stats.refused)) };
  const rate = Math.round(g6.length / ((Date.now() - t6) / 1000));

  // h-7: node 1 (took the landing) and node 2 (patched by a peer's evidence) closed and started again on their own files
  const after = [];
  for (const i of [0, 1]) {
    await h.nodes[i].close();
    const again = await startNode(h.opts(i));
    freshAgent();
    h.nodes[i] = again;
    const next = BigInt(PREFIX + 1 + (i === 0 ? 1 : 0) + GENUINE);
    after.push({ node: i + 1, patch: again.patch.on, by: again.patch.by, variant: outcome(await send(again.url, zeroDay(next, 99, 7))) });
  }
  facts.h7 = { restarted: after };
  await h.close();

  // h-5: a fresh flawed herd; a peer holding node 5's real key shares, to nodes 1–4, a genuine record (the next one, which
  // every gate admits) and a forged one (its signature broken) as if they were attacks
  { const h5 = await herd();
    const c5 = makeClient({ privateKey: SENDER, startCounter: BigInt(PREFIX + 1) });
    const genuineNext = packetFor(c5, FEED[PREFIX]);
    const forged = genuineNext.slice(); forged[forged.length - 1] ^= 1;
    const antigens = [genuineNext, forged].map((b) => Buffer.from(b).toString('hex'));
    const from = h5.info[4].key, sig = hex(signWith(NODE_KEYS[4])(Buffer.from(SHARE_DOMAIN + from + '|' + JSON.stringify(antigens))));
    const shares = [];
    for (let i = 0; i < N - 1; i++) {
      const r = await fetch(new URL('/immune/share', h5.nodes[i].url), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ v: 1, from, antigens, sig }) });
      shares.push(r.status);
    }
    const still = [];
    for (const n of h5.nodes) still.push(outcome(await send(n.url, genuineNext)));
    facts.h5 = { shareStatus: tally(shares.map(String)), patched: h5.nodes.filter((n) => n.patch.on).length, nextGenuine: tally(still) };
    await h5.close(); }

  facts.timing = { patchMs: facts.h3.peers.map((p) => p.patchedAfterMs), genuinePerSecond: rate, retried };
  return facts;
}

const facts = MODE === 'real' ? await real() : MODE === 'flawed' ? await flawed() : null;
if (!facts) { console.log('usage: node herd/run.mjs real | node --import ./herd/flaw.mjs herd/run.mjs flawed'); process.exit(2); }
if (agent) agent.destroy();
// no process.exit: on Windows an exit while the closed servers' handles are still closing trips a libuv assertion
process.stdout.write(JSON.stringify(facts) + '\n');
