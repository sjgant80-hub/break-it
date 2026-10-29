// tarpit/run.mjs — the tarpit measurement's runner, in a child process of tarpit/measure.mjs. Each node runs in its own
// process (tarpit/node.mjs); the attacker's proof-of-work is solved in worker threads (tarpit/solver.mjs), so neither
// shares an event loop with a node or with a timing. The attacker sends from 127.0.0.2, genuine traffic from 127.0.0.1
// unless a claim says otherwise. Every forgery is the attack kit's (attack-kit/lib.mjs message + signRaw, as
// attack-kit/forge.mjs builds one) signed with one fixed key the node does not pin; every genuine packet is the pilot's.
// Nothing here generates attacks. It prints one JSON object of facts on its last line.
//   node tarpit/run.mjs                 → the shipped settings
//   TARPIT_SMOKE=1 node tarpit/run.mjs  → plumbing only, on small settings: the facts' shape, never judged
import { fork } from 'node:child_process';
import { Worker } from 'node:worker_threads';
import http from 'node:http';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir, availableParallelism } from 'node:os';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { message, signRaw } from '../attack-kit/lib.mjs';
import { keyFromSeed } from '../src/keys.mjs';
import { OPS } from '../src/wire.mjs';
import { books } from '../src/feed.mjs';
import { loadFeed, genuine as genuineClient, packetFor, booksHash } from '../pilot/lib.mjs';
import { TARPIT } from '../src/tarpit.mjs';

const SMOKE = process.env.TARPIT_SMOKE === '1';
const S = SMOKE ? { CONFIRM: 5, HOLD_MS: 600, DRIP_MS: 100, CAP: 4 } : { ...TARPIT };
const TICKS = Math.floor(S.HOLD_MS / S.DRIP_MS);
const N = SMOKE ? { held: 3, window: 3000, flood: 8, genuine: 30, shared: 5, latency: 20, giveUp: 300, quick: 300 }
  : { held: 3, window: 120000, flood: 100, genuine: 3000, shared: 100, latency: 200, giveUp: 5000, quick: 5000 };
const ATTACKER = '127.0.0.2', HOME = '127.0.0.1';
const AKEY = keyFromSeed(new Uint8Array(32).fill(0xa7));
const forgery = (i) => signRaw(message({ sender: 1, counter: BigInt(i), op: OPS.SET, key: 'name', value: 'forged', delta: 1 }), AKEY);
const FEED = loadFeed().records;
const wait = (ms) => new Promise((ok) => setTimeout(ok, ms));
const median = (xs) => { const s = [...xs].sort((a, b) => a - b); return s.length ? (s[(s.length - 1) >> 1] + s[s.length >> 1]) / 2 : null; };
const r1 = (x) => Math.round(x * 10) / 10;

// ── the solver pool: the rebound's own solve(), in worker threads ──────────────────────────────────────────────────
const pool = Array.from({ length: Math.max(1, Math.min(8, availableParallelism() - 1)) }, () => new Worker(new URL('./solver.mjs', import.meta.url)));
let next = 0, ids = 0;
const waiting = new Map();
for (const w of pool) w.on('message', ({ id, nonce }) => { waiting.get(id)(nonce); waiting.delete(id); });
const pay = (challenge, bits) => new Promise((ok) => { const id = ids++; waiting.set(id, ok); pool[next++ % pool.length].postMessage({ id, challenge, bits }); });

// ── one POST on its own connection: status, headers, the raw bytes, how long; giveUpMs closes it early ───────────────
const request = (url, bytes, { from, work = null, giveUpMs = 0 } = {}) => new Promise((resolve) => {
  const t0 = performance.now(), parts = [];
  let done = false, res = null;
  const end = (o) => { if (!done) { done = true; resolve({ ...o, raw: Buffer.concat(parts), ms: performance.now() - t0 }); } };
  const headers = { 'content-type': 'application/octet-stream', 'content-length': bytes.length };
  if (work !== null) headers['x-rebound'] = work;
  const req = http.request(new URL('/packet', url), { method: 'POST', agent: false, localAddress: from, headers }, (r) => {
    res = r;
    r.on('data', (c) => parts.push(c));
    r.on('end', () => end({ status: r.statusCode, headers: r.headers }));
    r.on('close', () => end({ status: r.statusCode, headers: r.headers, aborted: !r.complete }));
  });
  req.on('error', () => end({ status: res ? res.statusCode : null, aborted: true }));
  if (giveUpMs) setTimeout(() => { if (!done) { req.destroy(); end({ status: res ? res.statusCode : null, aborted: true }); } }, giveUpMs);
  req.end(Buffer.from(bytes));
});
/** send, paying the rebound's work when it is asked (402: a token is good for its ten-second window, so one solved too
 *  late is asked for again), and retrying a rate-limit answer (429) — each counted */
const retried = { rate: 0, repaid: 0 };
async function send(url, bytes, opts = {}) {
  let work = null, paid = 0;
  for (let t = 0; t < 100; t++) {
    const r = await request(url, bytes, { ...opts, work });
    if (r.status === 402) {
      if (work !== null) retried.repaid++;
      const b = JSON.parse(r.raw.toString('utf8'));
      work = await pay(b.challenge, b.bits); paid = b.bits;
      continue;
    }
    if (r.status !== 429) return { ...r, paid };
    retried.rate++; await wait(20);
  }
  throw new Error('asked to pay or rate-limited 100 times in a row');
}
/** what a held answer looks like: the bytes before its JSON */
const lead = (raw) => { const i = raw.indexOf(0x7b); return i < 0 ? raw : raw.subarray(0, i); };
const spacesOnly = (b) => b.every((x) => x === 0x20);
const isAdmitted = (r) => r.status === 200 && JSON.parse(r.raw.toString('utf8')).accepted === true;

// ── the nodes, each in its own process ──────────────────────────────────────────────────────────────────────────────
async function startNode(tarpit) {
  const dir = mkdtempSync(join(tmpdir(), 'tarpit-'));
  const paths = { ledgerPath: join(dir, 'ledger.jsonl'), journalPath: join(dir, 'journal.jsonl'), lootPath: join(dir, 'loot.jsonl') };
  const child = fork(new URL('./node.mjs', import.meta.url), [JSON.stringify({ ...paths, tarpit })], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  const ask = (m, key) => new Promise((ok) => { const f = (x) => { if (x && x[key] !== undefined) { child.off('message', f); ok(x[key]); } }; child.on('message', f); if (m) child.send(m); });
  const url = await ask(null, 'url');
  return { url, paths, report: () => ask('report', 'report'), holding: () => ask('holding', 'holding'), journal: () => readFileSync(paths.journalPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)),
    close: async () => { await ask('close', 'closed'); rmSync(dir, { recursive: true, force: true }); } };
}

/** the attacker's forgeries from..to, one at a time, waiting for each answer */
async function forge(node, from, to) {
  const out = [];
  for (let i = from; i <= to; i++) out.push(await send(node.url, forgery(i), { from: ATTACKER }));
  return out;
}

const facts = { settings: S };
const on = await startNode(SMOKE ? S : true), off = await startNode(null);
let counter = 1;   // the attacker's forgery counter: every forgery new bytes

// ── p-3, p-6, p-7: the same sequence to both twins — CONFIRM refusals, then the held ones ─────────────────────────────
const seqOn = await forge(on, counter, counter + S.CONFIRM + N.held - 1), seqOff = await forge(off, counter, counter + S.CONFIRM + N.held - 1);
counter += S.CONFIRM + N.held;
const firstOn = seqOn.slice(0, S.CONFIRM), heldOn = seqOn.slice(S.CONFIRM), heldOff = seqOff.slice(S.CONFIRM);
facts.p3 = {
  first: S.CONFIRM, firstRefused: firstOn.filter((r) => r.status === 403).length, firstAnsweredAtOnce: firstOn.filter((r) => lead(r.raw).length === 0).length,
  then: N.held, thenHeld: heldOn.map((r) => ({ status: r.status, spaces: lead(r.raw).length, spacesOnly: spacesOnly(lead(r.raw)) })),
};
const noLength = (h) => Object.fromEntries(Object.entries(h || {}).filter(([k]) => !['content-length', 'date', 'connection', 'keep-alive'].includes(k)));
facts.p6 = heldOn.map((r, k) => {
  const json = r.raw.subarray(lead(r.raw).length), twin = heldOff[k];
  return { status: r.status === twin.status, headers: JSON.stringify(noLength(r.headers)) === JSON.stringify(noLength(twin.headers)), lengthCountsSpaces: Number(r.headers['content-length']) === r.raw.length,
    spacesOnly: spacesOnly(lead(r.raw)), spaces: lead(r.raw).length, jsonEqual: Buffer.compare(json, twin.raw) === 0 };
});
facts.p6all = seqOn.every((r, k) => Buffer.compare(r.raw.subarray(lead(r.raw).length), seqOff[k].raw) === 0);   // every answer of the sequence, held or not
const [repOn, repOff] = [await on.report(), await off.report()];
const noTime = (rec) => { const { at, ...rest } = rec; return rest; };
const [jOn, jOff] = [on.journal(), off.journal()];
facts.p7 = { libraryEqual: JSON.stringify(repOn.library) === JSON.stringify(repOff.library), exact: Object.keys(repOn.library.exact).length, shapes: repOn.library.shapes.length,
  journalEqual: jOn.length === jOff.length && jOn.every((x, k) => JSON.stringify(noTime(x)) === JSON.stringify(noTime(jOff[k]))), journalRecords: jOn.length };

// ── p-4: the confirmed attacker, one forgery at a time, for the window, against each twin ─────────────────────────────
async function window(node) {
  const t0 = performance.now(); let answers = 0, held = 0;
  while (performance.now() - t0 < N.window) { const r = await send(node.url, forgery(counter++), { from: ATTACKER }); if (r.status !== null && !r.aborted) answers++; if (lead(r.raw).length) held++; }
  return { answers, held, seconds: r1((performance.now() - t0) / 1000) };
}
const winOff = await window(off), winOn = await window(on);
facts.p4 = { off: winOff, on: winOn };

// ── p-1: the pilot's genuine records from another address while the attacker is being held ───────────────────────────
const client = genuineClient(), sent = [];
const genuineFrom = async (node, from, k) => { const rs = []; for (let i = 0; i < k; i++) { const rec = FEED[sent.length]; sent.push(rec); rs.push(await send(node.url, packetFor(client, rec), { from })); } return rs; };
let keepHolding = true, attackerHeld = 0;
const holder = (async () => { while (keepHolding) { const r = await send(on.url, forgery(counter++), { from: ATTACKER }); if (lead(r.raw).length) attackerHeld++; } })();
await wait(200);
const heldBefore = (await on.report()).stats.tarpitHeld;
const g1 = await genuineFrom(on, HOME, N.genuine);
const during = (await on.holding());
keepHolding = false; await holder;
facts.p1 = { sent: g1.length, admitted: g1.filter(isAdmitted).length, held: g1.filter((r) => lead(r.raw).length > 0).length, attackerHeldMeanwhile: attackerHeld, holdingAtTheEnd: during, nodeHeldBefore: heldBefore };

// ── p-5: a hundred forgeries at once; genuine latency with nothing held, then with the tarpit full ────────────────────
while ((await on.holding()) > 0) await wait(250);
const base = []; for (let i = 0; i < N.latency; i++) { const rec = FEED[sent.length]; sent.push(rec); const r = await send(on.url, packetFor(client, rec), { from: HOME }); base.push(r); }
let maxHolding = 0, watching = true;
const watch = (async () => { while (watching) { maxHolding = Math.max(maxHolding, (await on.holding())); await wait(50); } })();
const flood = Array.from({ length: N.flood }, () => send(on.url, forgery(counter++), { from: ATTACKER }));
for (let t = 0; t < 400 && (await on.holding()) < S.CAP; t++) await wait(50);
const fullAt = (await on.holding());
const busy = []; for (let i = 0; i < N.latency; i++) { const rec = FEED[sent.length]; sent.push(rec); busy.push(await send(on.url, packetFor(client, rec), { from: HOME })); }
const fullAfter = (await on.holding());
const floodR = await Promise.all(flood);
watching = false; await watch;
const rep5 = await on.report();
facts.p5 = { sent: N.flood, maxHolding, cap: S.CAP, heldWhenGenuineBegan: fullAt, heldWhenGenuineEnded: fullAfter, held: floodR.filter((r) => lead(r.raw).length > 0).length,
  quick: floodR.filter((r) => r.ms < N.quick).length, full: rep5.stats.tarpitFull,
  genuine: { sent: N.latency, admittedBase: base.filter(isAdmitted).length, admittedBusy: busy.filter(isAdmitted).length,
    medianBaseMs: r1(median(base.map((r) => r.ms))), medianBusyMs: r1(median(busy.map((r) => r.ms))), heldBusy: busy.filter((r) => lead(r.raw).length > 0).length } };

// ── p-2: genuine records from the confirmed attacker's own address ───────────────────────────────────────────────────
const g2 = await genuineFrom(on, ATTACKER, N.shared);
facts.p2 = { sent: g2.length, admitted: g2.filter(isAdmitted).length, held: g2.filter((r) => lead(r.raw).length > 0).length, paidWork: g2.filter((r) => r.paid > 0).length, bits: [...new Set(g2.map((r) => r.paid || 0))] };

// ── p-8: an attacker that gives up ────────────────────────────────────────────────────────────────────────────────────
while ((await on.holding()) > 0) await wait(250);
const abandonedBefore = (await on.report()).stats.tarpitAbandoned;
const gone = await send(on.url, forgery(counter++), { from: ATTACKER, giveUpMs: N.giveUp });
await wait(1000);
const rep8 = await on.report();
facts.p8 = { aborted: gone.aborted === true, bytes: gone.raw.length, spacesOnly: spacesOnly(gone.raw), holdingAfter: rep8.holding, abandonedRose: rep8.stats.tarpitAbandoned - abandonedBefore };

// ── the books: everything genuine the tarpit node admitted, against the feed ─────────────────────────────────────────
const state = await new Promise((ok) => http.get(new URL('/state', on.url), (r) => { const p = []; r.on('data', (c) => p.push(c)); r.on('end', () => ok(JSON.parse(Buffer.concat(p).toString('utf8')))); }));
facts.books = { records: sent.length, match: booksHash(state.state) === booksHash(books(sent)) };
facts.final = { stats: Object.fromEntries(Object.entries(rep8.stats).filter(([k]) => k.startsWith('tarpit') || ['admitted', 'refused', 'rebounded', 'flooded'].includes(k))) };
facts.retried = retried;

await on.close(); await off.close();
for (const w of pool) await w.terminate();
console.log(JSON.stringify(facts));
