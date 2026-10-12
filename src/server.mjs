// ════════════════════════════════════════════════════════════════
// server.mjs — one node: the local REST service in front of the gate. Bound to 127.0.0.1.
//
// A packet's path:   HTTP limits → exact antibodies (known attacks recognised on sight, gate double-check) → the GATE (verify before
//                    parse) → SENTINEL (behaviour, per verified sender) → LEDGER (written + fsync'd) → the naive APP
//                    → the REFEREE (did anything reach the app it should not have?)
// Every refusal, at any step, is an antigen: journalled, classified, fingerprinted, learned, turned into antibodies
// (exact ones only for refusals that are permanent), and — when it is new — signed and pushed to every pinned peer,
// which re-runs it against its OWN gate before it adopts anything. Every novel attack is also a vaccine
// (tools/vaccinate.mjs → CI replays every one, forever).
//
//   POST /packet          raw packet bytes (Content-Length required, ≤ MAX_PACKET; chunked bodies refused)
//   GET  /health /pubkeys /state /referee /immune /journal?since=&limit=
//   POST /immune/share    a peer's signed antigens (JSON) — adopted only after this node's own gate re-runs them
// ════════════════════════════════════════════════════════════════
import http from 'node:http';
import { createHash } from 'node:crypto';
import { decide } from './gate.mjs';
import { MAX_PACKET } from './wire.mjs';
import { judge, freshState } from './sentinel.mjs';
import { classify, fingerprint, learn, standing, detail, emptyMemory } from './immune.mjs';
import { immuneStage, features, mint, adopt, recognise, emptyLibrary, PERMANENT } from './antibody.mjs';
import { openChain, sha256hex } from './ledger.mjs';
import { openJournal } from './journal.mjs';
import { makeApp } from './app.mjs';
import { makeReferee } from './referee.mjs';
import { keyTable, signWith, rawPublic, publicFromRaw } from './keys.mjs';
import { mintRune, questLog } from './loot.mjs';
import { difficultyFor, challenge, verifyWork } from './rebound.mjs';
import { appendFileSync, readFileSync as readText, existsSync as exists } from 'node:fs';
import { verify as edVerify } from 'node:crypto';

export const LIMITS = Object.freeze({ rate: 300, burst: 600, queue: 1024, shareBytes: 65536, shareAntigens: 64, shareEveryMs: 250, ipTable: 10000 });
const hexOf = (u8) => Buffer.from(u8).toString('hex');
const bytesHash = (u8) => createHash('sha256').update(u8).digest('hex');
const sha = (str) => createHash('sha256').update(str).digest('hex');
const GATE_REFUSALS = new Set(['size', 'magic', 'schema', 'sender', 'signature', 'counter', 'behavior', 'error']);
const SHARE_DOMAIN = 'BREAK-IT/share/v1|';
const REBOUND_EPOCH_MS = 10000;                                 // a work token is good for its 10s window, then re-earned

function sendJson(res, code, body) {
  const text = JSON.stringify(body);
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-length': Buffer.byteLength(text) });
  res.end(text);
}

/** Read exactly Content-Length bytes, refusing chunked bodies, a missing or oversized length, or a mismatch. */
function readBody(req, max) {
  return new Promise((resolve) => {
    if (req.headers['transfer-encoding'] !== undefined) return resolve({ ok: false, why: 'chunked bodies are refused — send Content-Length' });
    const cl = req.headers['content-length'];
    if (typeof cl !== 'string' || !/^[0-9]{1,6}$/.test(cl)) return resolve({ ok: false, why: 'a Content-Length is required' });
    const n = Number(cl);
    if (n < 1 || n > max) return resolve({ ok: false, why: 'a body is 1–' + max + ' bytes' });
    const parts = []; let got = 0, done = false;
    const finish = (r) => { if (!done) { done = true; resolve(r); } };
    req.on('data', (c) => { got += c.length; if (got > n) { finish({ ok: false, why: 'the body is longer than its Content-Length' }); req.destroy(); } else parts.push(c); });
    req.on('end', () => finish(got === n ? { ok: true, bytes: new Uint8Array(Buffer.concat(parts)) } : { ok: false, why: 'the body is shorter than its Content-Length' }));
    req.on('error', () => finish({ ok: false, why: 'the connection failed' }));
    req.on('aborted', () => finish({ ok: false, why: 'the client aborted' }));
  });
}

/**
 * Start one node. opts: { port, host, ledgerPath, journalPath, pubkeys {id: hex}, nodeKey (private KeyObject),
 * peers [{ url, key (hex) }], now () → ms (injected so tests control time), log }
 */
export async function startNode(opts) {
  const o = opts || {};
  const host = o.host || '127.0.0.1';
  const now = o.now || (() => Date.now());
  const log = o.log || (() => {});
  const keys = keyTable(o.pubkeys || {});
  const nodePub = o.nodeKey ? hexOf(rawPublic(o.nodeKey)) : null;
  const sign = o.nodeKey ? signWith(o.nodeKey) : null;
  const peers = Array.isArray(o.peers) ? o.peers.filter((p) => p && /^[0-9a-f]{64}$/.test(p.key)) : [];
  const peerKeys = new Map(peers.map((p) => [p.key, publicFromRaw(Buffer.from(p.key, 'hex'))]));

  // ── state, rebuilt from the ledger: every packet re-run through the gate — a ledger the gate refuses will not start
  const ledger = openChain(o.ledgerPath);
  if (!ledger.ok) throw new Error(ledger.reason);
  const counters = new Map(), senders = new Map(), app = makeApp(), referee = makeReferee(), packets = [], admittedHashes = new Set();
  const ctx = { keyFor: keys.keyFor, verify: keys.verify, lastCounter: (s) => counters.get(s) || 0n };
  for (const e of ledger.entries) {
    const bytes = new Uint8Array(Buffer.from(e.packet, 'hex'));
    const v = decide(bytes, ctx);
    if (!v.admit) { ledger.close(); throw new Error('the ledger holds a packet the gate refuses (entry ' + e.seq + ': ' + v.reason + ') — refusing to start'); }
    const s = judge(senders.get(v.msg.sender) || freshState(), v.msg);
    senders.set(v.msg.sender, s.state);
    counters.set(v.msg.sender, v.msg.counter);
    app.apply(v.msg); referee.after(v.msg, bytes); packets.push(bytes); admittedHashes.add(bytesHash(bytes));
  }

  // ── immunity, rebuilt from the journal: memory from every record; antibodies re-minted by re-running each antigen
  const journal = openJournal(o.journalPath);
  let memory = emptyMemory(), library = emptyLibrary();
  const relearn = (bytes, family) => {
    const v = decide(bytes, ctx);
    if (v.admit) return { added: 0 };                              // valid NOW: never an antibody (no autoimmunity)
    const stage = immuneStage(v);
    const ab = mint(bytes, { hash: bytesHash(bytes), stage, keyset: keys.keyset, family });
    const r = adopt(library, [ab.exact, ab.shape].filter(Boolean));
    library = r.library;
    return { added: r.added, exact: !!ab.exact };
  };
  const blocked = new Set();                                    // senders SENTINEL has blocked — from the journal
  const reboundCount = new Map();                               // GATE-refusals per source — drives the cost law (rebound.mjs)
  const owed = (source) => difficultyFor(reboundCount.get(source) || 0);
  const charge = (source) => { if (source && !String(source).startsWith('peer:')) reboundCount.set(source, (reboundCount.get(source) || 0) + 1); };
  for (const r of journal.records) {
    memory = learn(memory, { family: r.family, print: r.print, source: r.source }).memory;
    if (r.stage === 'behavior' && r.context && r.context.blocked === true && Number.isInteger(r.context.sender)) blocked.add(r.context.sender);
    if (GATE_REFUSALS.has(r.stage) && typeof r.source === 'string' && !r.source.startsWith('peer:')) reboundCount.set(r.source, (reboundCount.get(r.source) || 0) + 1);
    if (r.detail === 'full' && r.bytes && r.size <= MAX_PACKET && r.bytes.length === r.size * 2) relearn(new Uint8Array(Buffer.from(r.bytes, 'hex')), r.family);
  }

  const stats = { admitted: 0, refused: 0, recognised: 0, breaches: 0, shared: 0, shareDropped: 0, adoptedFromPeers: 0, autoimmune: 0, flooded: 0, rebounded: 0 };
  // the loot: Legendary runes (signed, persisted), Epic autoimmune events
  const lootPath = o.lootPath || null;
  const runes = [], epics = [];
  const NL = String.fromCharCode(10);
  if (lootPath && exists(lootPath)) for (const l of readText(lootPath, 'utf8').split(NL).filter(Boolean)) { try { const x = JSON.parse(l); (x.tier === 'LEGENDARY' ? runes : epics).push(x); } catch { /* skip */ } }
  const keepLoot = (x) => { if (lootPath) { try { appendFileSync(lootPath, JSON.stringify(x) + NL); } catch { /* the drop still shows */ } } };
  const buckets = new Map();
  const allow = (ip) => {
    const t = now();
    let b = buckets.get(ip);
    if (!b) { if (buckets.size >= LIMITS.ipTable) buckets.delete(buckets.keys().next().value); b = { tokens: LIMITS.burst, at: t }; buckets.set(ip, b); }
    b.tokens = Math.min(LIMITS.burst, b.tokens + ((t - b.at) * LIMITS.rate) / 1000); b.at = t;
    if (b.tokens < 1) return false;
    b.tokens -= 1; return true;
  };

  // a flood is journalled as a count — one record per source per second, however hard it pushes
  const floods = new Map();
  function floodNote(source) {
    const f = floods.get(source) || { n: 0, at: 0 };
    f.n++;
    const t = now();
    if (t - f.at >= 1000) {
      journal.record({ at: new Date(t).toISOString(), source, stage: 'flood', reason: f.n + ' requests over the rate limit since the last note', family: 'flood', print: 'flood|rate', novel: false, detail: 'count', bytes: new Uint8Array(0), context: { count: f.n } });
      f.n = 0; f.at = t;
    }
    if (floods.size >= LIMITS.ipTable && !floods.has(source)) floods.delete(floods.keys().next().value);
    floods.set(source, f);
  }

  // one antigen → journal + memory + antibodies (+ the peers, when it is new)
  function antigen(bytes, refusal, source, extra = {}) {
    const stage = immuneStage(refusal);
    const decl = bytes.length >= 16 ? (bytes[14] << 8) | bytes[15] : null;
    const family = classify(refusal, { bytes, declaredLength: decl, exactReplay: extra.exactReplay === true });
    const print = fingerprint(family, { bytes });
    const before = standing(memory, source);
    const l = learn(memory, { family, print, source });
    memory = l.memory;
    const near = recognise(library, null, features(bytes, stage), keys.keyset).nearest;
    let minted = { exact: false };
    if (PERMANENT.includes(stage)) {
      const ab = mint(bytes, { hash: bytesHash(bytes), stage, keyset: keys.keyset, family });
      const r = adopt(library, [ab.exact, ab.shape].filter(Boolean)); library = r.library; minted = { exact: r.added > 0 && !!ab.exact };
    } else {
      const ab = mint(bytes, { stage, family });
      library = adopt(library, [ab.shape]).library;
    }
    const sender = bytes.length > 5 ? bytes[5] : null;
    const rec = journal.record({
      at: new Date(now()).toISOString(), source, stage: refusal.stage, reason: refusal.reason, family, print, novel: l.novel || extra.block === true,
      detail: detail(before, l.novel), bytes,
      context: { keyset: keys.keyset, stage, sender, last: sender === null ? null : String(counters.get(sender) || 0n), recognisedAs: near ? near.family : null, ...(extra.block ? { blocked: true } : {}) },
    });
    if (minted.exact) share([bytes]);                             // a new exact antibody → every peer, within SHARE_EVERY
    if (extra.block) blocked.add(refusal.sender);
    return { family, print, novel: l.novel, recognisedAs: near ? near.family : null, journal: rec ? rec.seq : null, antibody: minted.exact };
  }

  // the mycelium: every new exact antibody goes to every pinned peer, signed; each peer re-runs it on its own gate.
  // Batched: at most shareAntigens per peer every shareEveryMs (an attacker who mints a million unique forgeries
  // gets the mesh to re-run at most 256 a second per peer — the rest are still refused and journalled, just not
  // forwarded). A breach skips the queue.
  let outbox = [], flushTimer = null;
  function share(list, { now: immediate = false } = {}) {
    if (!sign || peers.length === 0) return;
    for (const b of list) { if (outbox.length < LIMITS.shareAntigens) outbox.push(b); else stats.shareDropped++; }
    if (immediate) { if (flushTimer) { clearTimeout(flushTimer); flushTimer = null; } flush(); }
    else if (!flushTimer) { flushTimer = setTimeout(() => { flushTimer = null; flush(); }, LIMITS.shareEveryMs); flushTimer.unref?.(); }
  }
  function flush() {
    if (!outbox.length) return;
    const antigens = outbox.splice(0).map((b) => hexOf(b));
    const body = JSON.stringify({ v: 1, from: nodePub, antigens, sig: hexOf(sign(Buffer.from(SHARE_DOMAIN + nodePub + '|' + JSON.stringify(antigens)))) });
    for (const p of peers) {
      try {
        const u = new URL('/immune/share', p.url);
        const req = http.request(u, { method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }, timeout: 2000 });
        req.on('error', () => {}); req.on('timeout', () => req.destroy());
        req.end(body);
        stats.shared += antigens.length;
      } catch { /* a peer that cannot be reached is simply not told — the others are */ }
    }
  }

  // one packet, start to finish — always run inside the serial queue, so counter check + append + apply are atomic
  function processPacket(bytes, source, work) {
    const hash = bytesHash(bytes);
    const seen = recognise(library, hash, null, keys.keyset);
    // belt and braces: an on-sight drop is checked against the gate. If the gate would ADMIT these bytes, an
    // antibody has turned on the body — the gate is the authority, so the packet goes on, and the Epic drops.
    if (seen.drop && decide(bytes, ctx).admit) {
      stats.autoimmune++;
      const epic = { tier: 'EPIC', name: 'Autoimmune', at: new Date(now()).toISOString(), source, packet: hexOf(bytes), family: seen.family };
      epics.push(epic); keepLoot(epic);
      delete library.exact[hash];
      log('EPIC: an antibody matched a valid packet — removed, packet admitted');
    } else if (seen.drop) {
      stats.recognised++; stats.refused++;
      const stand = standing(memory, source);
      memory = learn(memory, { family: seen.family || 'fault', print: 'recognised|' + (seen.family || 'fault'), source }).memory;
      // every attack is written down — a known one as a count (its bytes are already on file as the antigen)
      journal.record({ at: new Date(now()).toISOString(), source, stage: 'recognised', reason: 'a known attack, recognised on sight', family: seen.family || 'fault',
        print: 'recognised|' + (seen.family || 'fault'), novel: false, detail: stand === 'ALLOW' || stand === 'THROTTLE' ? 'full' : 'count', bytes, context: { hash, keyset: keys.keyset } });
      return { code: 403, body: { dropped: true, stage: 'recognised', reason: 'a known attack — dropped on sight by an exact antibody', family: seen.family } };
    }
    // THE REBOUND LAW — a source the gate already distrusts must spend compute to be looked at. We verify a token
    // in ONE hash; producing one costs ~2^bits. A legitimate client (which is never refused) owes nothing; a source
    // that has made us refuse it BLOCK+ times must pay, and the price rises with every refusal. We emit nothing back
    // at it — the attacker's own spent work becoming the price of its next attempt is the whole mechanism. (rebound.mjs)
    const bits = owed(source);
    if (bits > 0) {
      const epoch = Math.floor(now() / REBOUND_EPOCH_MS);
      const chal = challenge(epoch, source, hash);
      if (!verifyWork(chal, typeof work === 'string' ? work : null, bits, sha)) {
        stats.rebounded++;
        return { code: 402, body: { rebound: true, stage: 'rebound', reason: 'this source owes proof-of-work (' + bits + ' bits) — it has been refused ' + (reboundCount.get(source) || 0) + ' times', challenge: chal, bits, epoch } };
      }
    }
    const v = decide(bytes, ctx);
    if (!v.admit) {
      stats.refused++; charge(source);
      const exactReplay = v.stage === 'counter' && admittedHashes.has(hash);
      const a = antigen(bytes, v, source, { exactReplay });
      return { code: 403, body: { dropped: true, stage: v.stage, reason: v.reason, ...a } };
    }
    const prior = senders.get(v.msg.sender) || freshState();
    const s = judge(blocked.has(v.msg.sender) ? { ...prior, blocked: true } : prior, v.msg);
    if (!s.allow) {
      stats.refused++; charge(source);
      senders.set(v.msg.sender, s.state);                         // a BLOCK sticks; nothing else changes
      const block = s.state && s.state.blocked === true && !blocked.has(v.msg.sender);
      const a = antigen(bytes, { stage: 'behavior', reason: s.level + ' — ' + s.reason, sender: v.msg.sender }, source, { block });
      return { code: 403, body: { dropped: true, stage: 'behavior', level: s.level, reason: s.reason, ...a } };
    }
    const entry = ledger.append(bytes);                           // written and fsync'd BEFORE the app acts
    counters.set(v.msg.sender, v.msg.counter);
    senders.set(v.msg.sender, s.state);
    packets.push(bytes); admittedHashes.add(hash);
    app.apply(v.msg);
    stats.admitted++;
    const breach = referee.after(v.msg, bytes);
    if (breach) {
      stats.breaches++;
      // a zero-day: the gate let something through. The packet becomes an antigen at once, everywhere.
      const ab = mint(bytes, { hash, stage: 'replay', keyset: keys.keyset, family: 'breach' });
      library = adopt(library, [ab.exact, ab.shape].filter(Boolean)).library;
      journal.record({ at: new Date(now()).toISOString(), source, stage: 'breach', reason: breach.why, family: 'breach', print: 'breach', novel: true, detail: 'full', bytes, context: { keyset: keys.keyset, stage: 'breach' } });
      share([bytes], { now: true });
      if (sign) { const rune = mintRune({ node: nodePub, at: new Date(now()).toISOString(), seq: entry.seq, why: breach.why, packet: hexOf(bytes) }, sign); runes.push(rune); keepLoot(rune); }
      log("BREACH — the Breaker's Rune dropped: " + breach.why);
    }
    return { code: 200, body: { accepted: true, seq: entry.seq, level: s.level } };
  }

  let queue = Promise.resolve(), pending = 0;
  const serial = (fn) => {
    if (pending >= LIMITS.queue) return Promise.resolve({ code: 503, body: { dropped: true, stage: 'flood', reason: 'the queue is full — nothing was admitted' } });
    pending++;
    const p = queue.then(fn, fn).finally(() => { pending--; });
    queue = p.catch(() => {});
    return p;
  };

  function adoptShare(body, source) {
    let m;
    try { m = JSON.parse(body); } catch { return { code: 400, body: { adopted: 0, reason: 'not JSON' } }; }
    if (!m || m.v !== 1 || typeof m.from !== 'string' || !peerKeys.has(m.from) || !Array.isArray(m.antigens) || typeof m.sig !== 'string') return { code: 403, body: { adopted: 0, reason: 'not from a pinned peer' } };
    if (m.antigens.length > LIMITS.shareAntigens || !m.antigens.every((h) => typeof h === 'string' && /^(?:[0-9a-f]{2}){1,336}$/.test(h))) return { code: 400, body: { adopted: 0, reason: 'malformed antigens' } };
    let ok = false;
    try { ok = edVerify(null, Buffer.from(SHARE_DOMAIN + m.from + '|' + JSON.stringify(m.antigens)), peerKeys.get(m.from), Buffer.from(m.sig, 'hex')); } catch { ok = false; }
    if (!ok) return { code: 403, body: { adopted: 0, reason: 'the share signature does not verify' } };
    let adopted = 0;
    for (const h of m.antigens) {
      const bytes = new Uint8Array(Buffer.from(h, 'hex'));
      const v = decide(bytes, ctx);                                // re-run on THIS node's gate — never take a peer's word
      if (v.admit) continue;                                      // valid here: adopting it would be autoimmunity
      const stage = immuneStage(v);
      if (!PERMANENT.includes(stage)) continue;
      const decl = bytes.length >= 16 ? (bytes[14] << 8) | bytes[15] : null;
      const family = classify(v, { bytes, declaredLength: decl });
      const ab = mint(bytes, { hash: bytesHash(bytes), stage, keyset: keys.keyset, family });
      const r = adopt(library, [ab.exact, ab.shape].filter(Boolean));
      library = r.library;
      if (r.added) {
        adopted++;
        journal.record({ at: new Date(now()).toISOString(), source: 'peer:' + m.from.slice(0, 16), stage: v.stage, reason: 'learned from a peer, re-run here: ' + v.reason, family, print: fingerprint(family, { bytes }), novel: false, detail: 'full', bytes, context: { keyset: keys.keyset, stage, from: m.from } });
      }
    }
    stats.adoptedFromPeers += adopted;
    return { code: 200, body: { adopted } };
  }

  const server = http.createServer({ requestTimeout: 3000, headersTimeout: 2000, keepAliveTimeout: 1000, maxHeaderSize: 8192 }, async (req, res) => {
    const source = String(req.socket.remoteAddress || 'unknown');
    try {
      const url = new URL(req.url, 'http://local');
      if (req.method === 'POST' && url.pathname === '/packet') {
        if (!allow(source)) {
          stats.refused++; stats.flooded++;
          memory = learn(memory, { family: 'flood', print: 'flood|rate', source }).memory;
          floodNote(source);
          return sendJson(res, 429, { dropped: true, stage: 'flood', reason: 'too many requests from this address — nothing was admitted' });
        }
        const body = await readBody(req, MAX_PACKET);
        if (!body.ok) {
          stats.refused++;
          const a = antigen(new Uint8Array(0), { stage: 'http', reason: body.why }, source);
          return sendJson(res, 400, { dropped: true, stage: 'http', reason: body.why, ...a });
        }
        const work = typeof req.headers['x-rebound'] === 'string' ? req.headers['x-rebound'] : null;
        const r = await serial(() => processPacket(body.bytes, source, work));
        return sendJson(res, r.code, r.body);
      }
      if (req.method === 'POST' && url.pathname === '/immune/share') {
        const body = await readBody(req, LIMITS.shareBytes);
        if (!body.ok) return sendJson(res, 400, { adopted: 0, reason: body.why });
        const r = await serial(() => adoptShare(Buffer.from(body.bytes).toString('utf8'), source));
        return sendJson(res, r.code, r.body);
      }
      if (req.method !== 'GET') return sendJson(res, 405, { error: 'method not allowed' });
      if (url.pathname === '/health') return sendJson(res, 200, { ok: true, node: nodePub, ledger: ledger.length, journal: journal.length });
      if (url.pathname === '/pubkeys') return sendJson(res, 200, { pubkeys: o.pubkeys, keyset: keys.keyset, node: nodePub });
      if (url.pathname === '/state') return sendJson(res, 200, { state: app.state(), applied: app.log.length });
      if (url.pathname === '/referee') {
        const fold = referee.fold(app, packets);
        const b = referee.breaches;
        return sendJson(res, 200, { breached: b.length > 0, breaches: b, checked: referee.checked, foldMatches: fold, ledger: ledger.length });
      }
      if (url.pathname === '/immune') {
        return sendJson(res, 200, {
          stats, events: memory.events, novel: memory.novel, families: memory.families,
          sources: Object.fromEntries(Object.entries(memory.sources).map(([s, n]) => [s, { refusals: n, standing: standing(memory, s) }])),
          antibodies: { exact: Object.keys(library.exact).length, shapes: library.shapes.length },
          rebound: { epochMs: REBOUND_EPOCH_MS, owed: Object.fromEntries([...reboundCount].map(([src, n]) => [src, { refusals: n, bits: difficultyFor(n) }])) },
          fingerprints: Object.keys(memory.prints).length, peers: peers.map((p) => p.url), journal: journal.length,
        });
      }
      if (url.pathname === '/loot') {
        const ql = questLog(journal.tail(0, 5000));
        return sendJson(res, 200, { legendary: runes, epic: epics, shards: ql.shards, quests: ql.quests,
          dropRates: { legendary: runes.length + ' of ' + (stats.admitted + stats.refused) + ' packets', epic: epics.length + ' of ' + stats.recognised + ' on-sight drops' } });
      }
      if (url.pathname === '/journal') {
        const since = Math.max(0, Number(url.searchParams.get('since')) || 0), limit = Math.min(500, Math.max(1, Number(url.searchParams.get('limit')) || 100));
        return sendJson(res, 200, { records: journal.tail(since, limit), length: journal.length });
      }
      return sendJson(res, 404, { error: 'not found' });
    } catch {
      return sendJson(res, 500, { dropped: true, stage: 'error', reason: 'the node failed closed' });
    }
  });
  server.maxConnections = 256;
  server.maxRequestsPerSocket = 1000;
  await new Promise((r) => server.listen(o.port || 0, host, r));
  const port = server.address().port;
  log('break-it node on http://' + host + ':' + port + ' — ledger ' + ledger.length + ', journal ' + journal.length + ', antibodies ' + library.size);
  return {
    port, url: 'http://' + host + ':' + port, node: nodePub,
    stats, get library() { return library; }, get memory() { return memory; }, referee, app,
    close: () => new Promise((r) => { if (flushTimer) clearTimeout(flushTimer); server.close(() => { ledger.close(); journal.close(); r(); }); server.closeAllConnections?.(); }),
  };
}
