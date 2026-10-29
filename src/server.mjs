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
//   POST /immune/share    a peer's signed antigens — a LIGHT packet (vendor/light, src/share.mjs), checked at the
//                         LIGHT door before its body is decoded; or JSON from a node that predates LIGHT — and in
//                         both cases adopted only after this node's own gate re-runs every antigen
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
import { makeReferee, grammarOk } from './referee.mjs';
import { keyTable, signWith, rawPublic, publicFromRaw } from './keys.mjs';
import { mintRune, questLog } from './loot.mjs';
import { difficultyFor, challenge, verifyWork } from './rebound.mjs';
import { appendFileSync, readFileSync as readText, existsSync as exists } from 'node:fs';
import { verify as edVerify } from 'node:crypto';
import { prepare as lightPrepare, finish as lightFinish, open as lightOpen, KINDS as LIGHT_KINDS } from '../vendor/light/packet.mjs';
import { meshOrder, antigensToBytes, bytesToAntigens, nextCounter } from './share.mjs';
import { evidence, door } from './patch.mjs';
import { settings as tarpitSettings, decide as tarpitDecide, ticks as tarpitTicks } from './tarpit.mjs';

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

/** A held refusal (tarpit.mjs): sendJson's headers, its length counting the spaces; one inert space a tick, then the
 *  refusal exactly as sendJson would have sent it. If the source goes away first, the hold ends there: nothing more is
 *  written and nothing is kept for it. done(dripped, finished) runs once. */
function holdJson(res, code, body, t, done) {
  const text = JSON.stringify(body), n = tarpitTicks(t);
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-length': n + Buffer.byteLength(text) });
  let dripped = 0, over = false;
  const end = (finished) => { if (over) return; over = true; clearInterval(timer); done(dripped, finished); };
  const timer = setInterval(() => {
    if (dripped < n) { res.write(' '); dripped++; }
    if (dripped >= n) { res.end(text); end(true); }
  }, t.DRIP_MS);
  res.on('close', () => end(false));
  return { stop: () => { end(false); res.destroy(); } };
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
 * peers [{ url, key (hex) }], now () → ms (injected so tests control time), log,
 * shareAs 'light' (default: shares are LIGHT packets) | 'json' (as nodes shared before LIGHT) }
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
  // the LIGHT mesh: every node sorts the pinned keys (its own and its peers') the same way, and a node's place in that
  // order is the sender byte on its shares; a share counter only moves forward, per sender
  const mesh = meshOrder(nodePub ? [nodePub, ...peers.map((p) => p.key)] : []) || [];
  const meIndex = nodePub ? mesh.indexOf(nodePub) : -1;
  const shareAs = o.shareAs === 'json' ? 'json' : 'light';
  const shareSeen = new Map();
  let shareCounter = 0n;

  // ── state, rebuilt from the ledger: every packet re-run through the gate — a ledger the gate refuses will not start
  const ledger = openChain(o.ledgerPath);
  if (!ledger.ok) throw new Error(ledger.reason);
  const counters = new Map(), senders = new Map(), app = makeApp(), referee = makeReferee(), packets = [], admittedHashes = new Set();
  const ctx = { keyFor: keys.keyFor, verify: keys.verify, lastCounter: (s) => counters.get(s) || 0n };
  // the herd patch (patch.mjs): off until a zero-day is PROVEN on this node — by its own referee, by its own ledger, or by
  // re-checking a peer's evidence itself. Then the referee's independent grammar is a stage of this node's door.
  const herdPatch = o.herdPatch !== false;
  // the tarpit (tarpit.mjs) is off unless the operator switches it on: o.tarpit true for the defaults, or an object of settings
  const tarpit = o.tarpit ? tarpitSettings(o.tarpit === true ? null : o.tarpit) : null;
  const holds = new Set();
  let patch = { on: false, by: null, at: null, why: null };
  const proven = (bytes, by, why) => { if (!herdPatch || patch.on) return false; patch = { on: true, by, at: new Date(now()).toISOString(), why }; log('PATCHED — the referee’s grammar is now a door stage: ' + why); return true; };
  // the node’s whole door: the gate, then (once patched) the independent grammar — what “would this node admit it” means
  // the gate accepts a packet's FORM when it admits it or refuses it only for its counter (stale): size, magic, schema,
  // sender and signature all passed. A zero-day shared after this node moved on is still evidence; a forgery never is.
  const accepts = (v) => v.admit === true || v.stage === 'counter';
  const doorOf = (bytes) => { const v = decide(bytes, ctx); if (!v.admit) return v; const shut = door(patch.on, grammarOk(bytes)); return shut ? { admit: false, stage: shut.stage, reason: shut.reason } : v; };
  for (const e of ledger.entries) {
    const bytes = new Uint8Array(Buffer.from(e.packet, 'hex'));
    const v = decide(bytes, ctx);
    if (!v.admit) { ledger.close(); throw new Error('the ledger holds a packet the gate refuses (entry ' + e.seq + ': ' + v.reason + ') — refusing to start'); }
    const s = judge(senders.get(v.msg.sender) || freshState(), v.msg);
    senders.set(v.msg.sender, s.state);
    counters.set(v.msg.sender, v.msg.counter);
    app.apply(v.msg); referee.after(v.msg, bytes); packets.push(bytes); admittedHashes.add(bytesHash(bytes));
    if (evidence(true, grammarOk(bytes))) proven(bytes, 'ledger', 'its own ledger holds a packet its gate admitted and the independent grammar rejects (entry ' + e.seq + ')');
  }

  // ── immunity, rebuilt from the journal: memory from every record; antibodies re-minted by re-running each antigen
  const journal = openJournal(o.journalPath);
  let memory = emptyMemory(), library = emptyLibrary();
  const relearn = (bytes, family) => {
    const v = doorOf(bytes);
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
  // the patch's evidence, written down; on restart it is re-checked here, never trusted (patch.mjs)
  const keepPatch = (bytes) => journal.record({ at: new Date(now()).toISOString(), source: patch.by, stage: 'patch', reason: patch.why, family: 'zero-day', print: 'patch|zero-day', novel: true, detail: 'full', bytes, context: { keyset: keys.keyset } });
  for (const r of journal.records) {
    if (r.stage !== 'patch' || !r.bytes || r.bytes.length !== r.size * 2) continue;
    const b = new Uint8Array(Buffer.from(r.bytes, 'hex'));
    if (evidence(accepts(decide(b, ctx)), grammarOk(b))) proven(b, 'journal', 'its own journal’s evidence, re-checked at start: ' + r.reason);
  }
  for (const r of journal.records) {
    memory = learn(memory, { family: r.family, print: r.print, source: r.source }).memory;
    if (r.stage === 'behavior' && r.context && r.context.blocked === true && Number.isInteger(r.context.sender)) blocked.add(r.context.sender);
    if (GATE_REFUSALS.has(r.stage) && typeof r.source === 'string' && !r.source.startsWith('peer:')) reboundCount.set(r.source, (reboundCount.get(r.source) || 0) + 1);
    if (r.detail === 'full' && r.bytes && r.size <= MAX_PACKET && r.bytes.length === r.size * 2) relearn(new Uint8Array(Buffer.from(r.bytes, 'hex')), r.family);
  }

  const stats = { tarpitHeld: 0, tarpitFinished: 0, tarpitAbandoned: 0, tarpitFull: 0, tarpitDripped: 0, admitted: 0, refused: 0, recognised: 0, breaches: 0, shared: 0, shareDropped: 0, adoptedFromPeers: 0, autoimmune: 0, flooded: 0, rebounded: 0, patchRefused: 0, zeroDayEvidence: 0,
    light: { sent: 0, received: 0, admitted: 0, decoded: 0, refused: {} } };   // LIGHT shares: decoded counts every time the door let the decoder run
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
    const list = outbox.splice(0);
    let body, type;
    if (shareAs === 'light' && meIndex >= 0) {
      shareCounter = nextCounter(shareCounter, now());
      const p = lightPrepare({ sender: meIndex, counter: shareCounter, kind: LIGHT_KINDS.BYTES, bytes: antigensToBytes(list), dictId: 0 });
      const f = p.ok ? lightFinish(p.unsigned, sign(p.signed)) : p;
      if (!f.ok) return;
      body = Buffer.from(f.bytes); type = 'application/x-light';
      stats.light.sent++;
    } else {
      const antigens = list.map((b) => hexOf(b));
      body = Buffer.from(JSON.stringify({ v: 1, from: nodePub, antigens, sig: hexOf(sign(Buffer.from(SHARE_DOMAIN + nodePub + '|' + JSON.stringify(antigens)))) }));
      type = 'application/json';
    }
    for (const p of peers) {
      try {
        const u = new URL('/immune/share', p.url);
        const req = http.request(u, { method: 'POST', headers: { 'content-type': type, 'content-length': body.length }, timeout: 2000 });
        req.on('error', () => {}); req.on('timeout', () => req.destroy());
        req.end(body);
        stats.shared += list.length;
      } catch { /* a peer that cannot be reached is simply not told — the others are */ }
    }
  }

  // one packet, start to finish — always run inside the serial queue, so counter check + append + apply are atomic
  function processPacket(bytes, source, work) {
    const hash = bytesHash(bytes);
    const seen = recognise(library, hash, null, keys.keyset);
    // belt and braces: an on-sight drop is checked against the gate. If the gate would ADMIT these bytes, an
    // antibody has turned on the body — the gate is the authority, so the packet goes on, and the Epic drops.
    if (seen.drop && doorOf(bytes).admit) {
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
    const v = doorOf(bytes);
    if (!v.admit) {
      stats.refused++; charge(source);
      if (v.reason === door(true, false).reason) stats.patchRefused++;
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
      if (evidence(true, grammarOk(bytes)) && proven(bytes, 'self', 'its own referee: ' + breach.why)) keepPatch(bytes);
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

  // a share arrives: a LIGHT packet goes through the LIGHT door, anything else is read as the JSON shares of before
  function adoptShare(bytes) {
    if (bytes.length >= 4 && bytes[0] === 0x4c && bytes[1] === 0x47 && bytes[2] === 0x54 && bytes[3] === 0x31) return adoptLight(bytes);
    return adoptJson(Buffer.from(bytes).toString('utf8'));
  }
  function adoptLight(bytes) {
    stats.light.received++;
    const r = lightOpen(bytes, {
      keyFor: (s) => (s !== meIndex && mesh[s] && peerKeys.get(mesh[s])) || null,
      verify: (m, sig, key) => { try { return edVerify(null, Buffer.from(m), key, Buffer.from(sig)); } catch { return false; } },
      dictFor: () => null, lastCounter: (s) => shareSeen.get(s) || 0n, maxPacket: LIMITS.shareBytes, maxBody: LIMITS.shareBytes,
    });
    if (r.decoded) stats.light.decoded++;
    const no = (code, stage, reason) => { stats.light.refused[stage] = (stats.light.refused[stage] || 0) + 1; return { code, body: { adopted: 0, stage, reason } }; };
    if (!r.admit) return no(403, r.stage, r.reason);
    shareSeen.set(r.sender, r.counter);
    if (r.kind !== LIGHT_KINDS.BYTES) return no(400, 'body', 'a share body is antigen bytes');
    const parsed = bytesToAntigens(r.bytes, LIMITS.shareAntigens);
    if (!parsed.ok) return no(400, 'body', parsed.why);
    stats.light.admitted++;
    return { code: 200, body: { adopted: adoptAntigens(parsed.list, mesh[r.sender]) } };
  }
  function adoptJson(body) {
    let m;
    try { m = JSON.parse(body); } catch { return { code: 400, body: { adopted: 0, reason: 'not JSON' } }; }
    if (!m || m.v !== 1 || typeof m.from !== 'string' || !peerKeys.has(m.from) || !Array.isArray(m.antigens) || typeof m.sig !== 'string') return { code: 403, body: { adopted: 0, reason: 'not from a pinned peer' } };
    if (m.antigens.length > LIMITS.shareAntigens || !m.antigens.every((h) => typeof h === 'string' && /^(?:[0-9a-f]{2}){1,336}$/.test(h))) return { code: 400, body: { adopted: 0, reason: 'malformed antigens' } };
    let ok = false;
    try { ok = edVerify(null, Buffer.from(SHARE_DOMAIN + m.from + '|' + JSON.stringify(m.antigens)), peerKeys.get(m.from), Buffer.from(m.sig, 'hex')); } catch { ok = false; }
    if (!ok) return { code: 403, body: { adopted: 0, reason: 'the share signature does not verify' } };
    return { code: 200, body: { adopted: adoptAntigens(m.antigens.map((h) => new Uint8Array(Buffer.from(h, 'hex'))), m.from) } };
  }
  // every antigen re-run on THIS node's gate — never take a peer's word — and kept only where the gate refuses it
  function adoptAntigens(list, from) {
    let adopted = 0;
    for (const bytes of list) {
      let v = decide(bytes, ctx);                                  // re-run on THIS node's gate — never take a peer's word
      if (evidence(accepts(v), grammarOk(bytes)) && proven(bytes, 'peer:' + from.slice(0, 16), 'a peer’s antigen re-checked here: this gate accepts its form, the independent grammar rejects it')) { stats.zeroDayEvidence++; keepPatch(bytes); }
      if (v.admit) v = doorOf(bytes);                             // once patched, the door refuses what the grammar rejects
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
        journal.record({ at: new Date(now()).toISOString(), source: 'peer:' + from.slice(0, 16), stage: v.stage, reason: 'learned from a peer, re-run here: ' + v.reason, family, print: fingerprint(family, { bytes }), novel: false, detail: 'full', bytes, context: { keyset: keys.keyset, stage, from } });
      }
    }
    stats.adoptedFromPeers += adopted;
    return adopted;
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
        // the source's refusals BEFORE this packet, read in the queue: a source is confirmed once it had been refused CONFIRM times
        let prior = 0;
        const r = await serial(async () => { prior = reboundCount.get(source) || 0; return processPacket(body.bytes, source, work); });
        // THE TARPIT — after the gate has answered, outside the serial queue: only a confirmed attacker's permanent refusal is
        // held, and only while there is room; everything else, every admission first, goes out at once (tarpit.mjs)
        const d = tarpit ? tarpitDecide(r.code, r.body && r.body.stage, prior, holds.size, tarpit) : null;
        if (d && !d.hold && r.code === 403 && /full/.test(d.why)) stats.tarpitFull++;
        if (!d || !d.hold) return sendJson(res, r.code, r.body);
        stats.tarpitHeld++;
        const h = holdJson(res, r.code, r.body, tarpit, (dripped, finished) => { holds.delete(h); stats.tarpitDripped += dripped; if (finished) stats.tarpitFinished++; else stats.tarpitAbandoned++; });
        holds.add(h);
        return;
      }
      if (req.method === 'POST' && url.pathname === '/immune/share') {
        const body = await readBody(req, LIMITS.shareBytes);
        if (!body.ok) return sendJson(res, 400, { adopted: 0, reason: body.why });
        const r = await serial(() => adoptShare(body.bytes));
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
          stats, patch, events: memory.events, novel: memory.novel, families: memory.families,
          sources: Object.fromEntries(Object.entries(memory.sources).map(([s, n]) => [s, { refusals: n, standing: standing(memory, s) }])),
          antibodies: { exact: Object.keys(library.exact).length, shapes: library.shapes.length },
          tarpit: tarpit ? { ...tarpit, holding: holds.size, held: stats.tarpitHeld, finished: stats.tarpitFinished, abandoned: stats.tarpitAbandoned, full: stats.tarpitFull, dripped: stats.tarpitDripped } : null,
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
    stats, get holding() { return holds.size; }, get patch() { return patch; }, get library() { return library; }, get memory() { return memory; }, referee, app,
    close: () => new Promise((r) => { if (flushTimer) clearTimeout(flushTimer); for (const h of [...holds]) h.stop(); server.close(() => { ledger.close(); journal.close(); r(); }); server.closeAllConnections?.(); }),
  };
}
