// ════════════════════════════════════════════════════════════════
// core/node.mjs — a cell of the one body. Organ 2 of the shared foundation.
//
// A node is one identity (identity.mjs) carrying, together:
//   the LIGHT door      every byte it hears passes vendor/light/packet.mjs before one byte of a body is decoded, and
//                       everything it says is a LIGHT packet it signed;
//   the immune memory   every refusal becomes an antibody (antibody.mjs); a peer's antibodies are adopted only after
//                       re-running each on this node's own door (vendor/immune/subscribe.mjs);
//   a budget            every ask is authorised by its wallet (vendor/wallet/wallet.mjs) before a packet exists,
//                       and carries the signed token, so a node cannot ask past what it was given;
//   geometric memory    what it heard and did, provenance-tagged, recalled by resemblance (vendor/memory), kept as a
//                       LIGHT vault;
//   the contribution    every verified answer it uses is a signed value record in the contribution ledger
//   record              (vendor/ledger/contrib.mjs), counted only where this node can re-check the proof;
//   its couplings       a weight per peer and skill that grows when an answer's proof checks and shrinks when it does
//                       not — asks go to the strongest live link, and links below the floor are pruned. An ask nobody
//                       answers can be expired (Phase 3): it counts as a failed answer, so a node that died is routed
//                       around;
//   its notes           what it saw itself, shared with the mesh (Phase 3b): 'silent' when an ask of its own expired,
//                       'lied' when a holder answered VERIFIED with a receipt its check refused, carrying that holder's
//                       own signed answer. A peer's note moves nothing on the peer's word: a 'lied' note counts only if
//                       the packet is the accused's own signed answer and fails this node's own check; a 'silent' note
//                       makes the holder quiet here (asks go elsewhere) and sends it a probe, and only a probe that
//                       expires unanswered counts. A quiet holder is live again the moment it is heard from. And an
//                       asker tries every live holder once before it prefers one (untried first), so a liar that
//                       ranks last is still found. routing: 'greedy' keeps Phase 3's routing, which ignores both;
//   shared state        documents every member keeps a copy of, merged by the CRDT law (vendor/sync/crdt.mjs: last
//                       writer wins by Lamport time), carried as signed LIGHT packets from pinned peers only (Phase 3).
//
// Pinning is the only way a peer is trusted: its card is self-signed (it holds the key it names), but whether to trust
// that key is the owner's decision, made out of band. Transport is not here: hear() and the ask/share verbs return
// bytes and the caller carries them (in one process, between processes, over BroadcastChannel or WebRTC).
//
// Powered by the Konomi architecture, created by Thomas Frumkin.
// ════════════════════════════════════════════════════════════════
import { prepare, finish, open, frame, KINDS, MAX_PACKET } from './vendor/light/packet.mjs';
import { sha256 } from './vendor/light/sha256.mjs';
import { pack, unpack } from './vendor/light/vault.mjs';
import { makeBundle, verifyBundle, fromHex, toHex } from './vendor/immune/exchange.mjs';
import { adoptAntigens } from './vendor/immune/subscribe.mjs';
import * as W from './vendor/wallet/wallet.mjs';
import * as L from './vendor/ledger/contrib.mjs';
import { emptyDoc, setKey, merge, validDoc, valueOf } from './vendor/sync/crdt.mjs';
import { FallRemember } from './vendor/memory/fall-remember.mjs';
import { mint, adopt, recognise, emptyLibrary, hashOf, familyOf, PERMANENT } from './antibody.mjs';
import { verifyBytes, keysetOf, walletCrypto, slotOf, hex, unhex } from './identity.mjs';

export const SCHEMA = 'fall-kit.node.v1';
export const LINK = Object.freeze({ START: 500000, MAX: 1000000, FLOOR: 50000, GAIN: 4, ABSTAIN: 16, FAIL: 2 });
export const DEFAULT_BUDGET = 10000;   // asks. Always finite: JSON has no infinity, so an unlimited budget cannot travel in a token
export const MAX_PENDING = 256, MAX_ANTIGENS = 64, MAX_ANTIGEN_BYTES = 2048, MAX_SKILLS = 32;
// the notes a node keeps of its own and carries in one message; and the notes it remembers taking: every member's last
// MAX_NOTES, for a mesh of 32 members (the most a mesh genesis names). One forgotten is at worst taken again: a silence
// probed twice, or a proven lie counted twice against the one who signed it — never a cost to an honest node
export const MAX_NOTES = 16, MAX_NOTED = MAX_NOTES * 32;
export const ROUTING = Object.freeze(['shared', 'greedy']);
const ID = /^[a-z0-9][a-z0-9:._-]{0,95}$/, SKILL = /^[a-z0-9][a-z0-9-]{0,31}$/, HEX64 = /^[0-9a-f]{64}$/, HEX = /^(?:[0-9a-f]{2})+$/;
const isObj = (x) => Object.prototype.toString.call(x) === '[object Object]';
const has = (o, k) => isObj(o) && Object.prototype.hasOwnProperty.call(o, k);

// ── the law (pure) ────────────────────────────────────────────────────────────────────────────────────────────────

/** A coupling's next weight after one outcome. Whole parts of a million, always within [0, MAX]. */
export function hebb(w, outcome) {
  const x = Number.isSafeInteger(w) ? Math.max(0, Math.min(LINK.MAX, w)) : LINK.START;
  if (outcome === 'verified') return x + Math.floor((LINK.MAX - x) / LINK.GAIN);
  if (outcome === 'abstain') return x - Math.floor(x / LINK.ABSTAIN);
  if (outcome === 'failed') return x - Math.floor(x / LINK.FAIL);
  return x;
}

/**
 * Which peer an ask for this skill goes to. peers = [{ id, skills: [], weight(skill), tried?(skill), quiet?(skill) }]
 * → { id, weight, live, untried } | null. A link is live at or above the floor, unless its peer is quiet (it went
 * silent and has not been heard from since). Among live links one this asker has never tried comes first, then the
 * strongest, then the smaller id. With no live link the strongest of the rest is tried, marked not live, so a pruned or
 * quiet peer is asked only when no one else holds the skill. A peer that does not say whether it was tried or is quiet
 * counts as tried and not quiet: that is Phase 3's routing, the strongest live link alone.
 */
export function choose(peers, skill) {
  let best = null;
  for (const p of Array.isArray(peers) ? peers : []) {
    if (!isObj(p) || typeof p.id !== 'string' || !Array.isArray(p.skills) || !p.skills.includes(skill)) continue;
    const given = typeof p.weight === 'function' ? p.weight(skill) : LINK.START, w = Number.isSafeInteger(given) ? given : LINK.START;   // junk is a fresh link, as in hebb
    const live = w >= LINK.FLOOR && !(typeof p.quiet === 'function' && p.quiet(skill) === true);
    const untried = live && typeof p.tried === 'function' && p.tried(skill) === false;
    const better = best === null || (live && !best.live) || (live === best.live && ((untried && !best.untried) || (untried === best.untried && (w > best.weight || (w === best.weight && p.id < best.id)))));
    if (better) best = { id: p.id, weight: w, live, untried };
  }
  return best;
}

/** A message inside an admitted packet, checked for shape. → { ok, t, ... } | { ok: false, why }. Pure, total. */
export function readMessage(v) {
  if (!isObj(v) || typeof v.t !== 'string') return { ok: false, why: 'not a foundation message' };
  if (typeof v.to !== 'string' || !HEX64.test(v.to)) return { ok: false, why: 'a message names the node it is for' };
  if (v.t === 'ask') {
    if (typeof v.id !== 'string' || !ID.test(v.id)) return { ok: false, why: 'an ask names its id' };
    if (typeof v.skill !== 'string' || !SKILL.test(v.skill)) return { ok: false, why: 'an ask names a skill' };
    if (!has(v, 'input')) return { ok: false, why: 'an ask carries its input' };
    if (!isObj(v.token)) return { ok: false, why: 'an ask carries its budget token' };
    return { ok: true, t: 'ask', to: v.to, id: v.id, skill: v.skill, input: v.input, token: v.token };
  }
  if (v.t === 'answer') {
    if (typeof v.id !== 'string' || !ID.test(v.id)) return { ok: false, why: 'an answer names the ask it answers' };
    if (typeof v.skill !== 'string' || !SKILL.test(v.skill)) return { ok: false, why: 'an answer names the skill' };
    if (!isObj(v.answer) || (v.answer.verdict !== 'VERIFIED' && v.answer.verdict !== 'ABSTAIN')) return { ok: false, why: 'an answer is VERIFIED or ABSTAIN' };
    return { ok: true, t: 'answer', to: v.to, id: v.id, skill: v.skill, answer: v.answer };
  }
  if (v.t === 'antibody') return isObj(v.bundle) ? { ok: true, t: 'antibody', to: v.to, bundle: v.bundle } : { ok: false, why: 'an antibody message carries a bundle' };
  if (v.t === 'ledger') return Array.isArray(v.log) ? { ok: true, t: 'ledger', to: v.to, log: v.log } : { ok: false, why: 'a ledger message carries a log' };
  if (v.t === 'sync') return validDoc(v.doc) ? { ok: true, t: 'sync', to: v.to, doc: v.doc } : { ok: false, why: 'a sync message carries a document' };
  if (v.t === 'notes') return Array.isArray(v.notes) && v.notes.length >= 1 && v.notes.length <= MAX_NOTES ? { ok: true, t: 'notes', to: v.to, notes: v.notes } : { ok: false, why: 'a notes message carries 1 to ' + MAX_NOTES + ' notes' };
  if (v.t === 'probe' || v.t === 'pong') return typeof v.id === 'string' && ID.test(v.id) ? { ok: true, t: v.t, to: v.to, id: v.id } : { ok: false, why: 'a ' + v.t + ' names its id' };
  return { ok: false, why: 'message type ' + String(v.t).slice(0, 24) + ' is not spoken here' };
}

/** One note inside a notes message, checked for shape. → { ok, kind, holder, skill, job[, packet] } | { ok: false, why }. Pure, total. */
export function readNote(x) {
  if (!isObj(x) || (x.kind !== 'silent' && x.kind !== 'lied')) return { ok: false, why: 'a note is silent or lied' };
  if (typeof x.holder !== 'string' || !HEX64.test(x.holder)) return { ok: false, why: 'a note names the holder it is about' };
  if (typeof x.skill !== 'string' || !SKILL.test(x.skill)) return { ok: false, why: 'a note names a skill' };
  if (typeof x.job !== 'string' || !ID.test(x.job)) return { ok: false, why: 'a note names the ask it is about' };
  if (x.kind === 'silent') return { ok: true, kind: 'silent', holder: x.holder, skill: x.skill, job: x.job };
  if (typeof x.packet !== 'string' || x.packet.length > 2 * MAX_ANTIGEN_BYTES || !HEX.test(x.packet)) return { ok: false, why: 'a lied note carries the answer packet, in hex, up to ' + MAX_ANTIGEN_BYTES + ' bytes' };
  return { ok: true, kind: 'lied', holder: x.holder, skill: x.skill, job: x.job, packet: x.packet };
}

/** JSON with sorted keys: one text for one value, so a digest of it is stable across the wire. */
export function stableJson(x) {
  if (Array.isArray(x)) return '[' + x.map(stableJson).join(',') + ']';
  if (isObj(x)) return '{' + Object.keys(x).sort().map((k) => JSON.stringify(k) + ':' + stableJson(x[k])).join(',') + '}';
  const s = JSON.stringify(x);
  return s === undefined ? 'null' : s;
}
export const digestOf = (x) => hex(sha256(new TextEncoder().encode(stableJson(x))));
export const assetOf = (id) => 'node:' + String(id).slice(0, 16);
/** An ISO moment in whole seconds, UTC — the ledger's form. */
export const iso = (d) => (d instanceof Date && Number.isFinite(d.getTime()) ? d.toISOString().slice(0, 19) + 'Z' : '1970-01-01T00:00:00Z');

/** The generic receipt check: a receipt whose receiptHash re-hashes from its own fields (tamper-evident). */
export function receiptHolds(answer) {
  const r = isObj(answer) && isObj(answer.receipt) ? answer.receipt : null;
  if (r === null || typeof r.receiptHash !== 'string') return false;
  const { receiptHash, ...core } = r;
  return hex(sha256(new TextEncoder().encode(JSON.stringify(core)))) === receiptHash;
}

/** Does a LIGHT vault hold exactly these files? files = [{ path, sha256 }]. Pure, total. */
export function vaultMatches(bytes, files) {
  const u = unpack(bytes);
  if (!u.ok || !Array.isArray(files) || u.entries.length !== files.length) return false;
  return u.entries.every((e, i) => isObj(files[i]) && e.path === files[i].path && hex(sha256(e.bytes)) === files[i].sha256);
}

/** A card, checked for shape and self-signature. → { ok, card } | { ok: false, why }. */
export async function readCard(c) {
  if (!isObj(c) || c.schema !== SCHEMA) return { ok: false, why: 'not a ' + SCHEMA + ' card' };
  if (typeof c.id !== 'string' || !HEX64.test(c.id)) return { ok: false, why: 'a card names a 32-byte key' };
  if (typeof c.name !== 'string' || c.name.length === 0 || c.name.length > 64) return { ok: false, why: 'a card names its node' };
  if (typeof c.wallet !== 'string' || c.wallet.length < 40 || c.wallet.length > 48) return { ok: false, why: 'a card names its wallet key' };
  if (c.slot !== slotOf(unhex(c.id))) return { ok: false, why: 'the card’s slot is not its key’s' };
  if (!Array.isArray(c.skills) || c.skills.length > MAX_SKILLS || !c.skills.every((s) => typeof s === 'string' && SKILL.test(s))) return { ok: false, why: 'a card lists up to ' + MAX_SKILLS + ' skills' };
  if (c.genome !== null && !isObj(c.genome)) return { ok: false, why: 'a genome is a record, or null' };
  if (typeof c.sig !== 'string' || !/^[0-9a-f]{128}$/.test(c.sig)) return { ok: false, why: 'a card is signed' };
  const { sig, release, ...body } = c;
  if (!(await verifyBytes(c.id, new TextEncoder().encode(stableJson(body)), unhex(sig)))) return { ok: false, why: 'the card is not signed by the key it names' };
  return { ok: true, card: c, body };
}

// ── a node ────────────────────────────────────────────────────────────────────────────────────────────────────────

/**
 * opts: { name, identity (identity.mjs makeIdentity), skills: { skill: async (input) => answer }, checks: { skill:
 * (answer) => bool | Promise }, budget (whole asks; default DEFAULT_BUDGET), genesis (a signed contribution-ledger genesis, or none), genome, clock,
 * docs (the shared documents this node keeps; default ['mesh']), routing ('shared', the default, or 'greedy': Phase 3's) }.
 */
export async function createNode(opts) {
  const o = isObj(opts) ? opts : {};
  const me = o.identity;
  if (!me || typeof me.id !== 'string' || typeof me.sign !== 'function') throw new TypeError('a node needs an identity');
  const name = typeof o.name === 'string' && o.name ? o.name.slice(0, 64) : 'node';
  const skills = isObj(o.skills) ? o.skills : {}, checks = isObj(o.checks) ? o.checks : {};
  const clock = typeof o.clock === 'function' ? o.clock : () => new Date();
  const routing = o.routing === 'greedy' ? 'greedy' : 'shared';
  const wc = walletCrypto(me);
  const g = await W.genesis(wc, { caps: ['ask'], budget: Number.isSafeInteger(o.budget) && o.budget >= 0 ? o.budget : DEFAULT_BUDGET });
  const st = {
    wallet: g.wallet, sk: g.sk, out: 0n, asks: 0, probes: 0,
    notes: [], noted: new Set(), probing: new Map(),
    peers: new Map(), pending: new Map(), served: new Map(), used: new Map(), retired: new Map(),
    library: emptyLibrary(), antigens: [], memory: new FallRemember(), ledger: L.empty(),
    seen: { admitted: 0, refused: 0, recognised: 0, sent: 0 },
    docs: new Map((Array.isArray(o.docs) ? o.docs : ['mesh']).map(emptyDoc).filter(Boolean).map((d) => [d.docId, d])),
  };

  const body = { schema: SCHEMA, id: me.id, wallet: me.wallet.pk, name, slot: me.slot, skills: Object.keys(skills).filter((s) => SKILL.test(s)).sort().slice(0, MAX_SKILLS), genome: isObj(o.genome) ? o.genome : null };
  const sig = hex(await me.sign(new TextEncoder().encode(stableJson(body))));
  const releaseEntry = async () => {
    const r = await L.sign(me.ledgerKeys, { type: 'release', asset: assetOf(me.id), at: iso(clock()), form: 'node', lineage: [], proofs: [{ kind: 'card', ref: me.id, digest: digestOf(body) }] });
    return r.ok ? r.entry : null;
  };
  const card = { ...body, sig, release: null };

  // what this node can re-check, and so what it will record: its own card and its peers' (releases); the answers it
  // used and the answers it gave (values). Anything else is refused by name, never counted.
  const gate = async (entry) => {
    if (entry.type === 'release') {
      const c = entry.by === me.id ? body : st.peers.has(entry.by) ? st.peers.get(entry.by).body : null;
      if (c === null) return { ok: false, why: 'this node holds no card for that key' };
      const ok = entry.asset === assetOf(entry.by) && entry.form === 'node' && entry.proofs.length === 1 && entry.proofs[0].digest === digestOf(c);
      return ok ? { ok: true } : { ok: false, why: 'the release does not match the card this node holds' };
    }
    if (entry.type === 'value') {
      const p = entry.proofs[0];
      if (entry.by === me.id) {
        const u = st.used.get(entry.job);
        return u && p.digest === u.digest && entry.asset === assetOf(u.peer) ? { ok: true } : { ok: false, why: 'this node did not use that answer' };
      }
      if (entry.asset === assetOf(me.id)) {
        const s = st.served.get(entry.job);
        return s && s.to === entry.by && p.digest === s.digest ? { ok: true } : { ok: false, why: 'this node did not give that answer' };
      }
      return { ok: false, why: 'this node can re-check only work it did or used' };
    }
    return { ok: false, why: 'not a record this node gates' };
  };
  const record = async (entry) => {
    const r = await L.record(st.ledger, entry, { gate });   // the ledger refuses what is not its to count
    if (r.ok) st.ledger = r.ledger;
    return r.ok;
  };
  if (isObj(o.genesis)) await record(o.genesis);
  card.release = await releaseEntry();
  await record(card.release);

  const keyset = () => keysetOf([...st.peers.keys()]);
  const remember = (text, meta) => { st.memory.store({ text, meta: { ...meta, at: iso(clock()) } }); };

  // ── speaking ──
  async function say(to, value) {
    st.out += 1n;
    const p = prepare({ sender: me.slot, counter: st.out, kind: KINDS.JSON, value: { ...value, to }, dictId: 0 });
    if (!p.ok) return null;
    const f = finish(p.unsigned, await me.sign(p.signed));
    if (f.ok) st.seen.sent++;
    return f.ok ? f.bytes : null;
  }

  // ── the door, without side effects: who sent these bytes, and would this node admit them now? ──
  async function verdictOf(bytes) {
    const f = frame(bytes, {});
    if (!f.ok) return { v: f, match: null };
    const cands = [...st.peers.values()].filter((p) => p.slot === f.sender);
    let match = null;
    for (const p of cands) if (await verifyBytes(p.id, f.signed, f.sig)) { match = p; break; }
    const v = open(bytes, {
      keyFor: () => (match !== null ? match.raw : cands.length > 0 ? cands[0].raw : null),
      verify: () => match !== null,
      lastCounter: () => (match !== null ? match.inCounter : 0n),
    });
    return { v, match };
  }

  function learn(bytes, v, ks, hash) {
    const before = recognise(st.library, bytes, { keyset: ks, hash, stage: v.stage });
    const ab = mint(bytes, { stage: v.stage, keyset: ks, hash });
    st.library = adopt(st.library, [ab.exact, ab.shape].filter(Boolean)).library;
    if (ab.exact && bytes.length <= MAX_ANTIGEN_BYTES && st.antigens.length < MAX_ANTIGENS) {
      const h = toHex(bytes);
      if (!st.antigens.includes(h)) st.antigens.push(h);
    }
    remember('refused a packet at ' + v.stage + ': ' + familyOf(v.stage), { kind: 'refusal', stage: v.stage, family: familyOf(v.stage), hash });
    return before.variant;
  }

  // ── hearing ──
  // One packet at a time: the door reads a peer's last counter and moves it on, and between the two the signature is
  // checked asynchronously. Heard at the same moment, two packets would both read the old counter and the lower could
  // set it back, letting the higher be replayed. Found going live (Phase 3); hearing is now a queue.
  let line = Promise.resolve();
  function hear(bytes) {
    const turn = line.then(() => hearOne(bytes));
    line = turn.catch(() => {});
    return turn;
  }
  async function hearOne(bytes) {
    const ks = keyset(), hash = hashOf(bytes);
    const known = recognise(st.library, bytes, { keyset: ks, hash });
    if (known.exact) {
      st.seen.recognised++; st.seen.refused++;
      return { ok: false, stage: known.exact.stage, family: known.exact.family, decoded: false, recognised: true, reason: 'recognised on sight: a known ' + known.exact.family + ' packet', replies: [] };
    }
    const { v, match } = await verdictOf(bytes);
    if (!v.admit) {
      st.seen.refused++;
      const variant = learn(bytes, v, ks, hash);
      return { ok: false, stage: v.stage, family: familyOf(v.stage), decoded: v.decoded === true, recognised: false, variantOf: variant ? variant.of : null, reason: v.reason, replies: [] };
    }
    match.inCounter = v.counter;
    st.seen.admitted++;
    heardFrom(match);
    const m = readMessage(v.value);
    if (!m.ok) { remember('a pinned peer sent what is not a message: ' + m.why, { kind: 'junk', from: match.id, hash }); return { ok: false, stage: 'message', from: match.id, decoded: true, reason: m.why, replies: [] }; }
    if (m.to !== me.id) { remember('a packet from ' + match.name + ' addressed to another node', { kind: 'misaddressed', from: match.id, hash }); return { ok: false, stage: 'message', from: match.id, decoded: true, reason: 'addressed to another node', replies: [] }; }
    if (m.t === 'ask') return onAsk(m, match, hash);
    if (m.t === 'answer') return onAnswer(m, match, hash, bytes);
    if (m.t === 'antibody') return onAntibody(m, match);
    if (m.t === 'sync') return onSync(m, match);
    if (m.t === 'notes') return onNotes(m, match);
    if (m.t === 'probe') return onProbe(m, match);
    if (m.t === 'pong') return { ok: true, t: 'pong', from: match.id, id: m.id, replies: [] };   // heard from: that is the whole answer
    return onLedger(m, match);
  }

  /** A peer that speaks is alive: whatever silence this node held against it is over, and so are its probes. */
  function heardFrom(p) {
    if (p.quiet.size === 0) return;
    p.quiet.clear();
    for (const [id, q] of [...st.probing]) if (q.to === p.id) st.probing.delete(id);
    remember(p.name + ' was heard from: no longer quiet', { kind: 'heard-from', peer: p.id });
  }

  // ── notes: what this node saw itself, and what it takes from others only after its own re-check ──
  function keep(key) {
    st.noted.add(key);
    if (st.noted.size > MAX_NOTED) st.noted.delete(st.noted.values().next().value);
  }
  function note(n, key) {
    st.notes.push(n);
    if (st.notes.length > MAX_NOTES) st.notes.shift();
    keep(key);
  }
  const check = async (skill, answer) => { try { return (await (typeof checks[skill] === 'function' ? checks[skill](answer) : receiptHolds(answer))) === true; } catch { return false; } };

  async function probe(holder, skill) {
    const id = 'probe:' + me.id.slice(0, 8) + ':' + (st.probes + 1);
    const bytes = await say(holder.id, { t: 'probe', id });
    if (bytes === null) return null;
    st.probes++;
    st.probing.set(id, { to: holder.id, skill });
    return { to: holder.id, bytes };
  }

  /** One note from a pinned peer → 'adopted' | 'quiet' | 'already' | why it was refused. Never on the sender's word. */
  async function takeNote(raw, author, replies) {
    const n = readNote(raw);
    if (!n.ok) return n.why;
    if (n.holder === me.id) return 'a note about this node';
    if (n.holder === author.id) return 'a note about its own sender';
    const holder = st.peers.get(n.holder);
    if (holder === undefined) return 'a note about a node this one has not pinned';
    if (!holder.skills.includes(n.skill)) return 'the holder does not hold ' + n.skill;
    if (n.kind === 'silent') {
      const key = 'silent:' + author.id + ':' + n.job, seen = st.noted.has(key) || holder.quiet.has(n.skill);
      keep(key);
      if (seen) return 'already';
      holder.quiet.add(n.skill);   // asks go elsewhere at once; the link moves only if this node's own probe goes unanswered
      const p = await probe(holder, n.skill);
      if (p !== null) replies.push(p);
      return 'quiet';
    }
    const bytes = fromHex(n.packet), key = 'lied:' + hashOf(bytes);
    const f = frame(bytes, {});   // a packet that does not frame names no sender, so it fails the first test
    if (f.sender !== holder.slot || !(await verifyBytes(holder.id, f.signed, f.sig))) return 'the packet is not signed by the holder it accuses';
    // the door's own reading of it, its signature checked just above; a body that does not decode reads as no message
    const a = readMessage(open(bytes, { keyFor: () => holder.raw, verify: () => true, lastCounter: () => 0n }).value);
    if (!a.ok || a.t !== 'answer' || a.to !== author.id || a.id !== n.job || a.skill !== n.skill) return 'the packet is not that holder’s answer to that ask of the sender’s';
    // only now are these bytes this evidence and no other (the packet itself names its asker, ask and skill), so only
    // now is it asked whether they were judged before, and only now are they remembered: a note that misnames them is
    // refused by name, never waved through as a repeat, and cannot stop the true one being counted (Phase 3c)
    if (st.noted.has(key)) return 'already';
    keep(key);
    if (a.answer.verdict !== 'VERIFIED') return 'an abstain is not a lie';
    if (await check(a.skill, a.answer)) return 'the answer checks here';
    holder.links.set(n.skill, hebb(holder.links.has(n.skill) ? holder.links.get(n.skill) : LINK.START, 'failed'));
    return 'adopted';
  }

  async function onNotes(m, peer) {
    const replies = [], r = { adopted: 0, quiet: 0, already: 0, refused: [] };
    for (const raw of m.notes) {
      const t = await takeNote(raw, peer, replies);
      if (t === 'adopted' || t === 'quiet' || t === 'already') r[t]++;
      else r.refused.push(t);
    }
    remember('took ' + m.notes.length + ' notes from ' + peer.name + ': ' + r.adopted + ' counted, ' + r.quiet + ' quiet pending a probe, ' + r.refused.length + ' refused', { kind: 'notes', from: peer.id, adopted: r.adopted, quiet: r.quiet, refused: r.refused.length });
    return { ok: true, t: 'notes', from: peer.id, offered: m.notes.length, ...r, replies };
  }

  async function onProbe(m, peer) {
    const bytes = await say(peer.id, { t: 'pong', id: m.id });
    return { ok: true, t: 'probe', from: peer.id, id: m.id, replies: bytes ? [{ to: peer.id, bytes }] : [] };
  }

  async function onAsk(m, peer, hash) {
    const tok = m.token, tv = await W.verifyToken(wc, tok);
    let answer;
    if (!tv.ok || tok.id !== peer.wallet || tok.type !== 'ask' || tok.nonce !== m.id) answer = { verdict: 'ABSTAIN', why: 'the ask carries no valid budget token for this peer' };
    else if (st.served.has(m.id)) answer = { verdict: 'ABSTAIN', why: 'this ask was answered already: one token, one answer' };
    else if (typeof skills[m.skill] !== 'function') answer = { verdict: 'ABSTAIN', why: 'this node does not hold skill ' + m.skill };
    else {
      try { answer = await skills[m.skill](m.input); } catch { answer = null; }
      if (!isObj(answer) || (answer.verdict !== 'VERIFIED' && answer.verdict !== 'ABSTAIN')) answer = { verdict: 'ABSTAIN', why: 'the skill failed' };
    }
    if (!st.served.has(m.id)) st.served.set(m.id, { to: peer.id, digest: digestOf(answer) });
    remember('answered ' + m.skill + ' for ' + peer.name + ': ' + answer.verdict, { kind: 'served', skill: m.skill, from: peer.id, job: m.id, hash });
    const bytes = await say(peer.id, { t: 'answer', id: m.id, skill: m.skill, answer });
    return { ok: true, t: 'ask', from: peer.id, id: m.id, skill: m.skill, verdict: answer.verdict, why: answer.why, replies: bytes ? [{ to: peer.id, bytes }] : [] };
  }

  async function onAnswer(m, peer, hash, bytes) {
    const p = st.pending.get(m.id);
    if (!p || p.to !== peer.id || p.skill !== m.skill) return { ok: false, stage: 'message', from: peer.id, decoded: true, reason: 'an answer to nothing this node asked that peer', replies: [] };
    st.pending.delete(m.id);
    const checked = m.answer.verdict === 'VERIFIED' && (await check(m.skill, m.answer));
    const outcome = m.answer.verdict === 'ABSTAIN' ? 'abstain' : checked ? 'verified' : 'failed';
    peer.links.set(m.skill, hebb(peer.links.has(m.skill) ? peer.links.get(m.skill) : LINK.START, outcome));
    peer.tried.add(m.skill);
    // a receipt that does not check is kept as evidence the others can re-check: the holder's own signed answer (if it
    // is small enough to carry; the bound is readNote's, so nothing is kept that a receiver would refuse for its size)
    const lied = { kind: 'lied', holder: peer.id, skill: m.skill, job: m.id, packet: toHex(bytes) };
    if (outcome === 'failed' && readNote(lied).ok) note(lied, 'lied:' + hash);
    remember(m.skill + ' answer from ' + peer.name + ': ' + outcome, { kind: 'answer', skill: m.skill, from: peer.id, job: m.id, outcome, hash });
    let recorded = false;
    if (outcome === 'verified') {
      const digest = digestOf(m.answer);
      st.used.set(m.id, { peer: peer.id, digest });
      if (st.ledger.genesis) {   // the ledger itself refuses a value from a key it does not name, or on an asset it does not hold
        const e = await L.sign(me.ledgerKeys, { type: 'value', asset: assetOf(peer.id), at: iso(clock()), basis: 'routing', job: m.id, proofs: [{ kind: 'answer', ref: m.id, digest }], units: 1 });
        recorded = await record(e.entry);
      }
    }
    return { ok: true, t: 'answer', from: peer.id, id: m.id, skill: m.skill, outcome, answer: m.answer, recorded, replies: [] };
  }

  async function onAntibody(m, peer) {
    let seen = null;
    const pre = verifyBundle(m.bundle, (from) => from === peer.id, (msg, s, from) => { seen = { msg, s, from }; return true; });
    if (!pre.ok) return { ok: false, t: 'antibody', from: peer.id, reason: pre.reason, replies: [] };
    if (!(await verifyBytes(seen.from, seen.msg, seen.s))) return { ok: false, t: 'antibody', from: peer.id, reason: 'the bundle signature does not verify', replies: [] };
    const verdicts = new Map();
    for (const h of pre.antigens) verdicts.set(h, (await verdictOf(fromHex(h))).v);   // the re-run, on this node's own door
    const ks = keyset();
    const r = adoptAntigens(pre.antigens, {
      decide: (bytes) => verdicts.get(toHex(bytes)) || { admit: false, stage: 'error' },
      immuneStage: (v) => v.stage, classify: (v) => familyOf(v.stage),
      mint: (bytes, c) => mint(bytes, { stage: c.stage, keyset: c.keyset, hash: c.hash }),
      adopt: (lib, abs) => adopt(lib, abs), PERMANENT, keyset: ks, hash: hashOf, library: st.library,
    });
    st.library = r.library;
    remember('adopted ' + r.adopted + ' antibodies from ' + peer.name, { kind: 'antibodies', from: peer.id, adopted: r.adopted, blocked: r.autoimmuneBlocked });
    return { ok: true, t: 'antibody', from: peer.id, offered: pre.antigens.length, adopted: r.adopted, autoimmuneBlocked: r.autoimmuneBlocked, recognitionOnly: r.recognitionOnly, replies: [] };
  }

  function onSync(m, peer) {
    const d = st.docs.get(m.doc.docId);
    if (d === undefined) return { ok: false, t: 'sync', from: peer.id, reason: 'this node keeps no document ' + m.doc.docId, replies: [] };
    const r = merge(d, m.doc);   // the shape was checked when the message was read
    st.docs.set(d.docId, r.doc);
    remember('merged ' + r.changed.length + ' keys of ' + d.docId + ' from ' + peer.name, { kind: 'sync', from: peer.id, doc: d.docId, changed: r.changed.length });
    return { ok: true, t: 'sync', from: peer.id, doc: d.docId, changed: r.changed.length, replies: [] };
  }

  async function onLedger(m, peer) {
    const theirs = await L.replay(m.log, { gate: async () => ({ ok: true }) });   // rebuild their chain (signatures checked); trust nothing yet
    if (!theirs.ok || !st.ledger.genesis) return { ok: false, t: 'ledger', from: peer.id, reason: theirs.ok ? 'this node keeps no ledger' : theirs.why, replies: [] };
    const r = await L.reconcile(st.ledger, theirs.ledger, { gate });            // then each entry is recorded only if THIS node can re-check it
    if (!r.ok) return { ok: false, t: 'ledger', from: peer.id, reason: r.why, replies: [] };
    st.ledger = r.ledger;
    return { ok: true, t: 'ledger', from: peer.id, added: r.added, skipped: r.skipped, refused: r.refused.length, replies: [] };
  }

  // ── the verbs ──
  async function pin(c) {
    const r = await readCard(c);
    if (!r.ok) return r;
    if (c.id === me.id) return { ok: false, why: 'a node does not pin itself' };
    const prev = st.peers.get(c.id);
    // a key pinned again after an unpin keeps its last counter, so nothing it sent before can be replayed
    const inCounter = prev ? prev.inCounter : st.retired.has(c.id) ? st.retired.get(c.id) : 0n;
    st.peers.set(c.id, { id: c.id, raw: unhex(c.id), slot: c.slot, name: c.name, wallet: c.wallet, skills: c.skills.slice(), body: r.body, inCounter,
      links: prev ? prev.links : new Map(), tried: prev ? prev.tried : new Set(), quiet: prev ? prev.quiet : new Set() });
    const released = isObj(c.release) ? await record(c.release) : false;   // the ledger refuses a second release, or one with no genesis
    return { ok: true, id: c.id, released };
  }

  async function ask(skill, input) {
    // greedy routing tells choose nothing of tries or silence, so the strongest live link alone decides (Phase 3)
    const told = (p) => (routing === 'shared' ? { tried: (s) => p.tried.has(s), quiet: (s) => p.quiet.has(s) } : {});
    const peerList = [...st.peers.values()].map((p) => ({ id: p.id, skills: p.skills, weight: (s) => (p.links.has(s) ? p.links.get(s) : LINK.START), ...told(p) }));
    const pick = choose(peerList, skill);
    if (pick === null) return { ok: false, why: 'no pinned peer holds skill ' + skill };
    if (st.pending.size >= MAX_PENDING) return { ok: false, why: 'too many asks are waiting for an answer' };
    const id = 'ask:' + me.id.slice(0, 8) + ':' + (st.asks + 1);
    const auth = await W.authorize(wc, st.wallet, st.sk, { type: 'ask', cost: 1 }, id);   // the budget, before any packet exists
    if (!auth.ok) return { ok: false, why: auth.why };
    st.wallet = auth.wallet; st.asks++;
    const bytes = await say(pick.id, { t: 'ask', id, skill, input, token: auth.token });
    st.pending.set(id, { to: pick.id, skill });
    return { ok: true, id, to: pick.id, live: pick.live, untried: pick.untried, bytes };
  }

  /** This node's own notes, to one peer, as one signed message (as antibodies are shared). The receiver re-checks each. */
  async function shareNotes(to) { return st.peers.has(to) && st.notes.length > 0 ? say(to, { t: 'notes', notes: st.notes }) : null; }

  async function shareAntibodies(to) {
    if (!st.peers.has(to) || st.antigens.length === 0) return null;
    let msg = null;
    makeBundle(me.id, st.antigens, (m) => { msg = m; return new Uint8Array(64); });       // the exact bytes the bundle signs
    const real = await me.sign(msg);
    const bundle = makeBundle(me.id, st.antigens, () => real);
    return say(to, { t: 'antibody', bundle });
  }

  /** Stop trusting a peer (the founder's roster no longer names it): its key is dropped, so what it sends stops at the
   *  sender, and the asks waiting on it are given up. Its last counter is kept for a later pin. */
  function unpin(id) {
    const p = st.peers.get(id);
    if (p === undefined) return { ok: false, why: 'no pinned peer ' + String(id).slice(0, 40) };
    st.peers.delete(id);
    st.retired.set(id, p.inCounter);
    let dropped = 0;
    for (const [job, q] of [...st.pending]) if (q.to === id) { st.pending.delete(job); dropped++; }
    for (const [job, q] of [...st.probing]) if (q.to === id) st.probing.delete(job);
    remember('unpinned ' + p.name + ': no longer trusted', { kind: 'unpinned', peer: id, dropped });
    return { ok: true, id, dropped };
  }

  /**
   * An ask nobody answered, given up: it counts as a failed answer, the peer is quiet here until it is heard from, and
   * this node writes a 'silent' note for the others. A probe nobody answered, given up: this node's own evidence of a
   * silence it was told of, so only now does its link fall.
   */
  function expire(id) {
    const q = st.probing.get(id);
    if (q !== undefined) {
      st.probing.delete(id);
      const holder = st.peers.get(q.to);
      holder.links.set(q.skill, hebb(holder.links.has(q.skill) ? holder.links.get(q.skill) : LINK.START, 'failed'));
      remember('probe ' + id + ' to ' + holder.name + ' expired unanswered', { kind: 'probe-expired', to: q.to, skill: q.skill, job: id });
      return { ok: true, to: q.to, skill: q.skill, weight: holder.links.get(q.skill), probe: true };
    }
    const p = st.pending.get(id);
    if (p === undefined) return { ok: false, why: 'no ask ' + String(id).slice(0, 40) + ' is waiting' };
    st.pending.delete(id);
    const peer = st.peers.get(p.to);
    peer.links.set(p.skill, hebb(peer.links.has(p.skill) ? peer.links.get(p.skill) : LINK.START, 'failed'));
    peer.tried.add(p.skill);
    peer.quiet.add(p.skill);
    note({ kind: 'silent', holder: p.to, skill: p.skill, job: id }, 'silent:' + me.id + ':' + id);
    remember('ask ' + id + ' to ' + peer.name + ' expired unanswered', { kind: 'expired', to: p.to, skill: p.skill, job: id });
    return { ok: true, to: p.to, skill: p.skill, weight: peer.links.get(p.skill) };
  }

  /** One write to a shared document, stamped by this node. */
  function setShared(docId, key, value) {
    const d = st.docs.get(docId);
    if (d === undefined) return { ok: false, why: 'this node keeps no document ' + String(docId).slice(0, 40) };
    const r = setKey(d, me.id, key, value);
    if (!r.ok) return r;
    st.docs.set(docId, r.doc);
    return { ok: true, entry: r.entry };
  }
  async function shareSync(to, docId) { return st.peers.has(to) && st.docs.has(docId) ? say(to, { t: 'sync', doc: st.docs.get(docId) }) : null; }

  async function shareLedger(to) { return st.peers.has(to) && st.ledger.genesis ? say(to, { t: 'ledger', log: st.ledger.log }) : null; }

  async function vault() {
    const enc = (x) => new TextEncoder().encode(JSON.stringify(x));
    const files = [
      { path: 'memory.json', bytes: enc(st.memory.toJSON()) },
      { path: 'immune.json', bytes: enc(st.library) },
      { path: 'ledger.json', bytes: enc(st.ledger.log) },
    ];
    const p = pack(files);
    const index = files.map((f) => ({ path: f.path, sha256: hex(sha256(f.bytes)) }));
    const identical = vaultMatches(p.bytes, index);
    return { ok: identical, bytes: p.bytes, plain: files.reduce((n, f) => n + f.bytes.length, 0), files: index, identical };
  }

  return Object.freeze({
    id: me.id, name, slot: me.slot, routing,
    card: () => card,
    pin, unpin, hear, ask, shareAntibodies, shareLedger, vault, expire, setShared, shareSync, shareNotes,
    pinned: () => [...st.peers.keys()].sort(),
    notes: () => st.notes.map((n) => ({ ...n })),
    probing: () => [...st.probing.keys()],
    quiet: (peer, skill) => { const p = st.peers.get(peer); return p !== undefined && p.quiet.has(skill); },
    tried: (peer, skill) => { const p = st.peers.get(peer); return p !== undefined && p.tried.has(skill); },
    shared: (docId) => (st.docs.has(docId) ? valueOf(st.docs.get(docId)) : null),
    sharedDoc: (docId) => (st.docs.has(docId) ? st.docs.get(docId) : null),
    pending: () => [...st.pending.keys()],
    weight: (peer, skill) => { const p = st.peers.get(peer); return p && p.links.has(skill) ? p.links.get(skill) : LINK.START; },
    recall: (q, k = 3) => st.memory.retrieve(String(q), { k }),
    credits: () => L.credits(st.ledger),
    ledger: () => st.ledger,
    library: () => st.library,
    antigens: () => st.antigens.slice(),
    budget: () => ({ spent: st.wallet.budget.spent, total: st.wallet.budget.total }),
    stats: () => ({ ...st.seen, peers: st.peers.size, pending: st.pending.size, antibodies: Object.keys(st.library.exact).length, shapes: st.library.shapes.length, memory: st.memory.size, entries: st.ledger.log.length,
      notes: st.notes.length, probing: st.probing.size, quiet: [...st.peers.values()].reduce((k, p) => k + p.quiet.size, 0) }),
  });
}

/** A contribution-ledger genesis for a mesh, signed by its founder: names the nodes that may measure. */
export async function meshGenesis(founder, measurerIds) {
  const r = await L.sign(founder.ledgerKeys, {
    type: 'genesis', activators: [founder.id], measurers: (Array.isArray(measurerIds) ? measurerIds : []).filter((x) => HEX64.test(x)).slice(0, 32),
    policy: { makerPpm: 1000000, lineagePpm: 0, earlyUntil: 0, earlyNum: 1, earlyDen: 1 },
  });
  return r.ok ? r.entry : null;
}
