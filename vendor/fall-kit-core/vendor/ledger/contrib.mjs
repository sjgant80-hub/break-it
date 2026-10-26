// contrib.mjs — the CONTRIBUTION LEDGER: every release a signed, gated, measured contribution, recorded now.
//
// A release (a DIGI card, an app, a node, a mint) is written as a record signed by its maker. Ownership moves by a give
// the current owner signs. A measured contribution value (a card's leave-one-out share of a mesh's work, an app's
// gated usage, a node's routing share) is written as a value record, signed by a measurer the ledger names. Nothing
// counts unless its gate re-runs: the caller hands in `gate(entry)`, which re-checks the entry's proofs, and an entry
// whose gate fails is refused, not recorded.
//
// The ledger is append-only and hash-chained: each entry names the hash of the one before it, and replay() re-records
// every entry from nothing and demands the same chain back. First write wins: an asset is released once, and a give is
// valid only from the owner of that moment, so a second give of the same asset from the same owner is refused.
//
// The allocation policy is sealed at genesis, before any record it weighs: the maker's part and the parents' part of
// every value, and an early-contribution weight for entries up to a named position. allocate() turns the recorded,
// gated values into each contributor's part of a pool, in whole units, re-derivable by anyone from the ledger alone;
// shareOf() lists the line items behind one contributor's part, so everyone can check their own and everyone else's.
//
// ⚑ THE SWITCH IS OFF BY CONSTRUCTION. allocate() refuses a live allocation unless the ledger holds a switch entry
// signed by one of the activators genesis named; it computes a sandbox allocation, marked as such, for anyone. This
// kernel has no verb that creates a switch entry, and none that moves anything out of the ledger. As with kernel.mjs,
// there is NO money-out verb (no fiat, trade, exchange, withdraw, sell, convert, cashout, buy, payout) — the test
// `no money verb in the exported surface` checks the code. Units are internal contribution-units, not money. Whether an
// allocation is ever worth anything is a decision for the ledger's owner, with legal counsel, outside this code.
//
// reconcile() merges a ledger of the same schema into another: entries are identified by the hash of their signed
// content, so an entry both ledgers hold is counted once, and an entry that conflicts (a second release of an asset, a
// give from a former owner) is refused and named.
//
// Ed25519 and SHA-256 through WebCrypto (the same in Node and every modern browser); canonical JSON (sorted keys,
// whole numbers only), so a signed entry has one byte form. Total: junk is refused in plain words, never thrown.

export const SCHEMA = 'kcc.contrib.v1';
export const ZERO = '0'.repeat(64);
export const FORMS = Object.freeze(['card', 'chat', 'suite-node', 'hybrid', 'app', 'node', 'mint', 'suite']);
export const BASES = Object.freeze(['mesh-share', 'usage', 'routing', 'lineage']);
export const PPM = 1000000;
export const MAX_ENTRIES = 200000;
const PUB = /^[0-9a-f]{64}$/, SIG = /^[0-9a-f]{128}$/, ID = /^[a-z0-9][a-z0-9:._-]{0,95}$/, HEXD = /^[0-9a-f]{64}$/;
const KEYS = {
  genesis: ['activators', 'by', 'measurers', 'policy', 'type'],
  release: ['asset', 'at', 'by', 'form', 'lineage', 'proofs', 'type'],
  give: ['asset', 'at', 'by', 'to', 'type'],
  value: ['asset', 'at', 'basis', 'by', 'job', 'proofs', 'type', 'units'],
  switch: ['at', 'by', 'counsel', 'path', 'pool', 'type'],
};
const no = (why) => ({ ok: false, why });
const isObj = (x) => Object.prototype.toString.call(x) === '[object Object]';
const exactly = (x, keys) => isObj(x) && Object.keys(x).sort().join() === keys.join();
const whole = (n, max) => Number.isSafeInteger(n) && n >= 0 && n <= max;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

// ── canonical bytes, hashes, signatures ───────────────────────────────────────────────────────────────────────────
/** the one byte form of a value: sorted keys, no whitespace, whole numbers only. → string, or null for anything else */
export function canonical(x) {
  if (x === null || typeof x === 'boolean') return JSON.stringify(x);
  if (typeof x === 'string') return JSON.stringify(x);
  if (typeof x === 'number') return Number.isSafeInteger(x) ? String(x) : null;
  if (Array.isArray(x)) { const parts = x.map(canonical); return parts.includes(null) ? null : '[' + parts.join(',') + ']'; }
  if (isObj(x)) {
    const parts = [];
    for (const k of Object.keys(x).sort()) { const v = canonical(x[k]); if (v === null) return null; parts.push(JSON.stringify(k) + ':' + v); }
    return '{' + parts.join(',') + '}';
  }
  return null;
}
const utf8 = (s) => new TextEncoder().encode(s);
const hex = (b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.match(/../g), (x) => parseInt(x, 16));
export const sha256 = async (s) => hex(await crypto.subtle.digest('SHA-256', utf8(s)));
const PKCS8 = '302e020100300506032b657004220420';
/** an Ed25519 key pair from 32 seed bytes (a demo key from a public phrase is reproducible by anyone). → { pub, priv } */
export async function keysFromSeed(seed) {
  const priv = await crypto.subtle.importKey('pkcs8', unhex(PKCS8 + hex(seed)), { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', priv);
  const pub = hex(Uint8Array.from(atob(jwk.x.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (jwk.x.length % 4)) % 4)), (c) => c.charCodeAt(0)));
  return { pub, priv };
}
/** a key pair from a public phrase: SHA-256 of the phrase is the seed */
export const keysFromPhrase = async (phrase) => keysFromSeed(unhex(await sha256(phrase)));
// (WebCrypto answers false for a key or signature that does not check; record() turns anything thrown into a refusal)
async function verifySig(pub, sig, text) {
  const k = await crypto.subtle.importKey('raw', unhex(pub), { name: 'Ed25519' }, false, ['verify']);
  return crypto.subtle.verify({ name: 'Ed25519' }, k, unhex(sig), utf8(text));
}
const unsigned = (e) => Object.fromEntries(Object.entries(e).filter(([k]) => k !== 'sig'));
/** the identity of an entry: the hash of its signed content (the same in every ledger that holds it) */
export const idOf = (entry) => sha256(canonical(entry));

/** sign an entry's fields with keys: by is the signer's public key. → { ok, entry } | a refusal */
export async function sign(keys, fields) {
  if (!keys || !PUB.test(keys.pub || '') || !keys.priv) return no('signing needs an Ed25519 key pair');
  if (!isObj(fields)) return no('an entry is a record');
  const body = { ...fields, by: keys.pub }, text = canonical(body);
  if (text === null) return no('an entry holds only whole numbers, text, lists and records');
  try { return { ok: true, entry: { ...body, sig: hex(await crypto.subtle.sign({ name: 'Ed25519' }, keys.priv, utf8(text))) } }; } catch { return no('the key could not sign'); }
}

// ── the shape of each entry ───────────────────────────────────────────────────────────────────────────────────────
const isProofs = (p) => Array.isArray(p) && p.length <= 16 && p.every((x) => exactly(x, ['digest', 'kind', 'ref']) && typeof x.kind === 'string' && ID.test(x.kind) && typeof x.ref === 'string' && x.ref.length > 0 && x.ref.length <= 200 && HEXD.test(x.digest));
function shape(e) {
  const type = isObj(e) ? e.type : null;
  if (!KEYS[type]) return 'not a contribution entry';
  if (!exactly(unsigned(e), KEYS[type]) || !Object.prototype.hasOwnProperty.call(e, 'sig')) return 'a ' + type + ' entry has exactly the fields ' + KEYS[type].join(', ') + ' and its signature';
  if (!PUB.test(e.by) || !SIG.test(e.sig)) return 'it is not signed by an Ed25519 key';
  if (type !== 'genesis' && (typeof e.at !== 'string' || !ISO.test(e.at))) return 'its time is an ISO moment in whole seconds, UTC';
  if (type === 'genesis') {
    if (!Array.isArray(e.activators) || !e.activators.length || e.activators.length > 8 || !e.activators.every((k) => PUB.test(k))) return 'genesis names one to eight activator keys';
    if (!Array.isArray(e.measurers) || e.measurers.length > 32 || !e.measurers.every((k) => PUB.test(k))) return 'genesis names up to 32 measurer keys';
    const p = e.policy;
    if (!exactly(p, ['earlyDen', 'earlyNum', 'earlyUntil', 'lineagePpm', 'makerPpm'])) return 'the policy names makerPpm, lineagePpm, earlyUntil, earlyNum and earlyDen';
    if (!whole(p.makerPpm, PPM) || !whole(p.lineagePpm, PPM) || p.makerPpm + p.lineagePpm > PPM) return 'the maker’s and the parents’ parts are parts of a million, together at most a million';
    if (!whole(p.earlyUntil, MAX_ENTRIES) || !whole(p.earlyNum, 100) || !whole(p.earlyDen, 100) || p.earlyDen < 1 || p.earlyNum < p.earlyDen) return 'the early weight is a whole fraction of at least one, for entries up to a position';
  }
  if (type === 'release') {
    if (typeof e.asset !== 'string' || !ID.test(e.asset)) return 'an asset id is lowercase letters, digits and : . _ -';
    if (!FORMS.includes(e.form)) return 'its form is one of ' + FORMS.join(', ');
    if (!Array.isArray(e.lineage) || e.lineage.length > 8 || !e.lineage.every((x) => typeof x === 'string' && ID.test(x)) || new Set(e.lineage).size !== e.lineage.length) return 'its lineage is up to eight distinct asset ids';
    if (!isProofs(e.proofs) || !e.proofs.length) return 'a release carries at least one proof: { kind, ref, digest }';
  }
  if (type === 'give' && (typeof e.asset !== 'string' || !ID.test(e.asset) || !PUB.test(e.to))) return 'a give names an asset and the Ed25519 key it goes to';
  if (type === 'value') {
    if (typeof e.asset !== 'string' || !ID.test(e.asset)) return 'a value names an asset';
    if (!BASES.includes(e.basis)) return 'its basis is one of ' + BASES.join(', ');
    if (typeof e.job !== 'string' || !ID.test(e.job)) return 'a value names the job it was measured on';
    if (!whole(e.units, 1e12) || e.units < 1) return 'a value is a whole number of units, at least one';
    if (!isProofs(e.proofs) || !e.proofs.length) return 'a value carries the proof that re-measures it';
  }
  if (type === 'switch') {
    if (e.path !== 'network' && e.path !== 'fork') return 'a switch names its path: network or fork';
    if (!whole(e.pool, 1e15) || e.pool < 1) return 'a switch names a pool of whole units';
    if (typeof e.counsel !== 'string' || !HEXD.test(e.counsel)) return 'a switch names the digest of the counsel it was made under';
  }
  return '';
}

// ── the ledger ────────────────────────────────────────────────────────────────────────────────────────────────────
/** an empty ledger (genesis is its first entry) */
export const empty = () => ({ schema: SCHEMA, log: [], head: ZERO, ids: {}, genesis: null, assets: {}, values: {}, switch: null });
const copy = (l) => ({ schema: l.schema, log: l.log.slice(), head: l.head, ids: { ...l.ids }, genesis: l.genesis, assets: Object.fromEntries(Object.entries(l.assets).map(([k, a]) => [k, { ...a, owners: a.owners.slice() }])), values: { ...l.values }, switch: l.switch });

/**
 * Record one signed entry. opts.gate(entry, ledger) → { ok } | Promise of it: re-checks a release's or a value's proofs
 * (required for both; an entry whose gate does not pass is refused). → { ok, ledger, id } | a refusal naming why.
 */
export async function record(ledger, entry, opts = {}) {
  try {
    if (!ledger || ledger.schema !== SCHEMA || !Array.isArray(ledger.log)) return no('not a contribution ledger');
    if (ledger.log.length >= MAX_ENTRIES) return no('the ledger is full');
    const bad = shape(entry);
    if (bad) return no(bad);
    if (!(await verifySig(entry.by, entry.sig, canonical(unsigned(entry))))) return no('its signature does not check');
    const id = await idOf(entry);
    if (ledger.ids[id] !== undefined) return no('this very entry is already recorded (entry ' + ledger.ids[id] + ')');
    const g = ledger.genesis;
    if (entry.type === 'genesis') { if (g) return no('a ledger has one genesis'); }
    else if (!g) return no('a ledger begins with its genesis');
    const a = entry.asset !== undefined ? ledger.assets[entry.asset] : undefined;
    if (entry.type === 'release') {
      if (a) return no('asset ' + entry.asset + ' was released already: the first release recorded wins');
      for (const p of entry.lineage) if (!ledger.assets[p]) return no('its parent ' + p + ' is not recorded here');
    }
    if (entry.type === 'give') {
      if (!a) return no('asset ' + entry.asset + ' is not recorded here');
      if (entry.by !== a.owner) return no('only its owner of this moment can give ' + entry.asset + ' (a give from a former owner is a double sale)');
      if (entry.to === a.owner) return no('a give goes to another key');
    }
    if (entry.type === 'value') {
      if (!a) return no('asset ' + entry.asset + ' is not recorded here');
      if (!g.measurers.includes(entry.by)) return no('values are signed by a measurer the genesis names');
      if (ledger.values[entry.asset + '|' + entry.basis + '|' + entry.job] !== undefined) return no('this asset’s ' + entry.basis + ' on job ' + entry.job + ' is recorded already: nothing is counted twice');
    }
    if (entry.type === 'switch') {
      if (!g.activators.includes(entry.by)) return no('only an activator the genesis names can sign the switch');
      if (ledger.switch) return no('the switch is recorded already');
    }
    if (entry.type === 'release' || entry.type === 'value') {
      if (typeof opts.gate !== 'function') return no('a ' + entry.type + ' is recorded only once its gate re-runs: no gate was given');
      let r;
      try { r = await opts.gate(entry, ledger); } catch { r = null; }
      if (!r || r.ok !== true) return no('its gate did not pass: ' + ((r && r.why) || 'no reason given'));
    }
    const l = copy(ledger), n = l.log.length, link = { n, prev: l.head, entry };
    l.log.push(link); l.head = await sha256(canonical(link)); l.ids[id] = n;
    if (entry.type === 'genesis') l.genesis = entry;
    if (entry.type === 'release') l.assets[entry.asset] = { maker: entry.by, owner: entry.by, form: entry.form, lineage: entry.lineage.slice(), at: n, owners: [[n, entry.by]] };
    if (entry.type === 'give') { l.assets[entry.asset].owner = entry.to; l.assets[entry.asset].owners.push([n, entry.to]); }
    if (entry.type === 'value') l.values[entry.asset + '|' + entry.basis + '|' + entry.job] = n;
    if (entry.type === 'switch') l.switch = n;
    return { ok: true, ledger: l, id };
  } catch { return no('not an entry this ledger can record'); }
}

/** re-record every entry of a log from nothing, demanding the same chain back. → { ok, ledger } | a refusal naming the entry */
export async function replay(log, opts = {}) {
  if (!Array.isArray(log) || log.length > MAX_ENTRIES) return no('a log is a list of linked entries');
  let l = empty();
  for (let k = 0; k < log.length; k++) {
    const x = log[k];
    if (!exactly(x, ['entry', 'n', 'prev']) || x.n !== k || x.prev !== l.head) return no('entry ' + k + ' is not linked to the one before it');
    const r = await record(l, x.entry, opts);
    if (!r.ok) return no('entry ' + k + ': ' + r.why);
    l = r.ledger;
  }
  return { ok: true, ledger: l };
}

/** whose an asset was at entry n: the owner of record when its contribution was made */
export function ownerAt(ledger, asset, n) {
  const a = ledger && ledger.assets && ledger.assets[asset];
  if (!a || !Number.isSafeInteger(n)) return null;
  let who = null;
  for (const [at, k] of a.owners) if (at <= n) who = k;
  return who;
}

/**
 * Each contributor's credits, from the recorded, gated values: a value's units go to the asset's owner of that moment,
 * less the maker's part (makerPpm) and the parents' part (lineagePpm, split evenly among the parents' makers; with no
 * parents it stays with the owner); entries up to policy.earlyUntil weigh earlyNum / earlyDen.
 * Credits are exact (BigInt sums, given as decimal text) in units times the weight's denominator (scale).
 * → { ok, credits: { key: 'digits' }, lines: [{ n, asset, basis, job, key, role, credit: 'digits' }], scale } | a refusal
 */
export function credits(ledger) {
  if (!ledger || ledger.schema !== SCHEMA || !ledger.genesis) return no('not a contribution ledger with a genesis');
  const p = ledger.genesis.policy, out = {}, lines = [], M = BigInt(PPM);
  const add = (n, e, key, role, credit) => { if (credit <= 0n) return; out[key] = (out[key] || 0n) + credit; lines.push({ n, asset: e.asset, basis: e.basis, job: e.job, key, role, credit: String(credit) }); };
  for (const { n, entry: e } of ledger.log) {
    if (e.type !== 'value') continue;
    const a = ledger.assets[e.asset], units = BigInt(e.units) * BigInt(n <= p.earlyUntil ? p.earlyNum : p.earlyDen);
    const maker = (units * BigInt(p.makerPpm)) / M, k = BigInt(a.lineage.length), each = k ? (units * BigInt(p.lineagePpm)) / M / k : 0n;
    add(n, e, a.maker, 'maker', maker);
    for (const par of a.lineage) add(n, e, ledger.assets[par].maker, 'parent', each);
    add(n, e, ownerAt(ledger, e.asset, n), 'owner', units - maker - each * k);
  }
  return { ok: true, credits: Object.fromEntries(Object.entries(out).map(([key, v]) => [key, String(v)])), lines, scale: p.earlyDen };
}

/**
 * The allocation of a pool of whole units among contributors, in proportion to their credits: floors first, then the
 * remainder one unit at a time to the largest fractions (ties by key), so the parts sum to the pool exactly.
 * opts.sandbox with opts.pool: anyone's allocation over this ledger, marked sandbox — the switch need not be on.
 * Without sandbox: refused unless the ledger holds its switch (signed by an activator), whose pool it uses.
 * → { ok, sandbox, pool, parts: { key: whole }, total } | a refusal
 */
export function allocate(ledger, opts = {}) {
  const c = credits(ledger);
  if (!c.ok) return c;
  const sandbox = opts.sandbox === true;
  if (!sandbox && ledger.switch === null) return no('the switch is off: no allocation is live (a sandbox allocation can be computed by anyone)');
  const pool = sandbox ? opts.pool : ledger.log[ledger.switch].entry.pool;
  if (!whole(pool, 1e15) || pool < 1) return no('a pool is a whole number of units, at least one');
  const keys = Object.keys(c.credits).sort(), total = keys.reduce((s, k) => s + BigInt(c.credits[k]), 0n);   // every credit is above zero
  if (total === 0n) return { ok: true, sandbox, pool, parts: {}, total: 0 };
  const P = BigInt(pool), parts = {}, rest = [];
  let given = 0n;
  for (const k of keys) { const q = (BigInt(c.credits[k]) * P) / total, r = (BigInt(c.credits[k]) * P) % total; parts[k] = Number(q); given += q; rest.push([r, k]); }
  // the units left over, one each, to the largest remainders: rest is in key order, so the first of a tie is the smallest key
  const picked = new Set();
  for (let i = 0; i < Number(P - given); i++) {
    let best = null;
    for (const x of rest) if (!picked.has(x[1]) && (best === null || x[0] > best[0])) best = x;
    picked.add(best[1]); parts[best[1]] += 1;
  }
  return { ok: true, sandbox, pool, parts, total: Number(Object.values(parts).reduce((s, x) => s + BigInt(x), 0n)) };
}

/** one contributor's part and every line behind it, so they can check it from the ledger alone */
export function shareOf(ledger, key, opts = {}) {
  if (!PUB.test(key || '')) return no('a contributor is an Ed25519 public key');
  const c = credits(ledger), a = allocate(ledger, opts);
  if (!c.ok) return c;
  if (!a.ok) return a;
  return { ok: true, key, credit: c.credits[key] || '0', part: a.parts[key] || 0, pool: a.pool, sandbox: a.sandbox, lines: c.lines.filter((x) => x.key === key) };
}

/**
 * Merge a ledger of the same schema into another: each of `from`'s entries the target does not already hold (by the
 * hash of its signed content) is recorded on the target, in order, through the same checks and the same gate. An entry
 * the target holds is skipped (counted once); one that conflicts is refused and named, and the merge goes on.
 * → { ok, ledger, added, skipped, refused: [{ n, why }] } | a refusal
 */
export async function reconcile(into, from, opts = {}) {
  if (!into || into.schema !== SCHEMA || !from || from.schema !== SCHEMA) return no('both must be contribution ledgers of this schema');
  if (!into.genesis || !from.genesis) return no('both must begin with a genesis');
  if ((await idOf(into.genesis)) !== (await idOf(from.genesis))) return no('they began from different geneses: their policies and keys differ, so their entries are not the same economy');
  let l = into, added = 0, skipped = 0;
  const refused = [];
  for (const { n, entry } of from.log) {
    if (l.ids[await idOf(entry)] !== undefined) { skipped++; continue; }
    const r = await record(l, entry, opts);
    if (r.ok) { l = r.ledger; added++; } else refused.push({ n, why: r.why });
  }
  return { ok: true, ledger: l, added, skipped, refused };
}
