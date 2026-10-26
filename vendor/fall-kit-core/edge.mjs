// ════════════════════════════════════════════════════════════════
// core/edge.mjs — the edge: where the estate meets the outside, which still speaks standard formats. Organ 4 of the
// shared foundation (Phase 2, LIGHT everywhere: claims E1–E3 in core/phase2/claims.json).
//
// Inside, everything is a LIGHT packet a pinned key signed, and the door (vendor/light/packet.mjs) refuses anything
// else before one byte of a body is decoded. Outside, a request is JSON text from someone the estate never pinned.
// The edge is the one place the two meet, and it is thin on purpose:
//
//   inbound(bytes, { shape, maxBytes })  → { ok, value } | { ok: false, stage, why }
//       an outside request, checked in order: size → utf8 → json → shape. The value is only ever parsed from bytes that
//       are within the size and are valid UTF-8, and it is only let in if it fits the shape the edge declared for it.
//   sealInside(bytes, opts, sign)        → { ok, bytes, value } | { ok: false, stage, why }
//       inbound, then the checked value re-said as a LIGHT packet the edge's own key signs, so an organ inside only ever
//       hears signed LIGHT from a key it pinned. A refused request builds no packet.
//   outbound(bytes, { peers, lastCounter, verifyBytes })
//                                         → { ok, json, value, sender, counter } | { ok: false, stage, why, decoded }
//       a packet from inside, through the door first (the sender looked up by slot, its signature verified), and only
//       then said as standard JSON. A packet the door refuses produces no output.
//   shapeOk(value, shape) · shapeOf(value)
//       the declared shape: null, bool, int, number, string, list (of one shape), tuple (item by item), object (fields,
//       required, extra allowed or not), any (any JSON within a depth). shapeOf gives the exact shape of an example.
//
// Pure and total, apart from the signer and verifier handed in: garbage in is a refusal naming its stage, never a throw.
// Powered by the Konomi architecture, created by Thomas Frumkin.
// ════════════════════════════════════════════════════════════════
import { prepare, finish, open, frame, KINDS, MAX_PACKET } from './vendor/light/packet.mjs';

export const MAX_DEPTH = 64;
export const MAX_REQUEST = 1 << 20;
export const IN_STAGES = Object.freeze(['size', 'utf8', 'json', 'shape', 'packet']);
const TYPES = Object.freeze(['null', 'bool', 'int', 'number', 'string', 'list', 'tuple', 'object', 'any']);
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const no = (stage, why) => ({ ok: false, stage, why });
const bad = (why) => ({ ok: false, why });
const lim = (n, d) => (Number.isSafeInteger(n) && n >= 0 ? n : d);

/** Is this a JSON value no deeper than `left` levels? */
function plainJson(v, left) {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return true;
  if (typeof v === 'number') return Number.isFinite(v);
  if (left <= 0 || typeof v !== 'object') return false;
  const xs = Array.isArray(v) ? v : Object.getPrototypeOf(v) === Object.prototype ? Object.values(v) : null;
  return xs !== null && xs.every((x) => plainJson(x, left - 1));
}

/** Does the value fit the declared shape? → { ok: true } | { ok: false, why } */
export function shapeOk(value, shape) {
  return fits(value, shape, MAX_DEPTH);
}
function fits(v, s, left) {
  if (!isObj(s) || !TYPES.includes(s.type)) return bad('the shape is not one the edge declares');
  if (left <= 0) return bad('nested deeper than ' + MAX_DEPTH);
  switch (s.type) {
    case 'null': return v === null ? { ok: true } : bad('not null');
    case 'bool': return typeof v === 'boolean' ? { ok: true } : bad('not true or false');
    case 'int':
      if (!Number.isSafeInteger(v)) return bad('not a whole number');
      return inRange(v, s);
    case 'number':
      if (typeof v !== 'number' || !Number.isFinite(v)) return bad('not a number');
      return inRange(v, s);
    case 'string':
      if (typeof v !== 'string') return bad('not text');
      return v.length <= lim(s.max, MAX_REQUEST) ? { ok: true } : bad('text longer than ' + s.max);
    case 'list': {
      if (!Array.isArray(v)) return bad('not a list');
      if (v.length > lim(s.max, MAX_REQUEST)) return bad('a list longer than ' + s.max);
      for (let i = 0; i < v.length; i++) { const r = fits(v[i], s.of, left - 1); if (!r.ok) return bad('item ' + i + ': ' + r.why); }
      return { ok: true };
    }
    case 'tuple': {
      if (!Array.isArray(v) || !Array.isArray(s.items)) return bad('not a list');
      if (v.length !== s.items.length) return bad('a list of ' + v.length + ' where ' + s.items.length + ' are declared');
      for (let i = 0; i < v.length; i++) { const r = fits(v[i], s.items[i], left - 1); if (!r.ok) return bad('item ' + i + ': ' + r.why); }
      return { ok: true };
    }
    case 'object': {
      if (!isObj(v) || !isObj(s.fields)) return bad('not a record');
      const req = Array.isArray(s.required) ? s.required : [];
      for (const k of req) if (!Object.prototype.hasOwnProperty.call(v, k)) return bad('missing ' + k);
      for (const k of Object.keys(v)) {
        if (!Object.prototype.hasOwnProperty.call(s.fields, k)) { if (s.extra === true) continue; return bad('an undeclared field ' + k.slice(0, 40)); }
        const r = fits(v[k], s.fields[k], left - 1);
        if (!r.ok) return bad(k.slice(0, 40) + ': ' + r.why);
      }
      return { ok: true };
    }
    default: {   // 'any': any JSON value of at most `depth` levels (a plain value is one; each list or record adds one)
      const d = Number.isSafeInteger(s.depth) && s.depth >= 1 ? Math.min(s.depth, left) : left;
      return plainJson(v, d - 1) ? { ok: true } : bad('not JSON within depth ' + d);
    }
  }
}
function inRange(v, s) {
  if (typeof s.min === 'number' && v < s.min) return bad('below ' + s.min);
  if (typeof s.max === 'number' && v > s.max) return bad('above ' + s.max);
  return { ok: true };
}

/** The exact shape of an example value: what it is, and no more. → a shape | null (not JSON within the depth) */
export function shapeOf(value) {
  return plainJson(value, MAX_DEPTH - 1) ? exact(value) : null;
}
function exact(v) {
  if (v === null) return { type: 'null' };
  if (typeof v === 'boolean') return { type: 'bool' };
  if (typeof v === 'number') return { type: Number.isSafeInteger(v) ? 'int' : 'number', min: v, max: v };
  if (typeof v === 'string') return { type: 'string', max: v.length };
  if (Array.isArray(v)) return { type: 'tuple', items: v.map(exact) };
  const fields = {};
  for (const k of Object.keys(v)) fields[k] = exact(v[k]);
  return { type: 'object', fields, required: Object.keys(v), extra: false };
}

/** An outside request, checked: size → utf8 → json → shape. */
export function inbound(bytes, opts) {
  const o = isObj(opts) ? opts : {};
  if (!(bytes instanceof Uint8Array)) return no('size', 'not bytes');
  const max = Number.isSafeInteger(o.maxBytes) && o.maxBytes > 0 ? Math.min(o.maxBytes, MAX_REQUEST) : MAX_REQUEST;
  if (bytes.length === 0 || bytes.length > max) return no('size', 'a request is 1–' + max + ' bytes');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return no('utf8', 'not valid UTF-8'); }
  let value;
  try { value = JSON.parse(text); } catch { return no('json', 'not JSON'); }
  const r = shapeOk(value, o.shape);
  return r.ok ? { ok: true, value } : no('shape', r.why);
}

/** inbound, then re-said inside as a LIGHT packet the edge signs. opts = { shape, maxBytes, sender, counter }; sign(bytes) → 64 bytes. */
export async function sealInside(bytes, opts, sign) {
  const o = isObj(opts) ? opts : {};
  const r = inbound(bytes, o);
  if (!r.ok) return r;
  const p = prepare({ sender: o.sender, counter: o.counter, kind: KINDS.JSON, value: r.value, dictId: 0 });
  if (!p.ok) return no('packet', p.why);
  let sig = null;
  try { sig = typeof sign === 'function' ? await sign(p.signed) : null; } catch { sig = null; }
  const f = finish(p.unsigned, sig instanceof Uint8Array ? sig : null);
  return f.ok ? { ok: true, bytes: f.bytes, value: r.value } : no('packet', 'the edge could not sign: ' + f.why);
}

/**
 * A packet from inside, said outside as standard JSON, only after the door admits it. opts = { peers: [{ slot, id, raw }],
 * lastCounter(slot, id) → bigint, verifyBytes(id, bytes, sig) → Promise<bool> }.
 */
export async function outbound(bytes, opts) {
  const o = isObj(opts) ? opts : {};
  const f = frame(bytes, { maxPacket: MAX_PACKET });
  if (!f.ok) return { ok: false, stage: f.stage, why: f.reason, decoded: false };
  const cands = (Array.isArray(o.peers) ? o.peers : []).filter((p) => isObj(p) && p.slot === f.sender);
  let match = null;
  for (const p of cands) {
    let good = false;
    try { good = typeof o.verifyBytes === 'function' && (await o.verifyBytes(p.id, f.signed, f.sig)) === true; } catch { good = false; }
    if (good) { match = p; break; }
  }
  let last = 0n;
  try { last = match !== null && typeof o.lastCounter === 'function' ? o.lastCounter(match.slot, match.id) : 0n; } catch { last = null; }
  const v = open(bytes, {
    keyFor: () => (match !== null ? match.raw || match.id : cands.length > 0 ? cands[0].raw || cands[0].id : null),
    verify: () => match !== null,
    lastCounter: () => last,
  });
  if (!v.admit) return { ok: false, stage: v.stage, why: v.reason, decoded: v.decoded === true };
  if (v.kind !== KINDS.JSON) return { ok: false, stage: 'kind', why: 'only a JSON packet leaves as JSON', decoded: true };
  return { ok: true, json: JSON.stringify(v.value), value: v.value, sender: v.sender, counter: v.counter, from: match.id };
}
