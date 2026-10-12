// ════════════════════════════════════════════════════════════════
// antibody.mjs — every attack becomes an antibody. Pure, total, integer-only, gated.
//
// ANTIGEN → ANTIBODY. A refused attack is turned into two things:
//   an EXACT antibody   — the sha256 of its bytes. Those bytes are then RECOGNISED ON SIGHT, by name and family, on
//                         every node that adopts it (the gate still re-checks every such drop — see server.mjs — so an
//                         antibody can never refuse a packet the gate would admit; if one ever tried, that is the Epic).
//   a SHAPE antibody    — its point in attack-feature space (`features`: how it was built, as integers). A new attack
//                         near a known one is RECOGNISED as that family on arrival (nearest neighbour, L1 distance) —
//                         immunity to the family, not just the exact bytes.
//
// NO FALSE IMMUNITY (negative selection). An exact antibody may only ever match bytes that can NEVER be valid: it
// is minted (and adopted from a peer) only after the node RE-RUNS the antigen through its own gate and the gate
// refuses it at a PERMANENT stage — size, magic, schema (the bytes are pure), an unknown sender or a forged signature
// (under the exact pinned key set the antibody names), or a replay (counters only grow). An out-of-order packet is
// NOT permanent — it could become valid — so it gets recognition only, never an exact antibody. Shape antibodies
// never drop anything: they name and count. So the antibody library can make the service faster and wiser; it can
// never refuse a packet the gate would admit.
// ════════════════════════════════════════════════════════════════
import { MAGIC, VERSION, HEADER, SIG } from './wire.mjs';

export const PERMANENT = Object.freeze(['size', 'magic', 'schema', 'sender', 'signature', 'replay']);
export const STAGE_INDEX = Object.freeze({ size: 0, magic: 1, schema: 2, sender: 3, signature: 4, replay: 5, 'out-of-order': 6, error: 7, admitted: 8 });
export const WEIGHTS = Object.freeze([64, 1, 8, 1, 1, 1, 2, 1, 4, 4]);  // the stage dominates: families never cross stages
export const RADIUS = 24, MAX_LIBRARY = 8192;
const HEX64 = /^[0-9a-f]{64}$/;

const isBytes = (b) => b instanceof Uint8Array;
const clamp = (x, lo, hi) => Math.max(lo, Math.min(hi, x));

/** The gate's refusal → the immune stage (a counter refusal splits into replay — permanent — and out-of-order). */
export function immuneStage(refusal) {
  try {
    const r = refusal && typeof refusal === 'object' ? refusal : {};
    if (r.stage === 'counter') return /^replay/.test(String(r.reason)) ? 'replay' : 'out-of-order';
    return Object.prototype.hasOwnProperty.call(STAGE_INDEX, r.stage) ? r.stage : 'error';
  } catch { return 'error'; }
}

/** A packet's point in attack-feature space: ten integers describing HOW it was built (never its secrets). */
export function features(bytes, stage) {
  const b = isBytes(bytes) ? bytes : new Uint8Array(0);
  const len = b.length;
  const has = (i) => i < len;
  const magicOk = len >= 4 && MAGIC.every((m, i) => b[i] === m) ? 1 : 0;
  const declared = len >= 16 ? (b[14] << 8) | b[15] : -1;
  const actual = len - HEADER - SIG;
  const sig = len >= HEADER + SIG ? b.subarray(len - SIG) : new Uint8Array(0);
  const sigZero = sig.length === SIG && sig.every((x) => x === 0) ? 1 : 0;
  const sHigh = sig.length === SIG && sig[63] >= 0x10 ? 1 : 0;           // s ≥ 2^252-ish: a malleability probe
  return [
    Object.prototype.hasOwnProperty.call(STAGE_INDEX, stage) ? STAGE_INDEX[stage] : STAGE_INDEX.error,
    Math.min(len, 400) >> 3,
    magicOk,
    has(4) ? b[4] : 256,
    has(5) ? b[5] : 256,
    declared < 0 ? 128 : clamp(declared - actual, -64, 64) + 64,
    has(HEADER) ? b[HEADER] : 256,
    has(HEADER + 1) ? b[HEADER + 1] : 256,
    sigZero,
    sHigh,
  ];
}

/** Weighted L1 distance between two feature points. */
export function distance(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== WEIGHTS.length || b.length !== WEIGHTS.length) return Infinity;
  let d = 0;
  for (let i = 0; i < WEIGHTS.length; i++) {
    if (!Number.isInteger(a[i]) || !Number.isInteger(b[i])) return Infinity;
    d += WEIGHTS[i] * Math.abs(a[i] - b[i]);
  }
  return d;
}

/**
 * Mint the antibodies for one refused antigen. facts:
 *   hash        — sha256 hex of the antigen bytes
 *   stage       — immuneStage(the gate's refusal) on THIS node's own re-run
 *   keyset      — sha256 hex of the pinned key set the refusal was made under
 *   family      — immune.classify(...)
 * → { exact: {...} | null, shape: {...} }   exact is null unless the refusal is permanent.
 */
export function mint(bytes, facts) {
  try {
    const f = facts && typeof facts === 'object' ? facts : {};
    const stage = Object.prototype.hasOwnProperty.call(STAGE_INDEX, f.stage) ? f.stage : 'error';
    const point = features(bytes, stage);
    const family = typeof f.family === 'string' ? f.family.slice(0, 32) : 'fault';
    const permanent = PERMANENT.includes(stage) && typeof f.hash === 'string' && HEX64.test(f.hash) && typeof f.keyset === 'string' && HEX64.test(f.keyset);
    return {
      exact: permanent ? { kind: 'exact', hash: f.hash, stage, keyset: f.keyset, family } : null,
      shape: { kind: 'shape', point, stage, family },
    };
  } catch { return { exact: null, shape: { kind: 'shape', point: features(new Uint8Array(0), 'error'), stage: 'error', family: 'fault' } }; }
}

/** A fresh library. */
export const emptyLibrary = () => ({ exact: {}, shapes: [], size: 0 });

/**
 * Add antibodies to a library (deduplicated, bounded). Returns { library, added }. A shape point already within
 * RADIUS of a shape of the same family adds nothing (the family is already covered).
 */
export function adopt(library, antibodies) {
  const lib = library && typeof library === 'object' && library.exact && Array.isArray(library.shapes) ? library : emptyLibrary();
  const exact = { ...lib.exact }, shapes = [...lib.shapes];
  let size = lib.size, added = 0;
  for (const a of Array.isArray(antibodies) ? antibodies : []) {
    if (!a || typeof a !== 'object' || size >= MAX_LIBRARY) continue;
    if (a.kind === 'exact' && typeof a.hash === 'string' && HEX64.test(a.hash) && PERMANENT.includes(a.stage) && typeof a.keyset === 'string' && HEX64.test(a.keyset)) {
      if (!Object.prototype.hasOwnProperty.call(exact, a.hash)) { exact[a.hash] = { stage: a.stage, keyset: a.keyset, family: String(a.family).slice(0, 32) }; size++; added++; }
    } else if (a.kind === 'shape' && Array.isArray(a.point) && a.point.length === WEIGHTS.length && a.point.every(Number.isInteger)) {
      const covered = shapes.some((s) => s.family === a.family && distance(s.point, a.point) <= RADIUS);
      if (!covered) { shapes.push({ point: [...a.point], family: String(a.family).slice(0, 32), stage: a.stage }); size++; added++; }
    }
  }
  return { library: { exact, shapes, size }, added };
}

/**
 * On sight: does the library already know these bytes? keyset = the pinned key set NOW — an exact antibody minted
 * under another key set (a key was added, removed or rotated) does not fire for the stages that depend on keys.
 * → { drop: boolean, by: 'exact'|null, family, nearest: { family, distance } | null }
 */
export function recognise(library, hash, point, keyset) {
  const lib = library && typeof library === 'object' && library.exact && Array.isArray(library.shapes) ? library : emptyLibrary();
  let drop = false, by = null, family = null;
  if (typeof hash === 'string' && Object.prototype.hasOwnProperty.call(lib.exact, hash)) {
    const e = lib.exact[hash];
    const keyBound = e.stage === 'sender' || e.stage === 'signature';
    if (!keyBound || e.keyset === keyset) { drop = true; by = 'exact'; family = e.family; }
  }
  let nearest = null;
  for (const s of lib.shapes) {
    const d = distance(s.point, point);
    if (d <= RADIUS && (!nearest || d < nearest.distance)) nearest = { family: s.family, distance: d };
  }
  return { drop, by, family: family || (nearest ? nearest.family : null), nearest };
}
