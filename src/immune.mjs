// ════════════════════════════════════════════════════════════════
// immune.mjs — every attack becomes memory. Pure, total, integer-only, gated.
//
// The gate refuses; the immune system LEARNS from each refusal:
//   classify(refusal, facts)  → the attack FAMILY (forgery, replay, truncation, extension, schema-escape, …)
//   fingerprint(…)            → a short structural signature of HOW it was built (stage, family, length class,
//                               op, sender, magic) — two attacks built the same way share one fingerprint
//   learn(memory, event)      → a new memory: per-fingerprint counts, NOVELTY (a fingerprint never seen before is
//                               a new kind of attack → it becomes a vaccine), and the source's standing
//   standing(memory, source)  → the GEP ladder for that source: ALLOW → THROTTLE → BLOCK → ISOLATE
//
// SENTINEL's rule, kept absolute here: the immune system NEVER decides admission. Nothing in this file can admit a
// packet, change what the gate accepts, or touch a verified sender's history — the gate's verdict is exact on its
// own. Immunity here is MEMORY: what was tried, how often, by whom, which attacks are new (vaccines), and how much
// of a hostile source's traffic is worth writing down. Attacking it can at worst cost the attacker its own detail.
// Integer counts and logical time only (events, not clocks): the same attack stream gives the same memory on every
// machine. The GEP ladder (ALLOW / THROTTLE / STEP-UP / BLOCK / ISOLATE) is Gary W. Floyd's — Lumiea Systems
// Research Division, ThunderStruck Service LLC, "GEP-Based Security: Behavioral Entropy Signatures" (2025).
// ════════════════════════════════════════════════════════════════
import { MAGIC, VERSION, HEADER, SIG, MIN_PACKET, MAX_PACKET } from './wire.mjs';

export const FAMILIES = Object.freeze(['http', 'flood', 'malformed', 'truncation', 'extension', 'schema-escape',
  'unknown-sender', 'forgery', 'replay', 'out-of-order', 'behavior', 'fault']);
export const LADDER = Object.freeze({ THROTTLE: 20, BLOCK: 100, ISOLATE: 500 });   // refusals in the source's window
export const WINDOW = 1000;                                                          // events between halvings
export const MAX_FINGERPRINTS = 4096;                                                // bounded memory

const isBytes = (b) => b instanceof Uint8Array;
const lengthClass = (n) => (n === 0 ? 'empty' : n < MIN_PACKET ? 'short' : n > MAX_PACKET ? 'long' : 'fits');

/**
 * The attack family. refusal = { stage, reason } from the gate (or the server's http/flood/behavior stages);
 * facts = { bytes, declaredLength (the header's N or null), exactReplay (bytes match an admitted packet) }.
 */
export function classify(refusal, facts) {
  try {
  const r = refusal && typeof refusal === 'object' ? refusal : {};
  const f = facts && typeof facts === 'object' ? facts : {};
  const b = isBytes(f.bytes) ? f.bytes : new Uint8Array(0);
  switch (r.stage) {
    case 'http': return 'http';
    case 'flood': return 'flood';
    case 'behavior': return 'behavior';
    case 'magic': return 'malformed';
    case 'size': {
      if (!Number.isInteger(f.declaredLength)) return 'malformed';
      const want = HEADER + f.declaredLength + SIG;
      return b.length < want ? 'truncation' : 'extension';
    }
    case 'schema': return 'schema-escape';
    case 'sender': return 'unknown-sender';
    case 'signature': return 'forgery';
    case 'counter': return f.exactReplay === true || /^replay/.test(String(r.reason)) ? 'replay' : 'out-of-order';
    default: return 'fault';
  }
  } catch { return 'fault'; }
}

/** How the attack was built, in a few stable fields — never the payload itself. */
export function fingerprint(family, facts) {
  const f = facts && typeof facts === 'object' ? facts : {};
  const b = isBytes(f.bytes) ? f.bytes : new Uint8Array(0);
  const magicOk = b.length >= 5 && MAGIC.every((m, i) => b[i] === m) && b[4] === VERSION;
  const op = b.length > HEADER ? b[HEADER] : -1;
  const sender = b.length > 5 ? b[5] : -1;
  return [FAMILIES.includes(family) ? family : 'fault', lengthClass(b.length), magicOk ? 'brk1' : 'other', 'op' + op, 's' + sender].join('|');
}

/** A fresh memory. */
export const emptyMemory = () => ({ events: 0, prints: {}, sources: {}, novel: 0, families: {} });

/**
 * Learn one refusal. event = { family, print, source }. Returns { memory, novel }: novel is true the FIRST time a
 * fingerprint is seen — that attack becomes a vaccine. Counts per source halve every WINDOW events, so a source's
 * standing reflects its recent behaviour (logical time, not wall-clock time).
 */
export function learn(memory, event) {
  const m = memory && typeof memory === 'object' && memory.prints && memory.sources ? memory : emptyMemory();
  const e = event && typeof event === 'object' ? event : {};
  const family = FAMILIES.includes(e.family) ? e.family : 'fault';
  const print = typeof e.print === 'string' && e.print.length <= 128 ? e.print : 'fault|unprintable';
  const source = typeof e.source === 'string' && e.source.length <= 64 ? e.source : 'unknown';
  const prints = { ...m.prints }, sources = { ...m.sources }, families = { ...m.families };
  const known = Object.prototype.hasOwnProperty.call(prints, print);
  const room = Object.keys(prints).length < MAX_FINGERPRINTS;
  if (known) prints[print] = prints[print] + 1;
  else if (room) prints[print] = 1;
  families[family] = (families[family] || 0) + 1;
  sources[source] = (sources[source] || 0) + 1;
  let events = m.events + 1;
  if (events % WINDOW === 0) for (const s of Object.keys(sources)) sources[s] = Math.floor(sources[s] / 2);
  const novel = !known && room;
  return { memory: { events, prints, sources, families, novel: m.novel + (novel ? 1 : 0) }, novel };
}

/** The GEP ladder for a source, from its recent refusals. Only ever refuses more. */
export function standing(memory, source) {
  const m = memory && typeof memory === 'object' && memory.sources ? memory : emptyMemory();
  const n = typeof source === 'string' && Object.prototype.hasOwnProperty.call(m.sources, source) ? m.sources[source] : 0;
  if (n >= LADDER.ISOLATE) return 'ISOLATE';
  if (n >= LADDER.BLOCK) return 'BLOCK';
  if (n >= LADDER.THROTTLE) return 'THROTTLE';
  return 'ALLOW';
}

/**
 * What the journal keeps for a refusal from a source with this standing. The ladder never turns a request away —
 * shedding by source would let an attacker sharing your address lock YOU out — it decides how much of an attack is
 * written down: everything while a source is ALLOW or THROTTLE, and for a source at BLOCK or ISOLATE only a count,
 * so an attacker cannot fill the disk through the journal. A NOVEL attack is always kept in full: it is a vaccine.
 */
export const detail = (stand, novel) => (novel === true || stand === 'ALLOW' || stand === 'THROTTLE' ? 'full' : 'count');
