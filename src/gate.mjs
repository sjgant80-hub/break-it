// ════════════════════════════════════════════════════════════════
// gate.mjs — VERIFY BEFORE PARSE. The only door to the app. Pure, total, fail-closed.
//
// In order, on the RAW bytes:
//   1 size     — exactly one of the lengths the layout allows (wire.rawCheck)
//   2 magic    — 'BRK1' v1
//   3 schema   — the payload grammar, byte by byte (no decoding)
//   4 sender   — a pinned key exists for this sender id (keys never travel in packets)
//   5 signature— Ed25519 over DOMAIN ‖ header ‖ payload (one algorithm, no algorithm field, domain-separated)
//   6 counter  — exactly the sender's last admitted counter + 1 (inside the signed bytes: no window, no gaps,
//                no rollover, and a malleated signature cannot make a replay fresh)
//   then, and only then: parse — and the parsed message is handed out as an ADMITTED, frozen object.
//
// Every exception anywhere (a hostile byte string, a broken injected function, a bad key) is a refusal — there
// is no path on which a failure admits. The crypto, the key table and the counter store are injected (ctx), so
// this file has no I/O, no clock, no randomness and no floating point: the same bytes and the same state give
// the same verdict on every machine.
// ════════════════════════════════════════════════════════════════
import { rawCheck, signedBytes, headerOf, parse } from './wire.mjs';

export const STAGES = Object.freeze(['size', 'magic', 'schema', 'sender', 'signature', 'counter', 'error', 'admitted']);

const ADMITTED = new WeakSet();
/** True only for a message object this gate itself admitted — the app's tripwire (referee.mjs). */
export const isAdmitted = (m) => typeof m === 'object' && m !== null && ADMITTED.has(m);

const no = (stage, reason) => Object.freeze({ admit: false, stage, reason });

/**
 * ctx: { keyFor(senderId) → 32-byte Uint8Array | null,
 *        verify(messageBytes, signatureBytes, publicKeyBytes) → boolean   (synchronous),
 *        lastCounter(senderId) → bigint (0n before the first packet) }
 * → { admit: true, stage: 'admitted', msg } | { admit: false, stage, reason }
 */
export function decide(bytes, ctx) {
  try {
    const raw = rawCheck(bytes);
    if (!raw.ok) return no(raw.stage, raw.reason);
    const h = headerOf(bytes, raw.n);
    const key = ctx.keyFor(h.sender);
    if (!(key instanceof Uint8Array) || key.length !== 32) return no('sender', 'no pinned key for sender ' + h.sender);
    if (ctx.verify(signedBytes(bytes, raw.n), h.sig, key) !== true) return no('signature', 'the signature does not verify');
    const last = ctx.lastCounter(h.sender);
    if (typeof last !== 'bigint') return no('error', 'the counter store gave no counter');
    const expected = last + 1n;                                   // the one counter that may follow (computed once)
    if (h.counter <= last) return no('counter', 'replay — counter ' + h.counter + ' is not after ' + last);
    if (h.counter !== expected) return no('counter', 'out of order — expected counter ' + expected + ', got ' + h.counter);
    const msg = parse(bytes);
    if (!msg) return no('error', 'the parser refused a packet the raw check accepted');   // unreachable by construction
    Object.freeze(msg);
    ADMITTED.add(msg);
    return Object.freeze({ admit: true, stage: 'admitted', msg });
  } catch {
    return no('error', 'the gate failed closed');
  }
}
