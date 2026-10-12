// test/helpers.mjs — shared builders for the kernel tests. Deterministic keys, real packets.
import { createHash } from 'node:crypto';
import { encodeUnsigned, signedBytes, withSignature, SIG, OPS } from '../src/wire.mjs';
import { keyFromSeed, rawPublic, signWith, keyTable } from '../src/keys.mjs';

export const sha256hex = (s) => createHash('sha256').update(s).digest('hex');
export const hex = (u8) => Buffer.from(u8).toString('hex');
export const seedKey = (b) => keyFromSeed(new Uint8Array(32).fill(b));
export const S1 = seedKey(1), S2 = seedKey(2), ATTACKER = seedKey(0xee);
export const pubHex = (k) => hex(rawPublic(k));

/** A real signed packet. op defaults to SET. Sign with `signer` (default S1), optionally a wrong domain. */
export function packet({ sender = 1, counter = 1n, op = OPS.SET, key = 'name', value = 'alice', delta = 1, signer = S1, domain } = {}) {
  const u = encodeUnsigned({ sender, counter, op, key, value, delta });
  if (!u) throw new Error('test built an invalid packet: ' + JSON.stringify({ sender, counter, op, key }));
  const n = (u[14] << 8) | u[15];
  const toSign = signedBytes(new Uint8Array([...u, ...new Uint8Array(SIG)]), n);
  const material = domain === undefined ? toSign : new Uint8Array([...Array.from(domain, (c) => c.charCodeAt(0)), ...u]);
  return withSignature(u, signWith(signer)(material));
}

/** A gate ctx for one pinned sender (id 1 → S1 by default), with a settable last counter. */
export function ctxFor({ pubkeys = { 1: pubHex(S1) }, last = 0n } = {}) {
  const t = keyTable(pubkeys);
  const lasts = new Map([[1, last]]);
  return { ...t, keyFor: t.keyFor, verify: t.verify, lastCounter: (s) => (lasts.has(s) ? lasts.get(s) : 0n), set: (s, c) => lasts.set(s, c) };
}
