// client.mjs — the legitimate sender. It holds sender 1's private key (secrets/, never served) and sends real,
// signed traffic. Every packet it sends is also written to data/captured.hex — "sniffed" traffic for the attacker
// to replay, splice and tamper with. Capturing it is the starting point of the challenge, not a win.
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { encodeUnsigned, withSignature, signedBytes, OPS } from './wire.mjs';
import { signWith } from './keys.mjs';

const KEYS = ['balance', 'name', 'status', 'visits', 'note', 'level'];
const VALUES = ['active', 'ok', 'hello world', 'green', 'ready', 'v1.2'];

/** A deterministic, ordinary op stream: mostly ADD and SET, the odd DEL. */
export function nextOp(i) {
  const key = KEYS[i % KEYS.length];
  if (i % 11 === 10) return { op: OPS.DEL, key };
  if (i % 3 === 0) return { op: OPS.SET, key, value: VALUES[i % VALUES.length] };
  return { op: OPS.ADD, key, delta: (i % 7) + 1 };
}

export function makeClient({ privateKey, sender = 1, startCounter = 1n, capturePath = null }) {
  const sign = signWith(privateKey);
  let counter = startCounter;
  return {
    get counter() { return counter; },
    /** Build the next signed packet (and capture it). */
    next(op) {
      const u = encodeUnsigned({ sender, counter, ...op });
      if (!u) throw new Error('the client built an invalid packet');
      const n = (u[14] << 8) | u[15];
      const p = withSignature(u, sign(signedBytes(new Uint8Array([...u, ...new Uint8Array(64)]), n)));
      counter += 1n;
      if (capturePath) { mkdirSync(dirname(capturePath), { recursive: true }); appendFileSync(capturePath, Buffer.from(p).toString('hex') + '\n'); }
      return p;
    },
  };
}

/** POST one packet. → { status, body } */
export async function send(url, packet) {
  const r = await fetch(new URL('/packet', url), { method: 'POST', headers: { 'content-type': 'application/octet-stream' }, body: packet });
  let body = null;
  try { body = await r.json(); } catch { body = null; }
  return { status: r.status, body };
}
