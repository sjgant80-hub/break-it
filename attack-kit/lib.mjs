// attack-kit/lib.mjs — the shared pieces of the attack kit: build any packet (valid or not), sign it with any key,
// send raw bytes (or a raw HTTP request), read the captured traffic. Everything here is for attacking; none of it is
// trusted by the node.
import { readFileSync, existsSync } from 'node:fs';
import net from 'node:net';
import { generateKeyPairSync, sign as edSign } from 'node:crypto';
import { MAGIC, VERSION, HEADER, SIG, DOMAIN, OPS, encodeUnsigned } from '../src/wire.mjs';

export { OPS, HEADER, SIG, DOMAIN };
export const fromHex = (h) => new Uint8Array(Buffer.from(String(h).trim(), 'hex'));
export const toHex = (u8) => Buffer.from(u8).toString('hex');
export const randomKey = () => generateKeyPairSync('ed25519').privateKey;

/** Raw header + payload with NO validation (for building packets the grammar forbids). */
export function rawPacket({ sender = 1, counter = 1n, payload = [], magic = MAGIC, version = VERSION, declaredLength = null }) {
  const body = Uint8Array.from(payload);
  const out = new Uint8Array(HEADER + body.length);
  out.set(magic.slice(0, 4), 0); out[4] = version; out[5] = sender & 0xff;
  new DataView(out.buffer).setBigUint64(6, BigInt.asUintN(64, BigInt(counter)));
  const n = declaredLength === null ? body.length : declaredLength;
  out[14] = (n >> 8) & 0xff; out[15] = n & 0xff;
  out.set(body, HEADER);
  return out;
}

/** Sign header+payload the way the gate expects (DOMAIN ‖ bytes) — or without the domain, or over anything. */
export function signRaw(unsigned, privateKey, { domain = DOMAIN } = {}) {
  const d = Buffer.from(domain, 'latin1');
  const sig = new Uint8Array(edSign(null, Buffer.concat([d, Buffer.from(unsigned)]), privateKey));
  const out = new Uint8Array(unsigned.length + SIG); out.set(unsigned, 0); out.set(sig, unsigned.length);
  return out;
}

/** A well-formed message, unsigned (null if out of grammar — use rawPacket for those). */
export const message = (m) => encodeUnsigned(m);

/** POST raw bytes to /packet. */
export async function post(url, bytes, headers = {}) {
  const r = await fetch(new URL('/packet', url), { method: 'POST', headers: { 'content-type': 'application/octet-stream', ...headers }, body: bytes });
  let body = null;
  try { body = await r.json(); } catch { body = null; }
  return { status: r.status, body };
}

/** Send a hand-written HTTP request on a raw socket (chunked bodies, lying Content-Length, slow bodies…). */
export function rawHttp(url, text, { slowMs = 0, chunks = null, closeAfterMs = 4000 } = {}) {
  const u = new URL(url);
  return new Promise((resolve) => {
    const sock = net.connect(Number(u.port), u.hostname);
    let out = '';
    const timer = setTimeout(() => { sock.destroy(); resolve(out || '(no response)'); }, closeAfterMs);
    sock.on('data', (d) => { out += d.toString('latin1'); });
    sock.on('close', () => { clearTimeout(timer); resolve(out || '(closed)'); });
    sock.on('error', () => { clearTimeout(timer); resolve(out || '(error)'); });
    sock.on('connect', async () => {
      if (!chunks) { sock.write(text); return; }
      for (const c of chunks) { sock.write(c); if (slowMs) await new Promise((r) => setTimeout(r, slowMs)); }
    });
  });
}

/** The legitimate client's captured traffic (data/captured.hex), as packets. */
export function captured(path = 'data/captured.hex') {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').split('\n').filter((l) => /^[0-9a-f]+$/.test(l)).map(fromHex);
}
