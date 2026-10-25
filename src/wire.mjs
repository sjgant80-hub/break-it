// ════════════════════════════════════════════════════════════════
// wire.mjs — the one exact packet layout, its raw check, and its parser. Pure, total, gated.
//
//   [0..4)        magic      'BRK1'
//   [4]           version    1
//   [5]           sender     0..255 — a pinned public key per id (no key ever travels in a packet)
//   [6..14)       counter    u64 big-endian, 1.. — must be exactly the sender's last + 1 (gate.mjs)
//   [14..16)      length N   u16 big-endian, the payload's byte count, 3..MAX_PAYLOAD
//   [16..16+N)    payload    one op, exact grammar below
//   [16+N..+64)   signature  Ed25519 over DOMAIN ‖ bytes[0 .. 16+N)
//
// payload grammar — every byte is checked on the RAW bytes; nothing is decoded until all of it passed:
//   SET  0x01  keyLen K  key  valLen V  value       N = 3 + K + V      key: [a-z][a-z0-9_]{0,31}
//   DEL  0x02  keyLen K  key                         N = 2 + K          value: printable ASCII 0x20..0x7e,
//   ADD  0x03  keyLen K  key  delta (i32 BE)         N = 6 + K          0..MAX_VALUE bytes; delta |d| ≤ MAX_DELTA
//   REC  0x05  account (u32 BE)  period (u16 BE)  amount (u32 BE)   N = 11 — one record of an ingest feed (a payment
//              posted to an account): account 1..MAX_ACCOUNT, period = months since January 2000 (0..MAX_PERIOD),
//              amount 0..MAX_AMOUNT. No key, no text: three integers, each range-checked on the raw bytes. (0x04 is not
//              an op: the red-team battery's "unknown op" vector is pinned to it.)
//
// Why it cannot be read two ways: rawCheck accepts a byte string only if it is the ONE encoding of what parse
// returns — encode(parse(b)) is byte-identical to b for every b rawCheck accepts (pinned by an exhaustive test).
// No JSON, no text decoding of untrusted bytes, no optional fields, no trailing bytes, no alternative lengths.
// ════════════════════════════════════════════════════════════════

export const MAGIC = Object.freeze([0x42, 0x52, 0x4b, 0x31]);           // 'BRK1'
export const VERSION = 1;
export const HEADER = 16, SIG = 64, MAX_PAYLOAD = 256, MAX_KEY = 32, MAX_VALUE = 200, MAX_DELTA = 1000000;
export const MIN_PACKET = HEADER + 3 + SIG, MAX_PACKET = HEADER + MAX_PAYLOAD + SIG;
export const OPS = Object.freeze({ SET: 1, DEL: 2, ADD: 3, REC: 5 });
export const REC_N = 11, MAX_ACCOUNT = 99999999, MAX_PERIOD = 1199, MAX_AMOUNT = 100000000;
export const DOMAIN = 'BREAK-IT/gate/v1\u0000';                          // signatures are domain-separated

const isBytes = (b) => b instanceof Uint8Array;
const isLower = (c) => c >= 0x61 && c <= 0x7a;
const isKeyTail = (c) => isLower(c) || (c >= 0x30 && c <= 0x39) || c === 0x5f;
const isPrintable = (c) => c >= 0x20 && c <= 0x7e;
const u16 = (b, o) => (b[o] << 8) | b[o + 1];
const u32 = (b, o) => ((b[o] << 24) >>> 0) + ((b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);

/** A key at b[o..o+k): k in 1..MAX_KEY, first byte a-z, the rest a-z 0-9 _. */
function keyOk(b, o, k) {
  if (!(k >= 1 && k <= MAX_KEY) || !isLower(b[o])) return false;
  for (let i = 1; i < k; i++) if (!isKeyTail(b[o + i])) return false;
  return true;
}

/** A REC record's three fields on raw bytes. null if well-formed, else the reason. */
function recordWhy(b, o, n) {
  if (n !== REC_N) return 'a record is exactly ' + REC_N + ' bytes';
  const account = u32(b, o + 1), period = u16(b, o + 5), amount = u32(b, o + 7);
  if (!(account >= 1 && account <= MAX_ACCOUNT)) return 'an account is 1–' + MAX_ACCOUNT;
  if (!(period <= MAX_PERIOD)) return 'a period is a month from January 2000 to December 2099 (0–' + MAX_PERIOD + ')';
  return amount <= MAX_AMOUNT ? null : 'an amount is 0–' + MAX_AMOUNT;
}

/** The payload grammar on raw bytes. null if well-formed, else the reason. */
function payloadWhy(b, o, n) {
  const op = b[o];
  if (op === OPS.REC) return recordWhy(b, o, n);
  const k = b[o + 1];
  if (op === OPS.SET) {
    if (!keyOk(b, o + 2, k)) return 'a key must be 1–32 of a-z 0-9 _, starting a-z';
    const v = b[o + 2 + k];
    if (!(v <= MAX_VALUE)) return 'a value is at most ' + MAX_VALUE + ' bytes';
    if (n !== 3 + k + v) return 'the payload length does not match its fields';
    for (let i = 0; i < v; i++) if (!isPrintable(b[o + 3 + k + i])) return 'a value is printable ASCII only';
    return null;
  }
  if (op === OPS.DEL) {
    if (!keyOk(b, o + 2, k)) return 'a key must be 1–32 of a-z 0-9 _, starting a-z';
    return n === 2 + k ? null : 'the payload length does not match its fields';
  }
  if (op === OPS.ADD) {
    if (!keyOk(b, o + 2, k)) return 'a key must be 1–32 of a-z 0-9 _, starting a-z';
    if (n !== 6 + k) return 'the payload length does not match its fields';
    const d = new DataView(b.buffer, b.byteOffset + o + 2 + k, 4).getInt32(0);
    return d >= -MAX_DELTA && d <= MAX_DELTA ? null : 'a delta is at most ±' + MAX_DELTA;
  }
  return 'unknown op';
}

/**
 * The raw check — structure only, on the raw bytes, before any signature work and long before parsing.
 * → { ok: true, n } or { ok: false, stage, reason }   stage ∈ size | magic | schema
 */
export function rawCheck(bytes) {
  if (!isBytes(bytes)) return { ok: false, stage: 'size', reason: 'not bytes' };
  if (bytes.length < MIN_PACKET || bytes.length > MAX_PACKET) return { ok: false, stage: 'size', reason: 'a packet is ' + MIN_PACKET + '–' + MAX_PACKET + ' bytes' };
  if (MAGIC.some((m, i) => bytes[i] !== m) || bytes[4] !== VERSION) return { ok: false, stage: 'magic', reason: 'not a BRK1 v1 packet' };
  const n = u16(bytes, 14);
  if (bytes.length !== HEADER + n + SIG) return { ok: false, stage: 'size', reason: 'the packet length does not match its header' };
  const why = payloadWhy(bytes, HEADER, n);
  return why ? { ok: false, stage: 'schema', reason: why } : { ok: true, n };
}

/** The exact bytes the signature covers: DOMAIN ‖ header ‖ payload. Only for a packet rawCheck accepted. */
export function signedBytes(bytes, n) {
  const d = DOMAIN.split('').map((c) => c.charCodeAt(0));
  const out = new Uint8Array(d.length + HEADER + n);
  out.set(d, 0);
  out.set(bytes.subarray(0, HEADER + n), d.length);
  return out;
}

/** The header fields the gate needs before it parses anything: who, which counter, where the signature is. */
export function headerOf(bytes, n) {
  return { sender: bytes[5], counter: new DataView(bytes.buffer, bytes.byteOffset + 6, 8).getBigUint64(0), sig: bytes.subarray(HEADER + n, HEADER + n + SIG) };
}

const ascii = (b, o, len) => String.fromCharCode(...b.subarray(o, o + len));

/** The parser. Called ONLY on a packet that passed rawCheck, the signature and the counter (gate.mjs). */
export function parse(bytes) {
  const r = rawCheck(bytes);
  if (!r.ok) return null;                         // never reachable through the gate; total for direct callers
  const h = headerOf(bytes, r.n), o = HEADER, op = bytes[o];
  if (op === OPS.REC) return { sender: h.sender, counter: h.counter, op, account: u32(bytes, o + 1), period: u16(bytes, o + 5), amount: u32(bytes, o + 7) };
  const k = bytes[o + 1], key = ascii(bytes, o + 2, k);
  const base = { sender: h.sender, counter: h.counter, op, key };
  if (op === OPS.SET) return { ...base, value: ascii(bytes, o + 3 + k, bytes[o + 2 + k]) };
  if (op === OPS.ADD) return { ...base, delta: new DataView(bytes.buffer, bytes.byteOffset + o + 2 + k, 4).getInt32(0) };
  return base;
}

/** The one encoding of a message, unsigned (header + payload). null if any field is out of the grammar. */
export function encodeUnsigned(m) {
  const o = m && typeof m === 'object' ? m : {};
  if (!Number.isInteger(o.sender) || o.sender < 0 || o.sender > 255) return null;
  if (typeof o.counter !== 'bigint' || o.counter < 1n || o.counter >= 2n ** 64n) return null;
  let body;
  if (o.op === OPS.REC) {
    const int = (x, lo, hi) => Number.isInteger(x) && x >= lo && x <= hi;
    if (!int(o.account, 1, MAX_ACCOUNT) || !int(o.period, 0, MAX_PERIOD) || !int(o.amount, 0, MAX_AMOUNT)) return null;
    body = [OPS.REC, (o.account >>> 24) & 0xff, (o.account >>> 16) & 0xff, (o.account >>> 8) & 0xff, o.account & 0xff,
      o.period >> 8, o.period & 0xff, (o.amount >>> 24) & 0xff, (o.amount >>> 16) & 0xff, (o.amount >>> 8) & 0xff, o.amount & 0xff];
    return finish(o, body);
  }
  if (typeof o.key !== 'string') return null;
  // one char = one byte, ASCII only: a char above 0x7f would be truncated by the byte array ('š' 0x161 → 'a' 0x61)
  // and the client would sign a key it was never shown
  const key = Array.from(o.key, (c) => c.charCodeAt(0));
  if (key.some((c) => c > 0x7f)) return null;
  if (o.op === OPS.SET) {
    if (typeof o.value !== 'string') return null;
    const v = Array.from(o.value, (c) => c.charCodeAt(0));
    if (v.some((c) => c > 0x7f)) return null;
    body = [OPS.SET, key.length, ...key, v.length, ...v];
  } else if (o.op === OPS.DEL) body = [OPS.DEL, key.length, ...key];
  else if (o.op === OPS.ADD) {
    if (!Number.isInteger(o.delta)) return null;
    const d = new Uint8Array(4); new DataView(d.buffer).setInt32(0, o.delta | 0);
    if ((o.delta | 0) !== o.delta) return null;
    body = [OPS.ADD, key.length, ...key, ...d];
  } else return null;
  return finish(o, body);
}

/** Header + body, checked against the very grammar the gate uses (a placeholder signature appended). */
function finish(o, body) {
  if (body.length > MAX_PAYLOAD) return null;
  const out = new Uint8Array(HEADER + body.length);
  out.set(MAGIC, 0); out[4] = VERSION; out[5] = o.sender;
  new DataView(out.buffer).setBigUint64(6, o.counter);
  out[14] = body.length >> 8; out[15] = body.length & 0xff;
  out.set(body, HEADER);
  // the encoder enforces the same grammar the gate does: check it with a placeholder signature appended
  const probe = new Uint8Array(out.length + SIG); probe.set(out, 0);
  return rawCheck(probe).ok ? out : null;
}

/** Signature appended: the complete packet. */
export function withSignature(unsigned, sig) {
  if (!isBytes(unsigned) || !isBytes(sig) || sig.length !== SIG) return null;
  const out = new Uint8Array(unsigned.length + SIG); out.set(unsigned, 0); out.set(sig, unsigned.length);
  return rawCheck(out).ok ? out : null;
}
