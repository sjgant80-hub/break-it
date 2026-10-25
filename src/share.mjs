// ════════════════════════════════════════════════════════════════
// share.mjs — what a node says to its pinned peers, in LIGHT (vendor/light, the estate's one codec). Pure, total, gated.
//
// A share was JSON: {"v":1,"from":<64 hex>,"antigens":[<hex>…],"sig":<128 hex>} — every antigen's bytes spelled out in
// hex. As LIGHT it is one signed packet (vendor/light/packet.mjs) whose body is the antigens themselves, as bytes:
//   varint count · count × (varint length · the packet's bytes)
// coded by the LIGHT codec and checked at the receiver's door — magic, version, length, sender, signature, counter —
// before a byte of it is decoded. The receiver then re-runs every antigen through its OWN gate, exactly as before.
//
//   meshOrder(keysHex)           → the mesh's pinned keys, sorted: a node's place in it is its sender byte
//   antigensToBytes(list)        → the body bytes (null if a list or packet is out of bounds)
//   bytesToAntigens(bytes, max)  → { ok, list } | { ok:false, why }
//   nextCounter(last, nowMs)     → the next share counter: after the last one, and never behind the clock
// ════════════════════════════════════════════════════════════════
export const MAX_ANTIGENS = 64, MIN_ANTIGEN = 1, MAX_ANTIGEN = 336;
const HEX64 = /^[0-9a-f]{64}$/;

/** The mesh's keys, unique and sorted, so every node gives every node the same sender byte. null if any key is junk or there are more than 256. */
export function meshOrder(keysHex) {
  if (!Array.isArray(keysHex) || keysHex.length > 256 || !keysHex.every((k) => typeof k === 'string' && HEX64.test(k))) return null;
  return [...new Set(keysHex)].sort();
}

export function antigensToBytes(list) {
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_ANTIGENS) return null;
  const out = [];
  const varint = (n) => { for (;;) { const b = n & 127; n >>>= 7; if (n === 0) { out.push(b); return; } out.push(b | 128); } };
  varint(list.length);
  for (const a of list) {
    if (!(a instanceof Uint8Array) || a.length < MIN_ANTIGEN || a.length > MAX_ANTIGEN) return null;
    varint(a.length);
    for (const b of a) out.push(b);
  }
  return Uint8Array.from(out);
}

export function bytesToAntigens(bytes, max = MAX_ANTIGENS) {
  if (!(bytes instanceof Uint8Array)) return { ok: false, why: 'not bytes' };
  const cap = Number.isInteger(max) && max >= 1 && max <= MAX_ANTIGENS ? max : MAX_ANTIGENS;
  let at = 0;
  const num = () => {
    let n = 0, shift = 0;
    for (let k = 0; k < 3; k++) { if (at >= bytes.length) return -1; const b = bytes[at++]; n |= (b & 127) << shift; shift += 7; if (b < 128) return n; }
    return -1;
  };
  const count = num();
  if (count < 1 || count > cap) return { ok: false, why: 'a share carries 1–' + cap + ' antigens' };
  const list = [];
  for (let i = 0; i < count; i++) {
    const n = num();
    if (n < MIN_ANTIGEN || n > MAX_ANTIGEN) return { ok: false, why: 'antigen ' + i + ' is not 1–' + MAX_ANTIGEN + ' bytes' };
    if (at + n > bytes.length) return { ok: false, why: 'antigen ' + i + ' runs past the body' };
    list.push(bytes.slice(at, at + n));
    at += n;
  }
  if (at !== bytes.length) return { ok: false, why: 'bytes after the last antigen' };
  return { ok: true, list };
}

/** The next share counter: one more than the last, but never behind the node's clock (so a restarted node keeps moving forward). */
export function nextCounter(last, nowMs) {
  const l = typeof last === 'bigint' && last >= 0n ? last : 0n;
  const t = Number.isSafeInteger(nowMs) && nowMs > 0 ? BigInt(nowMs) : 0n;
  return t > l ? t : l + 1n;
}
