// ════════════════════════════════════════════════════════════════
// light/vault.mjs — many files as one LIGHT vault: how a store (the memory, a ledger, a folder of records) is kept in
// LIGHT. One solid stream, so what files share — headings, keys, whole lines — is paid for once. Every entry carries the
// SHA-256 of its bytes, and unpack refuses the vault unless every one matches; a path that could reach outside its
// folder is refused too. Pure and total.
//
//   'LVT1' · version 1 · dictionary id (u32, 0 = none) · LIGHT codec bytes of:
//      varint count · count × (varint path length · UTF-8 path · varint size · 32-byte SHA-256) · the files' bytes, in order
//
//   pack(entries, { dictId, primed })  → { ok, bytes, files, in }     entries = [{ path, bytes }]
//   unpack(vault, dictFor, { max })    → { ok, entries } | { ok:false, why }
//   safePath(path)                     → whether a path stays inside the folder it is unpacked into
// ════════════════════════════════════════════════════════════════
import { encode, decode, MAX_BYTES } from './codec.mjs';
import { sha256 } from './sha256.mjs';

export const VMAGIC = Object.freeze([0x4c, 0x56, 0x54, 0x31]);  // 'LVT1'
export const VVERSION = 1, VHEADER = 9, MAX_FILES = 100000, MAX_PATH = 1024;
const te = new TextEncoder();

/** A relative path of plain segments: no root, no drive, no '..', no backslash, no control characters. */
export function safePath(p) {
  if (typeof p !== 'string' || p.length === 0 || p.length > MAX_PATH) return false;
  if (p.startsWith('/') || p.includes('\\') || /^[a-zA-Z]:/.test(p) || /[\u0000-\u001f]/.test(p)) return false;
  return p.split('/').every((seg) => seg.length > 0 && seg !== '.' && seg !== '..');
}

function varint(out, n) { for (;;) { const b = n % 128; n = Math.floor(n / 128); if (n === 0) { out.push(b); return; } out.push(b | 128); } }

export function pack(entries, opts) {
  const o = opts && typeof opts === 'object' ? opts : {};
  const dictId = Number.isInteger(o.dictId) && o.dictId >= 0 && o.dictId <= 0xffffffff ? o.dictId : 0;
  if (dictId !== 0 && !o.primed) return { ok: false, why: 'a dictionary id needs its primed model' };
  if (!Array.isArray(entries) || entries.length > MAX_FILES) return { ok: false, why: 'entries is a list of at most ' + MAX_FILES };
  const seen = new Set(), head = [];
  let size = 0;
  varint(head, entries.length);
  for (const e of entries) {
    if (!e || !safePath(e.path)) return { ok: false, why: 'a path is not safe: ' + String(e && e.path).slice(0, 80) };
    if (seen.has(e.path)) return { ok: false, why: 'a path appears twice: ' + e.path };
    if (!(e.bytes instanceof Uint8Array)) return { ok: false, why: 'not bytes: ' + e.path };
    seen.add(e.path);
    const p = te.encode(e.path);
    varint(head, p.length); for (const b of p) head.push(b);
    varint(head, e.bytes.length); for (const b of sha256(e.bytes)) head.push(b);
    size += e.bytes.length;
  }
  if (head.length + size > MAX_BYTES) return { ok: false, why: 'more than ' + MAX_BYTES + ' bytes' };
  const plain = new Uint8Array(head.length + size);
  plain.set(head, 0);
  let at = head.length;
  for (const e of entries) { plain.set(e.bytes, at); at += e.bytes.length; }
  const c = encode(plain, dictId === 0 ? undefined : o.primed);
  if (!c.ok) return c;
  const out = new Uint8Array(VHEADER + c.bytes.length), dv = new DataView(out.buffer);
  out.set(VMAGIC, 0); out[4] = VVERSION; dv.setUint32(5, dictId); out.set(c.bytes, VHEADER);
  return { ok: true, bytes: out, files: entries.length, in: size };
}

export function unpack(vault, dictFor, opts) {
  try {
    if (!(vault instanceof Uint8Array) || vault.length < VHEADER) return { ok: false, why: 'not a LIGHT vault' };
    for (let i = 0; i < 4; i++) if (vault[i] !== VMAGIC[i]) return { ok: false, why: 'not a LIGHT vault: it does not begin with LVT1' };
    if (vault[4] !== VVERSION) return { ok: false, why: 'vault version ' + vault[4] + ' is not spoken here' };
    const dictId = new DataView(vault.buffer, vault.byteOffset, vault.byteLength).getUint32(5);
    const primed = dictId === 0 ? undefined : typeof dictFor === 'function' ? dictFor(dictId) : null;
    if (primed === null || primed === false) return { ok: false, why: 'dictionary ' + dictId.toString(16).padStart(8, '0') + ' is not held here' };
    const o = opts && typeof opts === 'object' ? opts : {};
    const d = decode(vault.subarray(VHEADER), primed, { max: o.max });
    if (!d.ok) return { ok: false, why: 'the vault does not decode: ' + d.why };
    const b = d.bytes;
    let at = 0;
    const num = () => {
      let n = 0, scale = 1;
      for (let k = 0; k < 6; k++) { if (at >= b.length) return -1; const x = b[at++]; n += (x & 127) * scale; scale *= 128; if (x < 128) return n; }
      return -1;
    };
    const count = num();
    if (count < 0 || count > MAX_FILES) return { ok: false, why: 'the file count is not readable' };
    const heads = [], td = new TextDecoder('utf-8', { fatal: true });
    for (let i = 0; i < count; i++) {
      const pl = num();
      if (pl < 1 || pl > MAX_PATH * 4 || at + pl > b.length) return { ok: false, why: 'entry ' + i + ': the path is not readable' };
      let path;
      try { path = td.decode(b.subarray(at, at + pl)); } catch { return { ok: false, why: 'entry ' + i + ': the path is not UTF-8' }; }
      at += pl;
      if (!safePath(path)) return { ok: false, why: 'entry ' + i + ': the path is not safe' };
      const size = num();
      if (size < 0 || at + 32 > b.length) return { ok: false, why: 'entry ' + i + ': the size is not readable' };
      heads.push({ path, size, sha: b.subarray(at, at + 32) });
      at += 32;
    }
    const entries = [], seen = new Set();
    for (const h of heads) {
      if (seen.has(h.path)) return { ok: false, why: 'a path appears twice: ' + h.path };
      seen.add(h.path);
      if (at + h.size > b.length) return { ok: false, why: h.path + ': the vault ends early' };
      const bytes = b.slice(at, at + h.size);
      at += h.size;
      const got = sha256(bytes);
      for (let k = 0; k < 32; k++) if (got[k] !== h.sha[k]) return { ok: false, why: h.path + ': its SHA-256 does not match' };
      entries.push({ path: h.path, bytes });
    }
    if (at !== b.length) return { ok: false, why: 'bytes after the last file' };
    return { ok: true, entries, dictId };
  } catch {
    return { ok: false, why: 'the vault failed closed' };
  }
}
