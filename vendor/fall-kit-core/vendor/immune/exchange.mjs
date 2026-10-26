// ════════════════════════════════════════════════════════════════
// exchange.mjs — the antibody bus. Pure, total, gated. Browser-safe (no Buffer); crypto is injected.
//
// A centerless, signed feed of ATTACKS between gates. A node that refused an attack bundles the raw bytes, signs
// the bundle with its own key, and publishes it. A subscriber verifies the bundle came from a PINNED peer and
// re-signs nothing — it will re-run every antigen through its OWN gate before it trusts a single byte (subscribe.mjs).
// The relay that carries bundles is untrusted: it cannot forge one (bundles are signed) and cannot make a
// subscriber adopt anything (the subscriber re-runs on its own gate). So a zero-day caught by one gate can
// immunise every subscriber — and no bundle, however it arrives, can turn a gate against a packet it would admit.
//
// The bundle is signed over EXCHANGE_DOMAIN ‖ from ‖ the exact antigen list, so the from-id and the antigens are
// bound together: you cannot lift a signature onto a different sender or a swapped list (the red-team proves it).
// ════════════════════════════════════════════════════════════════

export const EXCHANGE_DOMAIN = 'IMMUNE-EXCHANGE/bundle/v1\u0000';
export const MAX_ANTIGENS = 64, MAX_ANTIGEN_HEX = 4096;   // a bundle carries at most 64 antigens, each ≤ 2KB of bytes
const HEX = /^(?:[0-9a-f]{2})+$/;
const HEX64 = /^[0-9a-f]{64}$/;

export const toHex = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0'); return s; };
export const fromHex = (h) => { const s = String(h); const o = new Uint8Array(s.length >> 1); for (let i = 0; i < o.length; i++) o[i] = parseInt(s.substr(i * 2, 2), 16); return o; };

/** The exact bytes a bundle's signature covers: the domain, the from-id and the antigen list, bound together. */
export function bundleMaterial(from, antigens) {
  return EXCHANGE_DOMAIN + String(from) + '|' + JSON.stringify(Array.isArray(antigens) ? antigens : []);
}

/**
 * Make a signed bundle. from = the publisher's raw public key, hex. antigens = attack bytes as hex strings.
 * sign(messageBytes) → signature bytes (the publisher's key, injected). Malformed antigens are dropped, not signed.
 */
export function makeBundle(from, antigens, sign) {
  const list = (Array.isArray(antigens) ? antigens : [])
    .filter((a) => typeof a === 'string' && HEX.test(a) && a.length <= MAX_ANTIGEN_HEX)
    .slice(0, MAX_ANTIGENS);
  const sig = sign(new TextEncoder().encode(bundleMaterial(from, list)));
  return { v: 1, from: String(from), antigens: list, sig: toHex(sig instanceof Uint8Array ? sig : new Uint8Array(sig)) };
}

/**
 * Verify a bundle BEFORE any antigen is looked at. isPinned(fromHex) → boolean (do we pin this peer's key?).
 * verify(messageBytes, signatureBytes, fromHex) → boolean (synchronous, never throws — injected crypto).
 * → { ok: true, from, antigens } | { ok: false, reason }. Pure, total: any hostile bundle is a clean refusal.
 */
export function verifyBundle(bundle, isPinned, verify) {
  try {
    const b = (bundle && typeof bundle === 'object' && !Array.isArray(bundle)) ? bundle : {};
    // one condition per check, so each refusal is reachable on its own (and the happy path proves none mis-fires)
    if (b.v !== 1) return { ok: false, reason: 'not a v1 bundle' };
    if (typeof b.from !== 'string') return { ok: false, reason: 'from is not a string' };
    if (!HEX64.test(b.from)) return { ok: false, reason: 'from is not a 32-byte key' };
    if (typeof isPinned !== 'function') return { ok: false, reason: 'no pin check' };
    if (isPinned(b.from) !== true) return { ok: false, reason: 'not from a pinned peer' };
    if (!Array.isArray(b.antigens)) return { ok: false, reason: 'antigens is not a list' };
    if (b.antigens.length === 0) return { ok: false, reason: 'the antigen list is empty' };
    if (b.antigens.length > MAX_ANTIGENS) return { ok: false, reason: 'the antigen list is too long' };
    if (!b.antigens.every((a) => typeof a === 'string')) return { ok: false, reason: 'an antigen is not a string' };
    if (!b.antigens.every((a) => HEX.test(a))) return { ok: false, reason: 'an antigen is not hex' };
    if (!b.antigens.every((a) => a.length <= MAX_ANTIGEN_HEX)) return { ok: false, reason: 'an antigen is too long' };
    if (typeof b.sig !== 'string') return { ok: false, reason: 'the signature is not a string' };
    if (!HEX.test(b.sig)) return { ok: false, reason: 'the signature is not hex' };
    if (b.sig.length !== 128) return { ok: false, reason: 'the signature is not 64 bytes' };
    const ok = verify(new TextEncoder().encode(bundleMaterial(b.from, b.antigens)), fromHex(b.sig), b.from);
    return ok === true ? { ok: true, from: b.from, antigens: b.antigens } : { ok: false, reason: 'the bundle signature does not verify' };
  } catch { return { ok: false, reason: 'verify failed closed' }; }
}
