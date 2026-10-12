// chain.mjs — the append-only ledger's chain, pure (gated). Each entry commits to the one before it:
//   hash = sha256('BREAK-IT/ledger/v1|' + seq + '|' + prev + '|' + packetHex)
// so removing, reordering, inserting or editing any entry breaks every hash after it. The file I/O, the lock and the
// fsync are ledger.mjs; the gate re-run of every packet at start-up is server.mjs. sha256 is injected (no I/O here).

export const GENESIS = '0'.repeat(64);
const HEX64 = /^[0-9a-f]{64}$/;
const PACKET_HEX = /^(?:[0-9a-f]{2}){1,336}$/;
const KEYS = ['seq', 'prev', 'packet', 'hash'];

export const material = (seq, prev, packetHex) => 'BREAK-IT/ledger/v1|' + seq + '|' + prev + '|' + packetHex;

/** The next entry after `prev` (GENESIS for the first). null if any input is malformed. */
export function entryFor(prev, seq, packetHex, sha256hex) {
  if (typeof prev !== 'string' || !HEX64.test(prev) || !Number.isInteger(seq) || seq < 0) return null;
  if (typeof packetHex !== 'string' || !PACKET_HEX.test(packetHex)) return null;
  return { seq, prev, packet: packetHex, hash: sha256hex(material(seq, prev, packetHex)) };
}

/**
 * Check a whole chain. entries = the parsed lines in file order. → { ok: true, head } or { ok: false, at, reason }.
 * Every entry must have exactly the four fields, consecutive seq from 0, prev = the previous hash, and its own hash.
 */
export function verifyChain(entries, sha256hex) {
  try {
    if (!Array.isArray(entries)) return { ok: false, at: null, reason: 'not a list of entries' };
    let prev = GENESIS;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      if (!e || typeof e !== 'object' || Array.isArray(e)) return { ok: false, at: i, reason: 'entry ' + i + ' is not an object' };
      const keys = Object.keys(e);
      if (keys.length !== KEYS.length || !KEYS.every((k) => keys.includes(k))) return { ok: false, at: i, reason: 'entry ' + i + ' does not have exactly seq, prev, packet, hash' };
      if (e.seq !== i) return { ok: false, at: i, reason: 'entry ' + i + ' is out of sequence' };
      if (e.prev !== prev) return { ok: false, at: i, reason: 'entry ' + i + ' does not follow the entry before it' };
      const want = entryFor(prev, i, e.packet, sha256hex);
      if (!want || want.hash !== e.hash) return { ok: false, at: i, reason: 'entry ' + i + ' has been altered' };
      prev = e.hash;
    }
    return { ok: true, head: prev };
  } catch {
    return { ok: false, at: null, reason: 'the chain check failed closed' };
  }
}
