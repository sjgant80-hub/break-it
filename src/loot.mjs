// ════════════════════════════════════════════════════════════════
// loot.mjs — game time. Pure (signing injected); the drops are EARNED, never claimable by asking.
//
//   LEGENDARY  The Breaker's Rune  — dropped only when the REFEREE proves a breach: something reached the app the
//              gate should never have admitted. A certificate signed by the node, bound to the exact breach packet
//              and inscribed with whatever the breaker smuggled inside it. Anyone can re-run that packet against the
//              published gate and see the referee condition for themselves — the rune proves its own story.
//   EPIC       Autoimmune  — an antibody dropped a packet the gate would have admitted (the immune system turned on
//              the body). Every on-sight drop is double-checked by the gate; if it ever happens, the packet is
//              admitted anyway (the gate is the authority) and the Epic drops.
//   RARE       Rune Shards  — one per NOVEL attack (a fingerprint the immune system had never seen), credited to the
//              source that found it first. Every shard is an antibody the attacker fed the system.
//   QUESTS     the challenge's vectors, lit up from the attacker's own journal.
// ════════════════════════════════════════════════════════════════
import { parse } from './wire.mjs';

export const RUNE_DOMAIN = 'BREAK-IT/rune/v1|';
export const QUESTS = Object.freeze([
  { id: 'forge', name: 'Forge a packet', families: ['forgery', 'unknown-sender'] },
  { id: 'replay', name: 'Replay or race a packet', families: ['replay', 'out-of-order'] },
  { id: 'parser', name: 'Reach the parser before verification', families: ['malformed', 'truncation', 'extension', 'http'] },
  { id: 'schema', name: 'Escape the schema', families: ['schema-escape'] },
  { id: 'dos', name: 'Lock, exhaust or crash the gate', families: ['flood'] },
  { id: 'immune', name: 'Turn the immune system on the body', families: ['autoimmune'] },
  { id: 'state', name: 'Fork or desync the ledger', families: [], offline: 'attack the ledger file itself — the node refuses to start on any altered byte' },
  { id: 'determinism', name: 'Make one input verify differently on two machines', families: [], offline: 'CI re-runs the vectors on another OS; compare receipts/vectors.json' },
]);

const printable = (s) => String(s).replace(/[^\x20-\x7e]/g, '?');

/** What the breaker wrote into the breach packet: its value, its key, or the first bytes in hex. At most 80 chars. */
export function inscription(bytes) {
  try {
    const m = parse(bytes);
    if (m && typeof m.value === 'string' && m.value.length) return printable(m.value).slice(0, 80);
    if (m && typeof m.key === 'string') return printable(m.key).slice(0, 80);
  } catch { /* fall through */ }
  return 'hex:' + Buffer.from(bytes instanceof Uint8Array ? bytes.subarray(0, 32) : []).toString('hex');
}

/** The exact text a rune's signature covers. */
export function runeMaterial(r) {
  return RUNE_DOMAIN + JSON.stringify([r.tier, r.name, r.node, r.at, r.seq, r.why, r.packet, r.inscription]);
}

/** Mint the Legendary. sign(bytes) → signature bytes (the node key). */
export function mintRune({ node, at, seq, why, packet }, sign) {
  const bytes = new Uint8Array(Buffer.from(String(packet), 'hex'));
  const r = { tier: 'LEGENDARY', name: "The Breaker's Rune", node: String(node), at: String(at), seq: Number(seq) || 0, why: String(why).slice(0, 200), packet: String(packet), inscription: inscription(bytes) };
  return { ...r, sig: Buffer.from(sign(Buffer.from(runeMaterial(r)))).toString('hex') };
}

/** Shards and quest progress from journal records (their own attacks). → { shards: {source: n}, quests: [...] } */
export function questLog(records) {
  const rs = Array.isArray(records) ? records : [];
  const shards = {}, seen = {};
  for (const r of rs) {
    if (!r || typeof r !== 'object') continue;
    if (typeof r.family === 'string') seen[r.family] = (seen[r.family] || 0) + 1;
    if (r.novel === true && typeof r.source === 'string' && !String(r.source).startsWith('peer:')) shards[r.source] = (shards[r.source] || 0) + 1;
  }
  const quests = QUESTS.map((q) => {
    const attempts = q.families.reduce((t, f) => t + (seen[f] || 0), 0);
    return { id: q.id, name: q.name, attempts, status: q.offline ? 'offline — ' + q.offline : attempts ? 'attempted ' + attempts + '× — every one refused' : 'not attempted', won: false };
  });
  return { shards, quests };
}
