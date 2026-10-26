// ════════════════════════════════════════════════════════════════
// core/roster.mjs — who is in the mesh: the founder's signed list of member cards. Organ 7 of the shared foundation
// (Phase 3, pass 2: claim J1 in core/phase3/claims.json).
//
// Pinning is the only way a node trusts a peer, and whether to trust a key is the owner's decision. In a mesh the
// owner makes it once, as the founder: a roster names every member's card and the founder signs it. A node that holds
// the founder's key reads the roster, checks the founder's signature and every card in it, and pins the members; a
// card the roster does not name is not pinned, however well it is signed.
//
//   makeRoster(founder, cards)      → { ok, roster } | { ok: false, why }     founder = an identity (identity.mjs)
//   readRoster(roster, founderId)   → { ok, cards, ids } | { ok: false, why }  every check, or a refusal naming it
//   onRoster(read, card)            → is this exact card one the roster names?
//   rosterChanges(read, pinned, me) → { pin: [cards], unpin: [ids] }   what a node does to match a roster it has read:
//                                     pin the members it lacks, and unpin every key the roster no longer names
// Powered by the Konomi architecture, created by Thomas Frumkin.
// ════════════════════════════════════════════════════════════════
import { readCard, stableJson } from './node.mjs';
import { hex, unhex, verifyBytes } from './identity.mjs';

export const ROSTER = 'fall-kit.roster.v1';
export const MAX_MEMBERS = 256;
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const HEX64 = /^[0-9a-f]{64}$/;
const enc = (x) => new TextEncoder().encode(stableJson(x));

/** The founder's roster of these cards, signed. */
export async function makeRoster(founder, cards) {
  if (!founder || typeof founder.id !== 'string' || typeof founder.sign !== 'function') return { ok: false, why: 'a roster needs its founder' };
  if (!Array.isArray(cards) || cards.length === 0 || cards.length > MAX_MEMBERS) return { ok: false, why: 'a roster names 1–' + MAX_MEMBERS + ' cards' };
  if (new Set(cards.map((c) => String(c && c.id))).size !== cards.length) return { ok: false, why: 'a member is named twice' };
  const sorted = cards.slice().sort((a, b) => (String(a && a.id) < String(b && b.id) ? -1 : 1));
  const body = { schema: ROSTER, founder: founder.id, cards: sorted };
  return { ok: true, roster: { ...body, sig: hex(await founder.sign(enc(body))) } };
}

/** The roster, checked: its shape, the founder's signature, and every card in it. */
export async function readRoster(roster, founderId) {
  if (!isObj(roster) || roster.schema !== ROSTER) return { ok: false, why: 'not a ' + ROSTER + ' roster' };
  if (typeof founderId !== 'string' || !HEX64.test(founderId) || roster.founder !== founderId) return { ok: false, why: 'the roster is not the founder’s' };
  if (!Array.isArray(roster.cards) || roster.cards.length === 0 || roster.cards.length > MAX_MEMBERS) return { ok: false, why: 'a roster names 1–' + MAX_MEMBERS + ' cards' };
  if (typeof roster.sig !== 'string' || !/^[0-9a-f]{128}$/.test(roster.sig)) return { ok: false, why: 'a roster is signed' };
  const { sig, ...body } = roster;
  if (!(await verifyBytes(founderId, enc(body), unhex(sig)))) return { ok: false, why: 'the founder did not sign this roster' };
  const ids = [];
  for (const c of roster.cards) {
    const r = await readCard(c);
    if (!r.ok) return { ok: false, why: 'a card in the roster is not good: ' + r.why };
    if (ids.includes(c.id)) return { ok: false, why: 'a member is named twice' };
    ids.push(c.id);
  }
  return { ok: true, cards: roster.cards, ids };
}

/** What a node must change to match a roster it has read: the members it has not pinned (never itself), and the keys it
 *  has pinned that the roster no longer names — the founder drops a member by signing a roster without it. */
export function rosterChanges(read, pinnedIds, selfId) {
  if (!isObj(read) || read.ok !== true || !Array.isArray(read.cards)) return { pin: [], unpin: [] };
  const named = new Set(read.cards.map((c) => c.id)), have = new Set(Array.isArray(pinnedIds) ? pinnedIds : []);
  return { pin: read.cards.filter((c) => c.id !== selfId && !have.has(c.id)), unpin: [...have].filter((id) => !named.has(id)).sort() };
}

/** Is this exact card one the read roster names: the same key, and the same signed card? */
export function onRoster(read, card) {
  if (!isObj(read) || read.ok !== true || !Array.isArray(read.cards) || !isObj(card)) return false;
  return read.cards.some((c) => c.id === card.id && c.sig === card.sig);
}
