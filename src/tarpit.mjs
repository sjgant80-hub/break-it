// ════════════════════════════════════════════════════════════════
// tarpit.mjs — the waste. Pure, total, integer-only, gated. Timers and sockets are the server's; this decides and plans.
//
// The rebound law taxes a distrusted source: past BLOCK refusals it must spend work before it is looked at. The tarpit
// is the rung above it, for a CONFIRMED attacker: its refusals are no longer answered at once. The node holds the
// refusal open, drips one inert space a tick for HOLD_MS, then sends the same refusal it would have sent. An attacker
// that waits spends its own time and connection on nothing; one that will not wait never learns why it was refused.
//
// THE FIRM LINES, as rules this kernel keeps and the battery measures:
//   1. SEPARATION — only a refusal a pinned key cannot produce by accident is ever held: a packet of the wrong size,
//      magic or grammar, from an unknown sender, with a bad signature, or a known attack recognised on sight. An
//      admitted packet is answered at once whatever its address; so are a proof-of-work challenge (402: a genuine
//      client on a confirmed address must be able to pay and get through), a replay or out-of-order counter (a genuine
//      retry), and a behaviour refusal of a signed packet. A false positive therefore delays a refusal, never service.
//   2. GRADUATED — below CONFIRM gate refusals from a source nothing is held: the rebound's tax is the rung below.
//   3. BOUNDED — at most CAP holds at once across the node, each at most HOLD_MS long and ticks() spaces; when full,
//      the refusal goes out at once. Fail to the ordinary answer, never to admission.
//   4. INERT — what is dripped is ASCII spaces (0x20) only, ahead of the refusal's own JSON. JSON ignores leading
//      whitespace, so the body still parses as exactly the refusal. No extra header, no redirect, no script, nothing
//      aimed at the source's systems: everything stays on this node, and nothing reaches into the source.
//   5. HARVEST UNCHANGED — the hold comes after the gate has answered, so every refusal is journalled, minted and
//      shared exactly as before. The attack still teaches the herd.
// ════════════════════════════════════════════════════════════════

/** CONFIRM is the rebound ladder's top rung (REBOUND_LADDER.ISOLATE): the source has been refused that many times */
export const TARPIT = Object.freeze({ CONFIRM: 500, HOLD_MS: 20000, DRIP_MS: 1000, CAP: 64 });
/** the refusal stages that are held: none of them can come from a pinned key sending well-formed packets */
export const HELD_STAGES = Object.freeze(['size', 'magic', 'schema', 'sender', 'signature', 'recognised']);
export const SPACE = 0x20;

const nat = (v) => Number.isSafeInteger(v) && v >= 0;
/** the settings, each a whole number in range, or the default: a setting that is not one never widens the tarpit */
export function settings(o) {
  const t = { ...TARPIT };
  if (o && typeof o === 'object') for (const k of Object.keys(TARPIT)) if (nat(o[k]) && o[k] > 0) t[k] = o[k];
  t.DRIP_MS = Math.min(t.DRIP_MS, t.HOLD_MS);
  return Object.freeze(t);
}

/** decide(code, stage, refusals, active, t) → { hold, why } — hold only a confirmed attacker's permanent refusal, with room */
export function decide(code, stage, refusals, active, given = TARPIT) {
  const t = settings(given);
  if (code !== 403) return { hold: false, why: code === 402 ? 'a work challenge — answered at once, so anyone can pay and get through' : 'not a refusal — answered at once' };
  if (typeof stage !== 'string' || !HELD_STAGES.includes(stage)) return { hold: false, why: 'a refusal a genuine client could cause — answered at once' };
  if (!nat(refusals) || refusals < t.CONFIRM) return { hold: false, why: 'not a confirmed attacker — answered at once' };
  if (!nat(active) || active >= t.CAP) return { hold: false, why: 'the tarpit is full — answered at once' };
  return { hold: true, why: 'a confirmed attacker’s refusal — held ' + t.HOLD_MS + ' ms' };
}

/** how many spaces a full hold drips: one a tick, a tick every DRIP_MS, for HOLD_MS */
export const ticks = (t = TARPIT) => (t && nat(t.HOLD_MS) && nat(t.DRIP_MS) && t.DRIP_MS > 0 ? Math.floor(t.HOLD_MS / t.DRIP_MS) : 0);

/** true iff every byte is an inert space */
export function inert(bytes) {
  if (!bytes || typeof bytes.length !== 'number') return false;
  for (let i = 0; i < bytes.length; i++) if (bytes[i] !== SPACE) return false;
  return true;
}

/** a held body: the spaces dripped, then the refusal exactly as it would have been sent */
export const heldBody = (dripped, refusalJson) => ' '.repeat(nat(dripped) ? dripped : 0) + String(refusalJson);
