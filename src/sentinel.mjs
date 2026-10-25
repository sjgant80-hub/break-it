// ════════════════════════════════════════════════════════════════
// sentinel.mjs — the second shield: behaviour, on VERIFIED traffic, per sender. Pure, total, integer-only, gated.
//
// The gate proves a packet was signed by a pinned key, is fresh, and is well-formed. It cannot know whether the
// key is being ABUSED — stolen, scripted, turned against the store. SENTINEL watches each sender's admitted stream
// and limits the blast radius of a key in the wrong hands ("identity is insufficient; behaviour is authoritative"):
//
//   drain        — the cumulative |ADD delta| over the sender's last WINDOW packets stays under DRAIN_CAP
//                  (per-packet caps alone let twenty small drains add up — SENTINEL's flag 2, learned in v2)
//   inflation    — the cumulative REC amount over its last WINDOW packets stays under POST_CAP: an ingest feed's key in
//                  the wrong hands cannot post unbounded credit (the mirror of drain). The cap is the operator's: here
//                  set from the pilot feed's own history (about twice its largest 64-record window), and said so.
//   destruction  — at most DEL_CAP deletes in its last HALF packets
//   deviation    — once calibrated, the op mix of its last HALF packets is compared with its OWN baseline (one-class:
//                  it models the sender, not the attacker, so an attack it never saw still deviates). L1 distance in
//                  permille, integers only.
//
// The GEP ladder (Gary W. Floyd — Lumiea Systems Research Division, ThunderStruck Service LLC, "GEP-Based Security:
// Behavioral Entropy Signatures for Cybersecurity and DevOps", 2025): ALLOW · THROTTLE (admitted, flagged) ·
// STEP-UP (destructive ops refused) · BLOCK (everything refused until the operator resets the sender).
// It only ever refuses MORE than the gate: a packet it refuses is not written, not applied, and its counter is not
// spent. Only a verified packet can move a sender's state, so no one without the key can push a sender into BLOCK.
// ════════════════════════════════════════════════════════════════
import { OPS } from './wire.mjs';

export const WINDOW = 64, HALF = 32, CALIBRATE = 64;
export const DRAIN_CAP = 50000000, DEL_CAP = 16, POST_CAP = 10000000;
export const DEVIATION = Object.freeze({ THROTTLE: 400, STEP_UP: 600, BLOCK: 800 });

export const freshState = () => ({ total: 0, baseline: null, recent: [], blocked: false });

const opIndex = (op) => (op === OPS.SET ? 0 : op === OPS.DEL ? 1 : op === OPS.ADD ? 2 : op === OPS.REC ? 3 : -1);
function permille(ops) {
  const c = [0, 0, 0, 0];
  for (const o of ops) { const i = opIndex(o); if (i >= 0) c[i]++; }
  return ops.length ? c.map((x) => Math.floor((x * 1000) / ops.length)) : [0, 0, 0, 0];
}
// a baseline from before records existed has three parts: its missing fourth is no records at all
const l1 = (a, b) => [0, 1, 2, 3].reduce((t, i) => t + Math.abs((a[i] || 0) - (b[i] || 0)), 0);

/** The L1 distance (permille) between a sender's recent op mix and its baseline mix. */
export const deviation = (recentOps, baseline) => (Array.isArray(baseline) && Array.isArray(recentOps) && recentOps.length ? l1(permille(recentOps), baseline) : 0);

/**
 * Judge one VERIFIED message for its sender. state = the sender's state (freshState() before its first packet).
 * → { allow, level, reason, state }   — `state` is the next state; it includes the message only if allowed.
 */
export function judge(state, msg) {
  try {
    const s = state && typeof state === 'object' && Array.isArray(state.recent) ? state : freshState();
    const m = msg && typeof msg === 'object' ? msg : {};
    const op = m.op;
    if (opIndex(op) < 0) return { allow: false, level: 'BLOCK', reason: 'not an op this store knows', state: s };
    if (s.blocked === true) return { allow: false, level: 'BLOCK', reason: 'this sender is blocked until its operator resets it', state: s };
    const entry = { op, delta: op === OPS.ADD && Number.isInteger(m.delta) ? m.delta : 0, amount: op === OPS.REC && Number.isInteger(m.amount) ? m.amount : 0 };
    const after = [...s.recent, entry].slice(-WINDOW);
    const drained = after.reduce((t, e) => t + Math.abs(e.delta), 0);
    if (drained > DRAIN_CAP) {
      return { allow: false, level: 'BLOCK', reason: 'drain — ' + drained + ' moved in ' + after.length + ' packets is over ' + DRAIN_CAP, state: { ...s, blocked: true } };
    }
    const posted = after.reduce((t, e) => t + (e.amount || 0), 0);
    if (posted > POST_CAP) {
      return { allow: false, level: 'BLOCK', reason: 'inflation — ' + posted + ' posted in ' + after.length + ' packets is over ' + POST_CAP, state: { ...s, blocked: true } };
    }
    const half = after.slice(-HALF).map((e) => e.op);
    const dels = half.filter((o) => o === OPS.DEL).length;
    const dev = s.total >= CALIBRATE + HALF ? deviation(half, s.baseline) : 0;
    if (dev >= DEVIATION.BLOCK) return { allow: false, level: 'BLOCK', reason: 'deviation ' + dev + '‰ from this sender\'s own baseline', state: { ...s, blocked: true } };
    if (op === OPS.DEL && (dels > DEL_CAP || dev >= DEVIATION.STEP_UP)) {
      return { allow: false, level: 'STEP-UP', reason: dels > DEL_CAP ? 'too many deletes — ' + dels + ' in the last ' + half.length : 'deviation ' + dev + '‰ — destructive ops refused', state: s };
    }
    const total = s.total + 1;
    const baseline = s.baseline || (total === CALIBRATE ? permille(after.map((e) => e.op)) : null);
    const level = dev >= DEVIATION.THROTTLE ? 'THROTTLE' : 'ALLOW';
    return { allow: true, level, reason: level === 'ALLOW' ? 'within its own baseline' : 'admitted, flagged — deviation ' + dev + '‰', state: { total, baseline, recent: after, blocked: false } };
  } catch {
    return { allow: false, level: 'BLOCK', reason: 'sentinel failed closed', state: state };
  }
}
