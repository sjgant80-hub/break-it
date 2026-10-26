// ════════════════════════════════════════════════════════════════
// subscribe.mjs — NEGATIVE SELECTION: the one rule that makes the exchange safe. Pure, total, gated.
//
// A verified bundle (exchange.verifyBundle) is still only a CLAIM. Before this node trusts one byte of it, it
// RE-RUNS every antigen through its OWN gate, and adopts an antibody ONLY when its own gate refuses the bytes at
// a PERMANENT stage — bytes that can never become valid (bad size/magic/schema, an unknown sender, a forged
// signature, a replay). An antigen that this node's gate would ADMIT is never adopted (adopting it would be
// autoimmunity — the body turning on itself). An antigen refused at a stage that could later become valid
// (out-of-order) earns recognition, not a permanent antibody. So no peer, and no relay, can ever make this gate
// refuse a packet it would admit: the gate stays the sole authority; the exchange only ever makes it wiser.
//
// gate-agnostic: the gate's decide, its stage map and its antibody mint/adopt are all injected, so any gate can
// subscribe. The demo wires the break-it gate (vendored src/).
// ════════════════════════════════════════════════════════════════
import { fromHex } from './exchange.mjs';

/**
 * Adopt the antigens of an already-VERIFIED bundle into this node's antibody library, by re-running each on this
 * node's own gate. deps:
 *   ctx           — this node's gate context { keyFor, verify, lastCounter }
 *   decide        — the gate (bytes, ctx) → { admit, stage, ... }
 *   immuneStage   — refusal → the immune stage (counter splits into replay | out-of-order)
 *   classify      — refusal → attack family
 *   mint, adopt   — antibody minting/adoption (break-it antibody.mjs)
 *   PERMANENT     — the set of stages that can never become valid
 *   keyset, hash  — this node's pinned key-set hash, and sha256hex(bytes)
 *   library       — this node's current antibody library
 * → { library, adopted, autoimmuneBlocked, recognitionOnly, minted[] }. Pure except via the injected gate.
 */
export function adoptAntigens(antigens, deps) {
  const d = deps && typeof deps === 'object' ? deps : {};
  let library = d.library;
  let adopted = 0, autoimmuneBlocked = 0, recognitionOnly = 0;
  const minted = [];
  const list = Array.isArray(antigens) ? antigens : [];
  for (const hex of list) {
    if (typeof hex !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(hex)) continue;   // only bounded hex (verifyBundle already enforces this)
    let bytes;
    try { bytes = fromHex(hex); } catch { continue; }
    const v = d.decide(bytes, d.ctx);
    if (v.admit) { autoimmuneBlocked++; continue; }             // VALID on our gate → refuse to adopt (no false immunity)
    const stage = d.immuneStage(v);
    if (!d.PERMANENT.includes(stage)) { recognitionOnly++; continue; }
    const hashHex = d.hash(bytes);
    const ab = d.mint(bytes, { hash: hashHex, stage, keyset: d.keyset, family: d.classify(v, { bytes }) });
    const r = d.adopt(library, [ab.exact, ab.shape].filter(Boolean));
    library = r.library;
    if (r.added > 0) { adopted++; minted.push(hashHex); }
  }
  return { library, adopted, autoimmuneBlocked, recognitionOnly, minted };
}
