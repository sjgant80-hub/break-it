// ════════════════════════════════════════════════════════════════
// rebound.mjs — the cost law. Pure, total, integer-only, gated. sha256 is injected (no I/O here).
//
// A valid packet from a well-behaved sender is free. A source that keeps getting REFUSED climbs a ladder, and past
// a threshold it must attach a PROOF-OF-WORK token before its signature is even checked:
//
//   challenge = REBOUND_DOMAIN | epoch | source | packetHash       (bound so a token can't be precomputed, reused
//   token     = a nonce with sha256(challenge | nonce) having        across sources/packets, or hoarded past an epoch)
//               ≥ `bits` leading zero bits
//
// THE REBOUND LAW — the gate is an elastic membrane. An attack STRETCHES it (each refusal is stored tension); past
// its elastic limit the membrane RELEASES that stored energy back onto the source, as the work the source must now
// spend to earn a look. The energy returned is the attacker's OWN, banked from its own attacks — the membrane
// spends none of its own and EMITS NOTHING onto the wire (releasing traffic at a source would be an attack, and
// energy the system does not have). Stated as conservation laws the battery measures:
//
//   1. NO AMPLIFICATION AT THE DEFENDER. The membrane's own cost to reject one packet is O(1): exactly one hash,
//      forever. It flexes; it does not burn energy to snap back.
//   2. CONSERVATION & DIRECTION. The work a distrusted source must spend to earn a look is ≥ the defender's, and
//      every bit of it is spent on the ATTACKER's own side. "Rebound" is that stored attack-energy returning to the
//      one who put it in — never traffic aimed at them.
//   3. THE ELASTIC RATCHET (no perpetual motion for the attacker). Below the elastic limit (BLOCK) the membrane
//      absorbs the stretch and snaps back free. Past it, the energy released back rises with the stretch and never
//      falls — `released()` is monotone in the refusal count — so a flood doesn't exhaust the defender; it only
//      winds the spring tighter against the source, and every attack arms its own repulsion.
//
// `obeys()` and `elasticHolds()` check the law; a test and the red-team battery measure it on real traffic. This is
// a cost gate only — it never decides admission (the gate does) and never turns a source away (a legitimate client
// on a shared address pays once and gets through; it sends few packets, so the price is trivial for it and crushing
// for a flooder).
// ════════════════════════════════════════════════════════════════

export const REBOUND_DOMAIN = 'BREAK-IT/rebound/v1|';
export const MAX_BITS = 24;                                        // a ceiling: a verifier never trusts a larger ask
export const REBOUND_LADDER = Object.freeze({ BLOCK: 100, ISOLATE: 500 });   // GATE-refusals from a source before work is owed
export const BITS = Object.freeze({ BLOCK: 12, ISOLATE: 18 });     // difficulty at each rung (≈ 4k and ≈ 262k hashes)
export const DEFENDER_COST = 1;                                    // the law's O(1): one hash to reject, always
const HEX64 = /^[0-9a-f]{64}$/;
const NONCE = /^[0-9a-f]{1,32}$/;

/** Leading zero BITS of a hex digest (not nibbles): '00f…' → 8, '08…' → 4. */
export function leadingZeroBits(hexDigest) {
  if (typeof hexDigest !== 'string') return 0;
  let bits = 0;
  for (let i = 0; i < hexDigest.length; i++) {
    const v = parseInt(hexDigest[i], 16);
    if (!Number.isInteger(v)) return bits;
    if (v === 0) { bits += 4; continue; }
    return bits + (Math.clz32(v) - 28);                            // v in 1..15 → 0..3 more leading zero bits
  }
  return bits;
}

/** The difficulty a source owes, from how many times the GATE has had to refuse it. 0 below BLOCK. Monotone. */
export function difficultyFor(refusals) {
  const n = Number.isInteger(refusals) ? refusals : 0;
  if (n >= REBOUND_LADDER.ISOLATE) return BITS.ISOLATE;
  if (n >= REBOUND_LADDER.BLOCK) return BITS.BLOCK;
  return 0;
}

/** The exact challenge string for (epoch, source, packetHash). Bound three ways so one token buys exactly one look. */
export function challenge(epoch, source, packetHash) {
  return REBOUND_DOMAIN + String(epoch >>> 0) + '|' + String(source).slice(0, 64) + '|' + (HEX64.test(String(packetHash)) ? packetHash : '');
}

/** Verify a work token: true if bits ≤ 0, else one hash. Never throws. */
export function verifyWork(challengeStr, nonce, bits, sha256hex) {
  try {
    const b = Math.min(Number.isInteger(bits) ? bits : 0, MAX_BITS);
    if (b <= 0) return true;
    if (typeof nonce !== 'string' || !NONCE.test(nonce) || typeof challengeStr !== 'string') return false;
    return leadingZeroBits(sha256hex(challengeStr + '|' + nonce)) >= b;
  } catch { return false; }
}

/** Pay the price: find a nonce (for the honest client and the attack kit). → nonce hex, or null if cap reached. */
export function solve(challengeStr, bits, sha256hex, cap = 1 << 26) {
  const b = Math.min(Number.isInteger(bits) ? bits : 0, MAX_BITS);
  if (b <= 0) return '0';
  for (let i = 0; i < cap; i++) {
    const nonce = i.toString(16);
    if (leadingZeroBits(sha256hex(challengeStr + '|' + nonce)) >= b) return nonce;
  }
  return null;
}

/**
 * Does one interaction obey the rebound law? step = { attackerWork, defenderWork, bitsBefore, bitsAfter }.
 * → { ok, broke: [reasons] }. Pure, total.
 */
export function obeys(step) {
  const s = step && typeof step === 'object' ? step : {};
  const aw = Number.isFinite(s.attackerWork) ? s.attackerWork : 0;
  const dw = Number.isFinite(s.defenderWork) ? s.defenderWork : Infinity;
  const broke = [];
  if (!(dw <= DEFENDER_COST)) broke.push('amplification: the defender did ' + dw + ' > ' + DEFENDER_COST + ' hash per rejection');
  if (!(aw >= dw)) broke.push('the attacker spent less than the defender (' + aw + ' < ' + dw + ')');
  if (Number.isInteger(s.bitsBefore) && Number.isInteger(s.bitsAfter) && s.bitsAfter < s.bitsBefore) broke.push('the ratchet slipped: ' + s.bitsBefore + ' → ' + s.bitsAfter + ' bits (attacking got cheaper)');
  return { ok: broke.length === 0, broke };
}

/** The ladder is monotone in refusals (the ratchet): more refusals never costs the attacker less. */
export function ratchetHolds(maxRefusals = REBOUND_LADDER.ISOLATE + 10) {
  let prev = 0;
  for (let n = 0; n <= maxRefusals; n++) { const d = difficultyFor(n); if (d < prev) return false; prev = d; }
  return true;
}

/**
 * The energy the membrane releases back onto a source at a given stretch: the expected number of hashes it must
 * spend per look. 1 (free) while unstretched, 2^bits past the elastic limit. The defender's own cost is always
 * DEFENDER_COST, so released/DEFENDER_COST is the amplification of the ATTACKER's own cost — their stored energy,
 * returned. Pure; integer; no I/O.
 */
export function released(refusals) {
  return Math.pow(2, difficultyFor(refusals));
}

/**
 * The elastic law over the whole stretch: the energy released back never falls as a source attacks more (monotone),
 * it is free below the elastic limit, and the defender's own cost stays O(1) throughout. → { ok, broke: [...] }.
 */
export function elasticHolds(maxRefusals = REBOUND_LADDER.ISOLATE + 10) {
  const broke = [];
  if (released(0) !== 1) broke.push('the membrane is not free when unstretched (released(0) = ' + released(0) + ')');
  let prev = 0;
  for (let n = 0; n <= maxRefusals; n++) {
    const e = released(n);
    if (e < prev) { broke.push('the spring unwound at ' + n + ' refusals: ' + prev + ' → ' + e); break; }
    prev = e;
  }
  if (released(REBOUND_LADDER.BLOCK) <= released(REBOUND_LADDER.BLOCK - 1)) broke.push('crossing the elastic limit released no extra energy');
  return { ok: broke.length === 0, broke };
}
