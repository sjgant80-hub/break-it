// ════════════════════════════════════════════════════════════════
// patch.mjs — the herd patches itself from one landing. Pure, total, gated.
//
// The gate is the authority on what is admitted, and an antibody may never refuse what this node's own gate admits (no
// false immunity, antibody.mjs). So a zero-day — bytes the gate admits that it should not — cannot become an antibody:
// every node running the same gate code would admit it again, once each. What a node can share instead is EVIDENCE that
// proves itself: the packet itself, which its own gate admits and the referee's independent validator (referee.mjs
// grammarOk, written apart from wire.mjs) rejects. Any node can re-check that pair on its own, taking nobody's word for
// it; a node that does switches the validator on as a stage of its door. The hole then closes before the attack reaches
// that node, and every variant the validator rejects is refused at the door, not only the bytes that were seen.
//
//   evidence(admits, grammar)    → true only when this node's gate ADMITS the bytes and the independent validator
//                                  REJECTS them: a zero-day, proven here. Anything else proves nothing.
//   door(on, grammar)            → null (the gate's verdict stands) | the refusal, at stage 'schema' (permanent: the
//                                  bytes alone decide it)
//
// Legitimate traffic passes both validators by construction, so the patch costs it nothing (measured on the pilot feed).
// ════════════════════════════════════════════════════════════════

export const REASON = 'refused by the referee’s independent grammar, a door stage switched on by a proven zero-day';

export const evidence = (admits, grammar) => admits === true && grammar === false;

export const door = (on, grammar) => (on === true && grammar === false ? { stage: 'schema', reason: REASON } : null);
