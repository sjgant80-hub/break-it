// wallet.mjs — THE WALLET · the sovereign agent-wallet (the Seal's LINEAGE socket, §19 + §27).
//
// A Seal "IS an agent and IS a wallet" — it does not HAVE a budget, it CARRIES one, signed. This organ
// is that carry: an Ed25519 identity that is ALSO a capability (a typed set of actions it may perform)
// and a budget (a ceiling it cannot cross), forkable into a lineage tree where value flows upstream.
//
// It makes the estate's one real scar architecturally impossible: a Seal with budget=100k tokens CANNOT
// spend 2.2M — authorize() refuses at the ceiling, it is not a policy you can forget to apply.
//
// SPLIT (niceassos doctrine): the PURE, witnessable core is the capability/budget/lineage state machine
// (deterministic, no crypto — this is what the gate proves). Real Ed25519 is INJECTED as `crypto`; the
// platform (node:crypto / SubtleCrypto) owns the signing, we own the invariants.

export const KAPPA = (Math.sqrt(5) - 1) / 2;   // 0.618 — the lineage decay factor (kept off the public surface)

// ── canonical serialization: stable key order so a signature is over a fixed byte string ──
export function canonical(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonical).join(',') + ']';
  return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
}

// ══ PURE CORE — the invariants the gate proves (no crypto in here) ══

// may this wallet perform this action? (capability held AND budget not exceeded)
export function canDo(wallet, action) {
  const cost = Math.max(0, action.cost ?? 1);
  const held = wallet.caps.includes('*') || wallet.caps.includes(action.type);
  if (!held) return { ok: false, why: `capability not held: ${action.type}` };
  if (wallet.budget.spent + cost > wallet.budget.total) return { ok: false, why: `over budget: ${wallet.budget.spent}+${cost} > ${wallet.budget.total}` };
  return { ok: true, cost };
}

// spend it — returns a NEW wallet (immutable), never mutates. spent can never exceed total (canDo gates it).
export function applySpend(wallet, cost) {
  return { ...wallet, budget: { ...wallet.budget, spent: wallet.budget.spent + cost } };
}

// ATTENUATION (the capability-security law): you may only delegate a SUBSET of what you hold, and a budget
// no larger than what you have LEFT. A child can never out-reach its parent.
export function attenuates(parent, grant) {
  const capsOk = parent.caps.includes('*') || grant.caps.every(c => parent.caps.includes(c));
  const remaining = parent.budget.total - parent.budget.spent;
  const budgetOk = grant.budget <= remaining;
  if (!capsOk) return { ok: false, why: 'grant claims a capability the parent does not hold' };
  if (!budgetOk) return { ok: false, why: `grant budget ${grant.budget} exceeds parent's remaining ${remaining}` };
  return { ok: true };
}

// link a child into the lineage tree (§19: the fork IS the wallet · root preserved · depth grows)
export function linkChild(parent, childId) {
  return { parent: parent.id, root: parent.lineage.root, depth: parent.lineage.depth + 1, self: childId };
}

// lineage credit (§19 + §27 economics): a value V realized at a node — the earner keeps V (level 0) — mints
// UPSTREAM credit to each ancestor: V·κ^level for level 1..depth. Provenance appreciates as it is forked
// downstream, and the upstream payout is BOUNDED: Σ_{level≥1} V·κ^level ≤ V·κ/(1−κ) = V·φ (the §27 bound).
export function lineageSplit(depth, value, kappa = KAPPA) {
  const split = [];
  for (let level = 0; level <= depth; level++) split.push({ level, share: value * Math.pow(kappa, level) });
  const upstreamTotal = split.slice(1).reduce((s, x) => s + x.share, 0);
  const upstreamBound = value * kappa / (1 - kappa);   // = value·φ ≈ 1.618·value (convergent — never runs away)
  return { split, upstreamTotal, upstreamBound, self: value, withinBound: upstreamTotal <= upstreamBound + 1e-9 };
}

// ══ CRYPTO LAYER — real Ed25519 injected. `crypto` = { generate(), sign(msg,sk), verify(msg,sig,pk) } (async). ══

// INIT (§26 tetrahedron · birth): mint a wallet. id = the public key. The secret key is returned SEPARATELY
// and never lives in the wallet object.
export async function genesis(crypto, { caps = [], budget = Infinity } = {}) {
  const { pk, sk } = await crypto.generate();
  const wallet = { id: pk, pk, caps: [...caps], budget: { total: budget, spent: 0 }, lineage: { parent: null, root: pk, depth: 0, self: pk } };
  return { wallet, sk };
}

// AUTHORIZE: gate by canDo, then SIGN a token binding {id, action, cost, spentAfter, budget, nonce}. The
// signed token is the cross-trust boundary — a receiver verifies it without trusting the caller.
export async function authorize(crypto, wallet, sk, action, nonce = '') {
  const check = canDo(wallet, action);
  if (!check.ok) return { ok: false, why: check.why, wallet };
  const next = applySpend(wallet, check.cost);
  const body = { id: wallet.id, type: action.type, cost: check.cost, spentAfter: next.budget.spent, budgetTotal: wallet.budget.total, nonce };
  const sig = await crypto.sign(canonical(body), sk);
  return { ok: true, token: { ...body, sig }, wallet: next };
}

// VERIFY a token: real signature check + the wallet's own asserted budget invariant (spentAfter ≤ total).
export async function verifyToken(crypto, token) {
  if (!token || typeof token !== 'object' || !token.sig) return { ok: false, why: 'no token/sig' };
  const { sig, ...body } = token;
  const sigOk = await crypto.verify(canonical(body), sig, body.id);
  if (!sigOk) return { ok: false, why: 'bad signature (forged or tampered)' };
  if (body.spentAfter > body.budgetTotal) return { ok: false, why: 'token asserts an over-budget spend' };
  return { ok: true };
}

// DELEGATE (grant a child a capability certificate): attenuation-checked, parent-signed.
export async function delegate(crypto, parent, parentSk, childId, grant) {
  const att = attenuates(parent, grant);
  if (!att.ok) return { ok: false, why: att.why };
  const body = { kind: 'cap-cert', parent: parent.id, child: childId, caps: [...grant.caps].sort(), budget: grant.budget };
  const sig = await crypto.sign(canonical(body), parentSk);
  return { ok: true, cert: { ...body, sig } };
}
export async function verifyCert(crypto, cert) {
  if (!cert || cert.kind !== 'cap-cert' || !cert.sig) return { ok: false, why: 'not a cap-cert' };
  const { sig, ...body } = cert;
  const ok = await crypto.verify(canonical(body), sig, body.parent);
  return ok ? { ok: true } : { ok: false, why: 'cert signature invalid' };
}

// FORK (§19: fork = child = wallet = identity): mint a child, link its lineage to the parent, and hand it a
// parent-signed birth certificate so the lineage is verifiable, not merely asserted.
export async function fork(crypto, parent, parentSk, { caps = parent.caps, budget = 0 } = {}) {
  const { pk, sk } = await crypto.generate();
  const lineage = linkChild(parent, pk);
  const child = { id: pk, pk, caps: [...caps], budget: { total: budget, spent: 0 }, lineage };
  const birthBody = { kind: 'birth', parent: parent.id, child: pk, root: lineage.root, depth: lineage.depth };
  const birthSig = await crypto.sign(canonical(birthBody), parentSk);
  return { child, sk, birthCert: { ...birthBody, sig: birthSig } };
}
export async function verifyLineage(crypto, birthCert) {
  if (!birthCert || birthCert.kind !== 'birth' || !birthCert.sig) return { ok: false, why: 'not a birth cert' };
  const { sig, ...body } = birthCert;
  const ok = await crypto.verify(canonical(body), sig, body.parent);
  return ok ? { ok: true } : { ok: false, why: 'birth signature invalid' };
}

// ══ THE REFERENCE MONITOR — a capability sandbox for cooperative code (the-room seats, agent loops) ══
// fn runs ONLY inside an authorized budget. Over-budget or capability-not-held → fn NEVER runs. Honest
// limit: this guards code that goes THROUGH guard(); the SIGNED TOKEN is the boundary against untrusted code.
export async function guard(crypto, ctx, action, fn) {
  const res = await authorize(crypto, ctx.wallet, ctx.sk, action, String(ctx.nonce = (ctx.nonce || 0) + 1));
  if (!res.ok) return { ran: false, why: res.why };
  ctx.wallet = res.wallet;                    // commit the spend
  const out = await fn();
  return { ran: true, out, token: res.token, spent: ctx.wallet.budget.spent, total: ctx.wallet.budget.total };
}

export default { KAPPA, canonical, canDo, applySpend, attenuates, linkChild, lineageSplit, genesis, authorize, verifyToken, delegate, verifyCert, fork, verifyLineage, guard };
