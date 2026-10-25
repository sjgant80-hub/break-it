// pilot/judge.mjs — the pilot's judge: each sealed claim (pilot/claims.json) held against the facts the measurement
// gathered, by a rule fixed here, in code that is gated like every other kernel. Pure, total: a missing or junk fact
// is a failed claim, never a throw. A failed claim is reported as failed; nothing here can turn it green.
//   judge(claims, facts) → { held, failed, verdicts: [{ id, role, claim, measured, held }] }
//   explained(answer)    → whether a refusal names its stage and gives a reason in words
export const REFUSAL_STAGES = Object.freeze(['size', 'magic', 'schema', 'sender', 'signature', 'counter', 'error', 'behavior', 'recognised', 'rebound', 'http', 'flood', 'breach']);
export const GATE_STAGES = Object.freeze(['size', 'magic', 'schema', 'sender', 'signature', 'counter']);
export const BIND_LOOKUP = 'dns lookup 127.0.0.1 (before listening)';           // Node's own listen() resolving the bind literal
export const RECORDS = 180000, ACCOUNTS = 30000, BOOK_KEYS = 210000, MIN_RATE = 100, INJECTIONS = 6, BATTERY = 79;

const obj = (x) => (x && typeof x === 'object' ? x : {});
const num = (x) => (Number.isFinite(x) ? x : NaN);

/** A refusal is explained when it names a stage from the list and gives a reason of at least two words. */
export const explained = (a) => {
  const x = obj(a);
  return typeof x.stage === 'string' && REFUSAL_STAGES.includes(x.stage) && typeof x.reason === 'string' && /\S\s+\S/.test(x.reason);
};

const RULES = {
  'coo-1': (f) => [f.admitted === RECORDS && f.ledgerEntries === RECORDS && f.genuineRefused === 0,
    f.admitted + ' admitted, ' + f.ledgerEntries + ' in the ledger, ' + f.genuineRefused + ' genuine refused (' + f.retries + ' rate-limit retries)'],
  'coo-2': (f) => { const b = obj(f.books); return [b.equal === true && b.keys === BOOK_KEYS && b.accounts === ACCOUNTS,
    (b.equal === true ? 'equal' : 'NOT equal (' + b.mismatches + ' keys differ)') + ' across ' + b.keys + ' keys, ' + b.accounts + ' accounts']; },
  'coo-3': (f) => [num(f.perSecond) >= MIN_RATE, num(f.perSecond) + ' records a second (' + f.seconds + ' s for ' + f.admitted + ')'],
  'ciso-1': (f) => { const e = obj(f.egress); return [f.canarySeen === true && e.outbound === 0,
    'outbound ' + e.outbound + ' (tcp ' + e.tcp + ', tls ' + e.tls + ', udp ' + e.udp + ', dns ' + e.dns + ', fetch ' + e.fetch + '); the canary was ' + (f.canarySeen === true ? 'seen' : 'NOT seen')]; },
  'ciso-3': (f) => { const e = obj(f.egress), seen = Array.isArray(e.seen) ? e.seen : []; return [f.canarySeen === true && e.afterListening === 0 && e.outbound === seen.length && seen.every((x) => x === BIND_LOOKUP),
    e.afterListening + ' attempts after listening; before: ' + (seen.length ? seen.join('; ') : 'none') + '; the canary was ' + (f.canarySeen === true ? 'seen' : 'NOT seen')]; },
  'ciso-2': (f) => { const l = Array.isArray(f.listening) ? f.listening : []; return [l.length > 0 && l.every((a) => typeof a === 'string' && a.startsWith('127.0.0.1:')),
    'listening on ' + (l.length ? l.join(', ') : 'nothing recorded')]; },
  'sec-1': (f) => { const inj = Array.isArray(f.injections) ? f.injections : []; return [inj.length === INJECTIONS && inj.every((i) => {
    const a = obj(obj(i).first), b = obj(obj(i).second);
    return a.status === 403 && GATE_STAGES.includes(a.stage) && b.status === 403 && b.stage === 'recognised';
  }), inj.map((i) => obj(i).kind + ': ' + obj(obj(i).first).stage + ' → ' + obj(obj(i).second).stage).join('; ') || 'no injections']; },
  'sec-2': (f) => { const r = obj(f.referee); return [r.breached === false && r.foldMatches === true,
    (r.breached === false ? '0 breaches' : 'BREACHED') + ', fold ' + (r.foldMatches === true ? 'matches' : 'does NOT match') + ', ' + r.checked + ' checked']; },
  'sec-3': (f) => { const t = obj(f.redteam); return [t.exit === 0 && t.cases === BATTERY && t.held === true,
    t.cases + ' cases, ' + (t.held === true ? 'all held' : 'NOT all held') + ', --check exit ' + t.exit]; },
  'reg-1': (f) => { const x = obj(f.explained), c = obj(f.chain); return [x.answers > 0 && x.unexplained === 0 && x.journal > 0 && x.journalUnexplained === 0 && c.ok === true && typeof c.head === 'string' && c.head === f.derivedHead,
    x.answers + ' refusal answers (' + x.unexplained + ' unexplained), ' + x.journal + ' journal records (' + x.journalUnexplained + ' unexplained); chain ' + (c.ok === true ? 'verifies' : 'BROKEN') + ', head ' + (c.head === f.derivedHead ? 'equals' : 'DIFFERS from') + ' the offline derivation']; },
};

export function judge(claims, facts) {
  const list = Array.isArray(obj(claims).claims) ? claims.claims : [];
  const f = obj(facts);
  const verdicts = list.map((c) => {
    const x = obj(c), rule = Object.prototype.hasOwnProperty.call(RULES, x.id) ? RULES[x.id] : null;
    const [held, measured] = rule ? rule(f) : [false, 'no rule for this claim'];
    return { id: x.id, role: x.role, claim: x.claim, measured, held: held === true };
  });
  const held = verdicts.filter((v) => v.held).length;
  return { held, failed: verdicts.length - held, verdicts };
}
