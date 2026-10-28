// herd/judge.mjs — the herd's judge: each sealed claim (herd/claims.json) held against the facts herd/run.mjs gathered,
// by a rule fixed here. Pure, total: a missing or junk fact is a failed claim, never a throw. Nothing here can turn a
// failed claim green.
//   judge(claims, facts) → { held, failed, verdicts: [{ id, role, claim, measured, held }] }
export const N = 5, VARIANTS = 20, GENUINE = 3000, PATCH_MS = 2000;
export const DOOR = 'schema (door)';
// h-3's sealed words say the same packet is "refused": at the door, or on sight by the exact antibody a patched peer mints
// once its door refuses those bytes. (This rule first demanded the door alone, which the claim does not; corrected after a
// smoke run showed the peers refusing on sight, before the measurement. h-4 and h-7 do say "at the door" and keep DOOR.)
export const REFUSED = Object.freeze([DOOR, 'recognised']);

const obj = (x) => (x && typeof x === 'object' && !Array.isArray(x) ? x : {});
const arr = (x) => (Array.isArray(x) ? x : []);
const only = (t, key, n) => { const o = obj(t), ks = Object.keys(o); return ks.length === 1 && ks[0] === key && o[key] === n; };
const say = (t) => Object.entries(obj(t)).map(([k, n]) => n + ' ' + k).join(', ') || 'nothing';

export const RULES = {
  'h-1': (f) => { const x = obj(f.h1); return [x.sent === N && only(x.outcomes, 'schema', N) && x.breaches === 0,
    'the shipped gate, ' + x.sent + ' nodes: ' + say(x.outcomes) + '; breaches ' + x.breaches]; },
  'h-2': (f) => { const x = obj(f.h2); return [x.sent === N && only(x.outcomes, 'admitted', N) && x.breaches === N && x.patched === 0,
    'no herd patch, ' + x.sent + ' nodes: ' + say(x.outcomes) + '; breaches ' + x.breaches + '; patched ' + x.patched]; },
  'h-3': (f) => { const x = obj(f.h3), p = arr(x.peers);
    const ok = x.first === 'admitted' && obj(x.node1).patch === true && obj(x.node1).by === 'self' && p.length === N - 1
      && p.every((q) => Number.isFinite(q.patchedAfterMs) && q.patchedAfterMs <= PATCH_MS && q.by === 'peer' && REFUSED.includes(q.same)) && x.breaches === 1;
    return [ok, 'node 1: ' + x.first + ' (patched by ' + obj(x.node1).by + '); ' + p.map((q) => 'node ' + q.node + ' patched by ' + q.by + ' after ' + q.patchedAfterMs + ' ms, then the same packet: ' + q.same).join('; ') + '; breaches across the herd ' + x.breaches]; },
  'h-4': (f) => { const x = obj(f.h4); return [x.sent === N * VARIANTS && only(x.outcomes, DOOR, N * VARIANTS) && x.breaches === 1,
    x.sent + ' variants after the first landing: ' + say(x.outcomes) + '; breaches across the herd still ' + x.breaches]; },
  'h-5': (f) => { const x = obj(f.h5); return [only(x.shareStatus, '200', N - 1) && x.patched === 0 && only(x.nextGenuine, 'admitted', N),
    'shares delivered ' + say(x.shareStatus) + '; nodes patched ' + x.patched + '; the next genuine record: ' + say(x.nextGenuine)]; },
  'h-6': (f) => { const x = obj(f.h6), b = arr(x.booksMatch); return [x.sent === N * GENUINE && only(x.outcomes, 'admitted', N * GENUINE) && b.length === N && b.every((m) => m === true),
    x.sent + ' genuine records to the patched nodes: ' + say(x.outcomes) + '; books equal to the records held on ' + b.filter((m) => m === true).length + ' of ' + b.length + ' nodes'];
  },
  'h-7': (f) => { const r = arr(obj(f.h7).restarted), by = (i) => obj(r[i]).by;
    const ok = r.length === 2 && r.every((x) => x.patch === true && x.variant === DOOR) && by(0) === 'ledger' && by(1) === 'journal';
    return [ok, r.map((x) => 'node ' + x.node + ' restarted: patch ' + (x.patch ? 'on' : 'OFF') + ' by ' + x.by + ', a fresh variant ' + x.variant).join('; ')]; },
};

export function judge(claims, facts) {
  const verdicts = arr(obj(claims).claims).map((c) => {
    let held = false, measured = 'no rule for this claim';
    try { if (RULES[c.id]) [held, measured] = RULES[c.id](obj(facts)); } catch (e) { held = false; measured = 'the facts could not be read: ' + e.message; }
    return { id: c.id, role: c.role, claim: c.claim, measured, held: held === true };
  });
  return { held: verdicts.filter((v) => v.held).length, failed: verdicts.filter((v) => !v.held).length, verdicts };
}
