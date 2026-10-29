// tarpit/judge.mjs — the tarpit's judge: each sealed claim (tarpit/claims.json) held against the facts tarpit/run.mjs
// gathered at the shipped settings. Pure and total: a fact that is missing or malformed fails its claim, never throws.
//   judge(claims, facts) → { held, failed, verdicts: [{ id, role, claim, measured, held }] }
const obj = (x) => (x && typeof x === 'object' && !Array.isArray(x) ? x : {});
const arr = (x) => (Array.isArray(x) ? x : []);
const num = (x) => (Number.isFinite(x) ? x : NaN);
/** the numbers the claims were sealed with */
export const SEALED = Object.freeze({ GENUINE: 3000, SHARED: 100, CONFIRM: 500, HELD: 3, TICKS: 20, FLOOD: 100, CAP: 64, LATENCY: 200, NEAR_MS: 10, WASTE: 10, GIVE_UP_SPACES: 5 });
const S = SEALED;

export const RULES = {
  'p-1': (f) => { const x = obj(f.p1), b = obj(f.books);
    return [x.sent === S.GENUINE && x.admitted === S.GENUINE && x.held === 0 && b.match === true && num(x.attackerHeldMeanwhile) >= 1,
      'admitted ' + x.admitted + ' of ' + x.sent + ', held ' + x.held + '; the attacker was held ' + x.attackerHeldMeanwhile + ' times meanwhile; the books equal the feed’s: ' + b.match + ' (' + b.records + ' records)']; },
  'p-2': (f) => { const x = obj(f.p2);
    return [x.sent === S.SHARED && x.admitted === S.SHARED && x.held === 0 && x.paidWork === S.SHARED,
      'from the attacker’s own address: admitted ' + x.admitted + ' of ' + x.sent + ', held ' + x.held + '; each paid the work asked of that address (' + x.paidWork + ' paid, at ' + arr(x.bits).join(', ') + ' bits)']; },
  'p-3': (f) => { const x = obj(f.p3), then = arr(x.thenHeld);
    return [x.first === S.CONFIRM && x.firstRefused === S.CONFIRM && x.firstAnsweredAtOnce === S.CONFIRM && then.length === S.HELD && then.every((h) => h.status === 403 && h.spaces === S.TICKS && h.spacesOnly === true),
      'the first ' + x.first + ' refusals: ' + x.firstAnsweredAtOnce + ' answered at once; the next ' + then.length + ': ' + then.map((h) => h.spaces + ' spaces' + (h.spacesOnly ? '' : ' (not only spaces)') + ', then ' + h.status).join('; ')]; },
  'p-4': (f) => { const x = obj(f.p4), on = obj(x.on), off = obj(x.off), ratio = num(off.answers) / num(on.answers);
    return [num(on.answers) >= 1 && num(off.answers) >= S.WASTE * num(on.answers),
      'answers in ' + off.seconds + ' s with the tarpit off: ' + off.answers + '; in ' + on.seconds + ' s with it on: ' + on.answers + ' (' + (Number.isFinite(ratio) ? Math.round(ratio * 10) / 10 : '—') + ' times fewer)']; },
  'p-5': (f) => { const x = obj(f.p5), g = obj(x.genuine), near = num(g.medianBusyMs) - num(g.medianBaseMs) <= S.NEAR_MS;
    return [x.sent === S.FLOOD && num(x.maxHolding) <= S.CAP && x.held <= S.CAP && x.quick === x.sent - x.held && x.heldWhenGenuineBegan === S.CAP && x.heldWhenGenuineEnded === S.CAP
      && g.sent === S.LATENCY && g.admittedBase === S.LATENCY && g.admittedBusy === S.LATENCY && g.heldBusy === 0 && near,
      x.sent + ' forgeries at once: at most ' + x.maxHolding + ' held at a time, ' + x.held + ' held, ' + x.quick + ' answered in under 5 s; ' + g.admittedBusy + ' of ' + g.sent + ' genuine admitted while '
      + x.heldWhenGenuineBegan + ' were held (median ' + g.medianBusyMs + ' ms, against ' + g.medianBaseMs + ' ms with nothing held)']; },
  'p-6': (f) => { const xs = arr(f.p6);
    return [xs.length === S.HELD && xs.every((x) => x.status === true && x.headers === true && x.lengthCountsSpaces === true && x.spacesOnly === true && x.spaces === S.TICKS && x.jsonEqual === true),
      xs.length + ' held answers against the tarpit-off twin: status equal ' + xs.filter((x) => x.status).length + ', headers equal ' + xs.filter((x) => x.headers).length + ', length counts the spaces ' + xs.filter((x) => x.lengthCountsSpaces).length
      + ', spaces only before the JSON ' + xs.filter((x) => x.spacesOnly).length + ', JSON byte for byte ' + xs.filter((x) => x.jsonEqual).length + (f.p6all === true ? '; and every answer of the sequence equal after its spaces' : '')]; },
  'p-7': (f) => { const x = obj(f.p7);
    return [x.libraryEqual === true && x.journalEqual === true,
      'antibody libraries equal: ' + x.libraryEqual + ' (' + x.exact + ' exact, ' + x.shapes + ' shapes); journals equal record for record, time aside: ' + x.journalEqual + ' (' + x.journalRecords + ' records)']; },
  'p-8': (f) => { const x = obj(f.p8);
    return [x.aborted === true && x.spacesOnly === true && num(x.bytes) <= S.GIVE_UP_SPACES && x.holdingAfter === 0 && x.abandonedRose === 1,
      'it gave up: ' + x.aborted + '; it received ' + x.bytes + ' bytes, spaces only: ' + x.spacesOnly + '; a second later the node held ' + x.holdingAfter + ', abandoned rose by ' + x.abandonedRose]; },
};

export function judge(claims, facts) {
  const verdicts = arr(obj(claims).claims).map((c) => {
    let held = false, measured = 'no rule for this claim';
    try { if (RULES[c.id]) [held, measured] = RULES[c.id](obj(facts)); } catch (e) { held = false; measured = 'the facts could not be read: ' + e.message; }
    return { id: c.id, role: c.role, claim: c.claim, measured, held: held === true };
  });
  return { held: verdicts.filter((v) => v.held).length, failed: verdicts.filter((v) => !v.held).length, verdicts };
}
