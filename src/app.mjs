// app.mjs — the app behind the gate. NAIVE ON PURPOSE: it trusts every message it is handed, does no checking of
// its own, and keeps its state in a plain object. It assumes the gate only ever lets verified input through.
// Reach it with anything malicious — a message the gate did not admit, a forged, replayed or out-of-grammar one —
// and you win (referee.mjs decides, and the server reports it at GET /referee).
// A REC record is posted as naively as anything else: the account's balance gains the amount, and the posting is kept
// under its account and period. Their keys begin with a capital (A…, P…), which no SET, DEL or ADD key can (a-z only),
// so the two stores never meet. A record posted twice is counted twice — the app checks nothing; that is the point.
import { OPS } from './wire.mjs';

export function makeApp() {
  const store = {};
  const log = [];
  return {
    apply(msg) {
      log.push(msg);
      if (msg.op === OPS.SET) store[msg.key] = msg.value;
      else if (msg.op === OPS.DEL) delete store[msg.key];
      else if (msg.op === OPS.ADD) store[msg.key] = (Number(store[msg.key]) || 0) + msg.delta;
      else if (msg.op === OPS.REC) { const a = 'A' + msg.account; store[a] = (Number(store[a]) || 0) + msg.amount; store['P' + msg.account + '.' + msg.period] = msg.amount; }
    },
    state: () => ({ ...store }),
    log,
  };
}
