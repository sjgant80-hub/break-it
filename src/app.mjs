// app.mjs — the app behind the gate. NAIVE ON PURPOSE: it trusts every message it is handed, does no checking of
// its own, and keeps its state in a plain object. It assumes the gate only ever lets verified input through.
// Reach it with anything malicious — a message the gate did not admit, a forged, replayed or out-of-grammar one —
// and you win (referee.mjs decides, and the server reports it at GET /referee).
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
    },
    state: () => ({ ...store }),
    log,
  };
}
