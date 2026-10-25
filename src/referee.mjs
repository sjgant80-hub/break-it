// referee.mjs — decides whether the app was reached by anything it should not have been. The win condition.
//
// After every message the app acts on, the referee checks — with code written INDEPENDENTLY of the gate:
//   tripwire   — the message object is one the gate itself admitted (gate.isAdmitted); anything else reaching the
//                app bypassed the gate entirely
//   ledger     — the app's n-th action is exactly the n-th ledger entry, re-parsed here
//   grammar    — the packet passes a SECOND, independently written validator (a hex-string grammar, a different
//                technique from wire.mjs's byte loop). If the gate accepted bytes this rejects, the two disagree about
//                what a packet means — a schema escape — and that is a breach.
//   fold       — on demand, the app's whole state equals a fresh replay of the ledger
// A breach is recorded with the packet that caused it; the server turns that packet into an antigen at once.
import { isAdmitted } from './gate.mjs';
import { makeApp } from './app.mjs';
import { parse } from './wire.mjs';

const KEY = /^(?:6[1-9a-f]|7[0-9a])(?:6[1-9a-f]|7[0-9a]|3[0-9]|5f){0,31}$/;    // [a-z][a-z0-9_]{0,31}, as hex
const PRINTS = /^(?:2[0-9a-f]|[3-6][0-9a-f]|7[0-9a-e])*$/;                      // 0x20..0x7e, as hex
const FRAME = /^42524b3101[0-9a-f]{2}([0-9a-f]{16})([0-9a-f]{4})([0-9a-f]*)([0-9a-f]{128})$/;
const RECORD = /^05([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{8})$/;                    // op · account · period · amount, as hex
// bytes → lowercase hex, with NO Node Buffer — so this kernel runs unchanged in a browser (the live arena is the gated code)
const toHex = (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0'); return s; };

/**
 * The second validator, written independently of wire.mjs: the packet as a hex string, fields cut by their declared
 * lengths, each field checked by an anchored pattern. true only if every field and limit holds.
 */
export function grammarOk(bytes) {
  try {
    const m = FRAME.exec(toHex(bytes));
    if (!m) return false;
    const [, counter, nHex, body] = m;
    const n = parseInt(nHex, 16);
    if (/^0+$/.test(counter) || n < 3 || n > 256 || body.length !== n * 2) return false;
    const rec = RECORD.exec(body);
    if (rec) {
      const account = parseInt(rec[1], 16), period = parseInt(rec[2], 16), amount = parseInt(rec[3], 16);
      return account >= 1 && account <= 99999999 && period <= 1199 && amount <= 100000000;
    }
    const op = body.slice(0, 2), k = parseInt(body.slice(2, 4), 16), key = body.slice(4, 4 + 2 * k), rest = body.slice(4 + 2 * k);
    if (key.length !== 2 * k || !KEY.test(key)) return false;
    if (op === '01') { const v = parseInt(rest.slice(0, 2), 16); return rest.length >= 2 && v <= 200 && rest.length === 2 + 2 * v && PRINTS.test(rest.slice(2)); }
    if (op === '02') return rest.length === 0;
    if (op === '03') { if (rest.length !== 8) return false; const d = parseInt(rest, 16) | 0; return d >= -1000000 && d <= 1000000; }
    return false;
  } catch { return false; }
}

const same = (a, b) => a && b && a.sender === b.sender && a.counter === b.counter && a.op === b.op && a.key === b.key && a.value === b.value && a.delta === b.delta
  && a.account === b.account && a.period === b.period && a.amount === b.amount;

export function makeReferee() {
  const breaches = [];
  let checked = 0;
  return {
    /** Check the app's latest action against the latest ledger entry. → null or the breach. */
    after(msg, packet) {
      checked++;
      let why = null;
      if (!isAdmitted(msg)) why = 'the app was handed a message the gate never admitted';
      else if (!grammarOk(packet)) why = 'the gate admitted a packet the independent grammar rejects — a schema escape';
      else if (!same(parse(packet), msg)) why = 'the app acted on something other than the ledger entry';
      if (!why) return null;
      const b = { at: checked, why, packet: toHex(packet instanceof Uint8Array ? packet : new Uint8Array(0)) };
      breaches.push(b);
      return b;
    },
    /** Replay the whole ledger into a fresh app and compare with the live app. */
    fold(app, packets) {
      const fresh = makeApp();
      for (const p of packets) { const m = parse(p); if (m) fresh.apply(m); }
      const a = JSON.stringify(Object.entries(app.state()).sort()), b = JSON.stringify(Object.entries(fresh.state()).sort());
      if (a !== b) breaches.push({ at: checked, why: 'the app state is not the replay of the ledger', packet: '' });
      return a === b;
    },
    get breaches() { return [...breaches]; },
    get checked() { return checked; },
  };
}
