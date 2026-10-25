// ════════════════════════════════════════════════════════════════
// feed.mjs — the partner feed: the UCI credit-default CSV (feeds/credit-default.csv) read as REC records, and the
// books it should produce. One kernel for the pilot's node run, its offline re-derivation, and the live page. Pure,
// total: a feed with one bad line is refused whole, with the line and the reason, never half-read and never a throw.
//
//   recordsFrom(text) → { ok, records: [{ account, period, amount }], accounts } | { ok:false, line, why }
//   books(records)    → { 'A<account>': balance, 'P<account>.<period>': amount }, the state the app must end with
//
// Each client row gives six records, one a month from April to September 2005 (PAY_AMT6 … PAY_AMT1, NT dollars), in
// that order: account = the row's ID, period = months since January 2000 (April 2005 = 63). No other column is read.
// ════════════════════════════════════════════════════════════════
import { MAX_ACCOUNT, MAX_AMOUNT } from './wire.mjs';

export const MONTHS = Object.freeze(['PAY_AMT6', 'PAY_AMT5', 'PAY_AMT4', 'PAY_AMT3', 'PAY_AMT2', 'PAY_AMT1']);
export const FIRST_PERIOD = 63;
const DIGITS = /^[0-9]{1,9}$/;

/** The feed's text → its records, in feed order. */
export function recordsFrom(text) {
  if (typeof text !== 'string') return { ok: false, line: 0, why: 'the feed is not text' };
  const lines = text.split('\n');
  const head = lines[0].replace(/\r$/, '').split(',');
  const id = head.indexOf('ID'), cols = MONTHS.map((m) => head.indexOf(m));
  if (id < 0 || cols.includes(-1)) return { ok: false, line: 1, why: 'the header lacks ID or a PAY_AMT column' };
  const records = [], seen = new Set();
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].replace(/\r$/, '');
    if (line === '') { if (i === lines.length - 1) break; return { ok: false, line: i + 1, why: 'an empty line inside the feed' }; }
    const f = line.split(',');
    if (f.length !== head.length) return { ok: false, line: i + 1, why: 'the line has ' + f.length + ' fields, the header ' + head.length };
    if (!DIGITS.test(f[id])) return { ok: false, line: i + 1, why: 'the ID is not a whole number' };
    const account = Number(f[id]);
    if (account < 1 || account > MAX_ACCOUNT) return { ok: false, line: i + 1, why: 'the ID is outside 1–' + MAX_ACCOUNT };
    if (seen.has(account)) return { ok: false, line: i + 1, why: 'the ID ' + account + ' is already in the feed' };
    seen.add(account);
    for (let m = 0; m < MONTHS.length; m++) {
      const v = f[cols[m]];
      if (!DIGITS.test(v) || Number(v) > MAX_AMOUNT) return { ok: false, line: i + 1, why: MONTHS[m] + ' is not a whole amount from 0 to ' + MAX_AMOUNT };
      records.push({ account, period: FIRST_PERIOD + m, amount: Number(v) });
    }
  }
  return { ok: true, records, accounts: seen.size };
}

/** The books a faithful ingest ends with: each account's balance, and each account-month's amount. */
export function books(records) {
  const out = {};
  if (!Array.isArray(records)) return out;
  for (const r of records) {
    if (!r || typeof r !== 'object') continue;
    out['A' + r.account] = (out['A' + r.account] || 0) + r.amount;
    out['P' + r.account + '.' + r.period] = r.amount;
  }
  return out;
}
