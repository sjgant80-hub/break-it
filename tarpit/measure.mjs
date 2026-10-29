#!/usr/bin/env node
// tarpit/measure.mjs — the tarpit measurement: the seal checked, the run made at the shipped settings, the facts judged
// against the sealed claims, the receipt written.
//   node tarpit/measure.mjs            → receipts/tarpit.json
//   node tarpit/measure.mjs --check    → re-run; refuse unless every verdict and every fact but the timings is the receipt's
//   TARPIT_SMOKE=1 node tarpit/measure.mjs → plumbing only, on small settings: prints the facts' shape, judges nothing
// It refuses to run if tarpit/claims.json differs from the commit that sealed it.
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { judge } from './judge.mjs';

const ROOT = new URL('../', import.meta.url);
const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
const sha = (s) => createHash('sha256').update(s).digest('hex');
const SMOKE = process.env.TARPIT_SMOKE === '1';

const path = 'tarpit/claims.json', text = readFileSync(new URL(path, ROOT), 'utf8');
const commit = git('log', '-1', '--format=%H', '--', path).trim();
if (!commit || git('show', commit + ':' + path) !== text) { console.log(path + ' differs from the commit that sealed it — refusing to measure'); process.exit(1); }
let codeAtSeal = true;
try { git('show', commit + ':tarpit/run.mjs'); } catch { codeAtSeal = false; }

const t0 = Date.now();
const out = execFileSync(process.execPath, ['tarpit/run.mjs'], { cwd: ROOT, encoding: 'utf8', env: { ...process.env }, maxBuffer: 1 << 24, timeout: 3600000 });
const facts = JSON.parse(out.trim().split('\n').pop());

if (SMOKE) {
  const keys = (o, d = 0) => (o && typeof o === 'object' && !Array.isArray(o) && d < 2 ? '{' + Object.keys(o).map((k) => k + keys(o[k], d + 1)).join(' ') + '}' : '');
  console.log('SMOKE RAN END TO END · ' + Math.round((Date.now() - t0) / 1000) + ' s · ' + keys(facts));
  process.exit(0);
}
const claims = JSON.parse(text), j = judge(claims, facts);
// what must reproduce: every fact but the timings — how many answers a window got, latencies, how often the attacker was
// held while genuine traffic ran, how many spaces a source that gave up caught, retries, and the running totals. Added
// after the first run (receipts/tarpit.json, said on the page): p-4 and p-5 turn on how fast the attacker's machine pays
// the rebound's work — the first run's attacker could keep only 21 forgeries held at once, so the cap of 64 was never
// reached — so a faster or slower machine may judge them differently. CI re-runs and prints them; it does not require them.
export const SPEED = ['p-4', 'p-5'];
const steadyOf = (f) => {
  const { p4, retried, final, ...rest } = f;
  const { attackerHeldMeanwhile, holdingAtTheEnd, nodeHeldBefore, ...p1 } = rest.p1 || {};
  const { genuine, sent } = rest.p5 || {}, { admittedBase, admittedBusy, heldBusy } = genuine || {};
  const { bytes, ...p8 } = rest.p8 || {};
  return { ...rest, p1, p5: { sent, genuine: { admittedBase, admittedBusy, heldBusy } }, p8 };
};
const steady = steadyOf(facts);
const receipt = { kind: 'break-it.tarpit.receipt', v: 1, speedClaims: SPEED, sealed: { path, commit, claimsSha256: sha(text), measuringCodeCommittedAtSeal: codeAtSeal }, facts, steadySha256: sha(JSON.stringify(steady)), held: j.held, failed: j.failed, verdicts: j.verdicts };

if (process.argv.includes('--check')) {
  const was = JSON.parse(readFileSync(new URL('receipts/tarpit.json', ROOT), 'utf8'));
  const outcomes = (vs) => JSON.stringify(vs.filter((v) => !SPEED.includes(v.id)).map((v) => [v.id, v.held]));
  for (const v of j.verdicts.filter((x) => SPEED.includes(x.id))) console.log('  ' + v.id + ' on this machine (not required to match): ' + (v.held ? 'held' : 'failed') + ' · ' + v.measured);
  const same = sha(JSON.stringify(steadyOf(was.facts))) === sha(JSON.stringify(steady)) && outcomes(was.verdicts) === outcomes(receipt.verdicts);
  if (!same) for (const k of Object.keys(steady)) if (JSON.stringify(steadyOf(was.facts)[k]) !== JSON.stringify(steady[k])) console.log('  differs: ' + k);
  console.log(same ? 'TARPIT REPRODUCED · ' + j.held + ' held, ' + j.failed + ' failed, as the receipt says (timings aside)' : 'TARPIT DRIFT · the re-run differs from the receipt');
  process.exit(same ? 0 : 1);
}
writeFileSync(new URL('receipts/tarpit.json', ROOT), JSON.stringify(receipt, null, 1) + '\n');
for (const v of j.verdicts) console.log((v.held ? 'HELD   ' : 'FAILED ') + v.id + ' · ' + v.measured);
console.log('wrote receipts/tarpit.json · ' + j.held + ' held, ' + j.failed + ' failed · ' + Math.round((Date.now() - t0) / 1000) + ' s');
