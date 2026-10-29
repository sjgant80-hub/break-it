#!/usr/bin/env node
// witness-all.mjs — the re-runnable mutation gate over BREAK IT's decision kernels. Local and CI run the SAME
// thing: `node witness-all.mjs`. Exit 0 only if every gated kernel is clean (no unreviewed survivors).
//
// Gated here — the pure, total decision kernels, each the thing an attacker must beat:
//   wire      — the one exact layout + the raw check + the canonical parser (verify-before-parse starts here)
//   gate      — VERIFY BEFORE PARSE, in order, fail-closed (the only door to the app)
//   sentinel  — behaviour on verified traffic: drain / destruction / deviation, the GEP ladder
//   immune    — every refusal → family, fingerprint, novelty, the source's standing
//   antibody  — antigen → antibody; negative selection; exact-vs-shape; key-set binding
//   chain     — the append-only ledger's hash chain (tamper/reorder/delete all break it)
//   rebound   — the cost law: proof-of-work difficulty, the elastic release, the ratchet
//   referee   — the win oracle: the independent grammar + the tripwire + the fold
//   loot      — the signed Legendary rune's material (what the breach certificate commits to)
//   feed      — the partner feed read as records, and the books a faithful ingest must end with
//   judge     — the pilot's judge: each sealed claim held against what was measured (pilot/judge.mjs)
//   cost      — the CFO's case: the managed-cloud bill against the node's, from the buyer's figures and sourced prices
//
// NOT gated here, each with its reason:
//   · server.mjs, run.mjs — HTTP/orchestration and I/O (sockets, timers, process): no pure decision kernel. The
//     red-team battery (attack-kit/redteam.mjs --check) drives real nodes end to end and reproduces its receipt.
//   · ledger.mjs, journal.mjs — file I/O (fsync, locks, torn-tail trimming) over chain.mjs, which IS gated. Value-
//     tested by the battery (ledger tamper/delete/reorder/torn-tail/double-open all refuse; the journal is chained).
//   · app.mjs — the naive target on purpose; it does no checking, so there is nothing to mutate-test.
//   · keys.mjs, client.mjs — node:crypto glue and the legitimate sender; exercised by every test that signs.
//   · attack-kit/** — the attacker's tools; not trusted by the node, not part of the defence.
// Reviewed-equivalent survivors, if any, live in witness.baseline.json with an argued reason.
import { runMutations } from './.witness/witness.mjs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { writeFileSync } from 'node:fs';

const HERE = dirname(fileURLToPath(import.meta.url));
// each kernel's own unit test, plus the shared hostile-input battery (fuzz.test.mjs) — the latter kills the
// defensive type-guard mutants (x && typeof x === 'object' → ||) by proving the function stays total on junk.
export const PAIRS = [
  ['src/wire.mjs', ['test/wire.test.mjs', 'test/ingest.test.mjs', 'test/fuzz.test.mjs']],
  ['src/gate.mjs', ['test/gate.test.mjs', 'test/fuzz.test.mjs']],
  ['src/sentinel.mjs', ['test/sentinel.test.mjs', 'test/ingest.test.mjs', 'test/fuzz.test.mjs']],
  ['src/immune.mjs', ['test/immune.test.mjs', 'test/fuzz.test.mjs']],
  ['src/antibody.mjs', ['test/antibody.test.mjs', 'test/fuzz.test.mjs']],
  ['src/chain.mjs', ['test/chain.test.mjs', 'test/fuzz.test.mjs']],
  ['src/rebound.mjs', ['test/rebound.test.mjs', 'test/fuzz.test.mjs']],
  ['src/referee.mjs', ['test/referee.test.mjs', 'test/ingest.test.mjs', 'test/fuzz.test.mjs']],
  ['src/app.mjs', ['test/ingest.test.mjs', 'test/referee.test.mjs']],
  ['src/loot.mjs', ['test/loot.test.mjs', 'test/fuzz.test.mjs']],
  ['src/cost.mjs', ['test/cost.test.mjs']],
  ['src/feed.mjs', ['test/feed.test.mjs']],
  ['src/tarpit.mjs', ['test/tarpit.test.mjs']],
  ['src/patch.mjs', ['test/patch.test.mjs']],
  ['herd/judge.mjs', ['test/herd-judge.test.mjs']],
  ['pilot/judge.mjs', ['test/pilot.test.mjs']],
];

const RECEIPT = process.argv.includes('--receipt');                  // also write receipts/witness.json (the page reads it)
const only = process.argv.slice(2).filter((a) => a !== '--receipt');
let allClean = true;
const rows = [];
for (const [src, tests] of PAIRS) {
  if (only.length && !only.includes(src)) continue;
  const testFiles = Array.isArray(tests) ? tests : [tests];
  const t0 = Date.now();
  const r = runMutations(join(HERE, src), { cwd: HERE, cap: 5000, timeout: 60000, testCmd: ['node', '--test', ...testFiles] });
  const secs = ((Date.now() - t0) / 1000).toFixed(1);
  rows.push({ src, killed: r.killed, total: r.total, survived: r.survived.length, ignored: r.ignored.length, capped: r.capped, secs, clean: r.clean && !r.capped });
  console.log(`${r.clean && !r.capped ? '✓' : '✗'} ${src.padEnd(18)} ${String(r.killed).padStart(4)}/${String(r.total).padEnd(4)} killed` +
    `${r.ignored.length ? ` · ${r.ignored.length} reviewed-equivalent` : ''}${r.capped ? ` · CAPPED at ${r.capped}` : ''} · ${secs}s  (${testFiles.length} files)`);
  for (const s of r.survived) console.log(`    SURVIVED line ${s.line}: ${s.mutation} :: ${s.snippet}`);
  if (!r.clean || r.capped) allClean = false;
}
const k = rows.reduce((a, r) => a + r.killed, 0), n = rows.reduce((a, r) => a + r.total, 0);
console.log(`\n${allClean ? 'WITNESS CLEAN' : 'WITNESS NOT CLEAN'} — ${k}/${n} mutants killed across ${rows.length} kernel(s)`);
if (RECEIPT && !only.length) writeFileSync(join(HERE, 'receipts/witness.json'), JSON.stringify({ kind: 'break-it.witness', v: 1, clean: allClean, killed: k, total: n,
  kernels: rows.map(({ src, killed, total, ignored, survived, clean }) => ({ src, killed, total, ignored, survived, clean })) }, null, 1) + String.fromCharCode(10));
process.exit(allClean ? 0 : 1);
