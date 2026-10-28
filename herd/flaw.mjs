// herd/flaw.mjs — the planted zero-day, for the herd measurement only (herd/claims.json). Loaded with --import before
// anything else, in the measuring process alone, it registers herd/flaw-hooks.mjs, which rewrites src/wire.mjs as Node
// loads it: the period bound, off by one, so the gate accepts period 1200 — a month past its limit. One expression,
// matched exactly once, or the load fails. The shipped file on disk is never touched, and nothing outside this process is
// affected. (module.register runs on Node 20.6 and later, which CI uses.)
import { register } from 'node:module';

register('./flaw-hooks.mjs', import.meta.url);
