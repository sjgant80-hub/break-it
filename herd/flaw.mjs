// herd/flaw.mjs — the planted zero-day, for the herd measurement only (herd/claims.json). Loaded with --import before
// anything else, in the measuring process alone, it rewrites src/wire.mjs as Node loads it: the period bound, off by one,
// so the gate accepts period 1200 — a month past its limit. One expression, matched exactly once, or the process refuses
// to start. The shipped file on disk is never touched, and nothing outside this process is affected.
import { registerHooks } from 'node:module';

export const FROM = 'if (!(period <= MAX_PERIOD)) return';
export const TO = 'if (!(period <= MAX_PERIOD + 1)) return';

registerHooks({
  load(url, context, next) {
    const r = next(url, context);
    if (!url.endsWith('/src/wire.mjs')) return r;
    const src = typeof r.source === 'string' ? r.source : Buffer.from(r.source).toString('utf8');
    if (src.split(FROM).length !== 2) throw new Error('herd/flaw.mjs: the period bound was not found exactly once in src/wire.mjs — refusing to plant');
    return { ...r, source: src.replace(FROM, TO) };
  },
});
