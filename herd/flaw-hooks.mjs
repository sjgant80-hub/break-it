// herd/flaw-hooks.mjs — the module hook herd/flaw.mjs registers: src/wire.mjs, with its period bound off by one.
export const FROM = 'if (!(period <= MAX_PERIOD)) return';
export const TO = 'if (!(period <= MAX_PERIOD + 1)) return';

export async function load(url, context, next) {
  const r = await next(url, context);
  if (!url.endsWith('/src/wire.mjs')) return r;
  const src = typeof r.source === 'string' ? r.source : Buffer.from(r.source).toString('utf8');
  if (src.split(FROM).length !== 2) throw new Error('herd/flaw-hooks.mjs: the period bound was not found exactly once in src/wire.mjs — refusing to plant');
  return { ...r, source: src.replace(FROM, TO) };
}
