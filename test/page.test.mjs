// the live page's gate: what a stranger opens must explain itself, wire every control, load only its own files,
// keep its FAQ and its schema word for word the same, and carry its credits. Read as text; no browser needed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const read = (p) => readFileSync(new URL('../' + p, import.meta.url), 'utf8');
const HTML = read('index.html'), APP = read('page/app.mjs'), CSS = read('page/style.css');
const text = (s) => s.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();

test('a self-only security policy, and nothing inline it would have to allow', () => {
  const csp = (HTML.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/) || [])[1];
  assert.ok(csp, 'a CSP meta');
  for (const d of ["default-src 'self'", "script-src 'self'", "style-src 'self'", "connect-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'none'"]) assert.ok(csp.includes(d), d);
  assert.ok(!/unsafe-(inline|eval)/.test(csp), 'no unsafe-inline or unsafe-eval');
  const scripts = [...HTML.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  for (const [, attrs, body] of scripts) {
    if (/type="application\/ld\+json"/.test(attrs)) continue;
    assert.match(attrs, /src="page\/app\.mjs"/, 'the only script is page/app.mjs');
    assert.equal(body.trim(), '');
  }
  assert.ok(!/\sstyle="/.test(HTML), 'no inline style attributes');
  assert.ok(!/\son[a-z]+="/i.test(HTML), 'no inline event handlers');
  assert.ok(!/=\s*"var\(/.test(HTML), 'no CSS variables in SVG presentation attributes');
  for (const [, tag] of HTML.matchAll(/<(?:script|link)\b([^>]*)>/g)) {
    const u = (tag.match(/\b(?:src|href)="([^"]+)"/) || [])[1];
    if (!u || /rel="canonical"/.test(tag)) continue;
    assert.ok(!/^[a-z]+:|^\/\//i.test(u), 'no third-party script or stylesheet: ' + u);
  }
  for (const [, u] of HTML.matchAll(/\s(?:src|href)="([^"#][^"]*)"/g)) {
    if (/^https:\/\//.test(u)) continue;
    assert.ok(existsSync(new URL('../' + u.split('?')[0], import.meta.url)), 'a local file the page links: ' + u);
  }
  for (const [, u] of APP.matchAll(/fetch\('([^']+)'\)/g)) assert.ok(existsSync(new URL('../' + u, import.meta.url)), 'a file the page fetches: ' + u);
  assert.ok(!/fetch\(\s*['"`]https?:/.test(APP), 'the page fetches nothing off its own origin');
});

test('the page explains itself: what, start here, live, pilot, cost, how, blueprint, red team, business, white paper, FAQ', () => {
  for (const id of ['what', 'start', 'live', 'pilot', 'cfo', 'how', 'blueprint', 'redteam', 'business', 'paper', 'faq']) assert.match(HTML, new RegExp('<section id="' + id + '"'), id);
  for (const role of ['CEO', 'CFO', 'COO', 'CTO and CISO', 'Engineering and data', 'Compliance and the DPO']) assert.ok(HTML.includes('<h4>' + role + '</h4>'), role);
  for (const h of ['Against what you pay for now', 'Security, data protection and audit', 'Roll-out', 'Ownership, support and exit', 'Risks, answered straight', 'The case for the board']) assert.ok(HTML.includes('<h3>' + h + '</h3>'), h);
  assert.ok(HTML.includes('<svg viewBox'), 'a diagram');
});

test('every id the script reaches for exists, and every control on the page is wired', () => {
  const ids = new Set([...HTML.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
  for (const [, id] of APP.matchAll(/\$\('([^']+)'\)/g)) assert.ok(ids.has(id), 'the script uses #' + id);
  for (const m of HTML.matchAll(/<button\b([^>]*)>/g)) {
    const tag = m[1];
    const id = (tag.match(/\bid="([^"]+)"/) || [])[1], data = (tag.match(/\bdata-(atk|speed|fill)="/) || [])[1];
    if (data) { assert.ok(APP.includes("'[data-" + data + "]'"), 'data-' + data + ' buttons are wired'); continue; }
    if (id) { assert.ok(new RegExp("\\$\\('" + id + "'\\)\\.addEventListener\\('click'").test(APP), '#' + id + ' has a click handler'); continue; }
    // a button with neither is a call to action inside a link to a section
    const before = HTML.slice(Math.max(0, m.index - 40), m.index);
    assert.match(before, /<a href="#[a-z]+">\s*$/, 'a call to action inside a link: ' + tag);
  }
  for (const [, id] of APP.matchAll(/\$\('(c-[a-z-]+)'\)\.value/g)) assert.ok(APP.includes("'" + id + "'") && ids.has(id), 'cost input #' + id);
  for (const [, a] of HTML.matchAll(/href="#([^"]+)"/g)) assert.ok(ids.has(a), 'anchor #' + a);
});

test('the visible FAQ and the FAQPage schema say exactly the same thing', () => {
  const ld = JSON.parse(HTML.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)[1]);
  const faq = ld['@graph'].find((g) => g['@type'] === 'FAQPage').mainEntity.map((q) => [q.name, q.acceptedAnswer.text]);
  const block = HTML.slice(HTML.indexOf('<section id="faq"'), HTML.indexOf('</section>', HTML.indexOf('<section id="faq"')));
  const shown = [...block.matchAll(/<dt>([\s\S]*?)<\/dt><dd>([\s\S]*?)<\/dd>/g)].map((m) => [text(m[1]), text(m[2])]);
  assert.equal(faq.length, 7);
  assert.deepEqual(shown, faq);
});

test('credits in full, and no price of our own anywhere', () => {
  assert.ok(/powered by the Konomi architecture, created by Thomas Frumkin/i.test(HTML), 'the Konomi credit');
  for (const s of ['Gary W. Floyd', 'Lumiea Systems Research Division', 'ThunderStruck Service, LLC', 'I.-C. Yeh and C.-H. Lien', 'DOI 10.24432/C55S3H', 'CC BY 4.0', 'AI Native Solutions']) assert.ok(HTML.includes(s), s);
  const page = HTML + APP;
  for (const re of [/priceCurrency/i, /"@type"\s*:\s*"Offer"/i, /\bper seat\b.*break-it/i, /\/mo\b/i, /\bpricing\b/i, /break-it (?:costs|is priced)/i]) assert.ok(!re.test(page), String(re));
  assert.ok(HTML.includes('no licence fee'), 'the licence fact');
});

test('both themes define every colour the page uses', () => {
  const used = new Set([...CSS.matchAll(/var\((--[a-z0-9-]+)\)/g), ...APP.matchAll(/'(--[a-z0-9]+)'/g)].map((m) => m[1]));
  const blocks = [CSS.match(/:root\{([\s\S]*?)\}/)[1], CSS.match(/:root\[data-theme="light"\]\{([\s\S]*?)\}/)[1]];
  for (const name of used) {
    if (['--mono', '--sans', '--serif'].includes(name)) { assert.ok(blocks[0].includes(name + ':'), name); continue; }
    for (const b of blocks) assert.ok(b.includes(name + ':'), name + ' in both themes');
  }
  assert.ok(CSS.includes('@media (prefers-color-scheme: light)'), 'follows the system');
});
