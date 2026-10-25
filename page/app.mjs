// page/app.mjs — the live page's engine. Every decision on this page is made by the repository's own gated kernels
// (src/): the same files the unit tests, the mutation gate, the red-team battery and the pilot run. The gate, the
// sentinel, the immune system, the naive app, the referee, the rebound, the feed reader and the cost case all run
// here unchanged. The browser adds only Ed25519 (WebCrypto, with a key this tab makes for itself, so no secret is
// shipped) and a synchronous SHA-256. Nothing here sends anything anywhere: the only requests are for this site's
// own files (the feed, the receipts, the sources), and the page's security policy allows no other.
import { rawCheck, headerOf, signedBytes, encodeUnsigned, withSignature, MAGIC, VERSION, HEADER, SIG, OPS } from '../src/wire.mjs';
import { decide } from '../src/gate.mjs';
import { classify, fingerprint, learn, emptyMemory } from '../src/immune.mjs';
import { immuneStage, features, mint, adopt, recognise, emptyLibrary, PERMANENT } from '../src/antibody.mjs';
import { judge, freshState } from '../src/sentinel.mjs';
import { makeApp } from '../src/app.mjs';
import { makeReferee } from '../src/referee.mjs';
import { difficultyFor, released, REBOUND_LADDER, DEFENDER_COST } from '../src/rebound.mjs';
import { recordsFrom, books } from '../src/feed.mjs';
import { costCase, pricesFrom } from '../src/cost.mjs';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const n0 = (x) => Number(x).toLocaleString('en-GB');
const gbp = (pence) => (pence < 0 ? '−' : '') + '£' + (Math.abs(pence) / 100).toLocaleString('en-GB', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const usd = (cents) => '$' + (cents / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
const MONTH = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const monthOf = (period) => MONTH[period % 12] + ' ' + (2000 + Math.floor(period / 12));

// ── theme: dark, light, or the system's (a per-viewer convenience; works without storage) ─────────────────────────
const THEMES = ['system', 'dark', 'light'];
let theme = 'system';
try { theme = THEMES.includes(localStorage.getItem('break-it.theme')) ? localStorage.getItem('break-it.theme') : 'system'; } catch { /* no storage */ }
function applyTheme() {
  if (theme === 'system') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = theme;
  $('theme').textContent = 'theme: ' + theme;
}
$('theme').addEventListener('click', () => { theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length]; try { localStorage.setItem('break-it.theme', theme); } catch { /* fine */ } applyTheme(); });
applyTheme();

// ── a compact, synchronous SHA-256, so the immune and antibody kernels run inline ─────────────────────────────────
const sha256 = (() => {
  const K = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
    0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
    0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  return (bytes) => {
    const l = bytes.length, bl = ((l + 8 >> 6) + 1) << 6, buf = new Uint8Array(bl); buf.set(bytes); buf[l] = 0x80;
    const dv = new DataView(buf.buffer); dv.setUint32(bl - 4, l * 8);
    const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const w = new Uint32Array(64);
    for (let o = 0; o < bl; o += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
      for (let i = 16; i < 64; i++) { const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0; }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g), t1 = (h + S1 + ch + K[i] + w[i]) | 0,
          S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), mj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + mj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0; H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    let out = ''; for (let i = 0; i < 8; i++) out += H[i].toString(16).padStart(8, '0'); return out;
  };
})();
const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => { h = (h || '').replace(/[^0-9a-fA-F]/g, ''); const o = new Uint8Array(h.length >> 1); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; };

// ── Ed25519 in WebCrypto: the feed's key is made in this tab; forgeries use keys made the same way ────────────────
let feedKey, feedPub, keyset = '';
const importPub = (raw) => crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
async function verifyAsync(msg, sig, pubRaw) { try { return await crypto.subtle.verify('Ed25519', await importPub(pubRaw), sig, msg); } catch { return false; } }
const signAsync = async (msg, key) => new Uint8Array(await crypto.subtle.sign('Ed25519', key, msg));
async function signPacket(unsigned, key) {
  const n = (unsigned[14] << 8) | unsigned[15];
  return withSignature(unsigned, await signAsync(signedBytes(new Uint8Array([...unsigned, ...new Uint8Array(SIG)]), n), key));
}

// ── the node, in this tab: the same steps server.mjs takes, in the same order ────────────────────────────────────
const counters = new Map(), senders = new Map();
let memory = emptyMemory(), library = emptyLibrary(), app = makeApp(), referee = makeReferee();
let packets = [], admittedHashes = new Set(), yourRefusals = 0;
const S = { seen: 0, admitted: 0, gate: 0, recognised: 0, behavior: 0 };
const keyFor = (id) => (id === 1 ? feedPub : null);
const lastCounter = (id) => counters.get(id) || 0n;

async function runGate(bytes) {
  const raw = rawCheck(bytes); let sigOk = false;
  if (raw.ok) { const h = headerOf(bytes, raw.n), key = keyFor(h.sender); if (key) sigOk = await verifyAsync(signedBytes(bytes, raw.n), h.sig, key); }
  return decide(bytes, { keyFor, verify: () => sigOk, lastCounter });
}
function antigen(bytes, refusal, source) {
  const stage = immuneStage(refusal), hash = sha256(bytes);
  const decl = bytes.length >= 16 ? (bytes[14] << 8) | bytes[15] : null;
  const family = classify(refusal, { bytes, declaredLength: decl, exactReplay: refusal.stage === 'counter' && admittedHashes.has(hash) });
  const print = fingerprint(family, { bytes });
  const l = learn(memory, { family, print, source }); memory = l.memory;
  const near = recognise(library, null, features(bytes, stage), keyset).nearest;
  let exact = false;
  if (PERMANENT.includes(stage)) { const ab = mint(bytes, { hash, stage, keyset, family }); const r = adopt(library, [ab.exact, ab.shape].filter(Boolean)); library = r.library; exact = r.added > 0 && !!ab.exact; }
  else library = adopt(library, [mint(bytes, { stage, family }).shape]).library;
  return { family, print, novel: l.novel, recognisedAs: near ? near.family : null, antibody: exact };
}
/** One packet, start to finish → { stage, reason, admit?, breach?, family?, recognisedAs?, antibody? } */
async function sendPacket(bytes, source) {
  S.seen++;
  const hash = sha256(bytes), seen = recognise(library, hash, null, keyset);
  const v = await runGate(bytes);
  if (seen.drop && !v.admit) { S.recognised++; return { stage: 'recognised', reason: 'a known attack, dropped on sight by an exact antibody', family: seen.family, recognised: true }; }
  if (!v.admit) { S.gate++; if (source === 'you') yourRefusals++; return { stage: v.stage, reason: v.reason, ...antigen(bytes, v, source) }; }
  const prior = senders.get(v.msg.sender) || freshState(), s = judge(prior, v.msg);
  senders.set(v.msg.sender, s.state);
  if (!s.allow) { S.behavior++; if (source === 'you') yourRefusals++; return { stage: 'behavior', reason: s.level + ' — ' + s.reason, ...antigen(bytes, { stage: 'behavior', reason: s.reason, sender: v.msg.sender }, source) }; }
  counters.set(v.msg.sender, v.msg.counter); packets.push(bytes); admittedHashes.add(hash);
  app.apply(v.msg); S.admitted++;
  const breach = referee.after(v.msg, bytes);
  return { stage: 'admitted', admit: true, breach, msg: v.msg };
}

// ── the arena (the look of the live-defence sketch, driven by the real verdicts above) ────────────────────────────
const arena = $('arena'), logEl = $('log');
const GATE_X = 0.32, CORE_X = 0.86;
let flying = 0;
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
function fly(colour, stopAt, glow) {
  if (flying > 36 || document.hidden) return;
  flying++;
  const p = document.createElement('div'); p.className = 'pkt'; p.style.background = css(colour);
  p.style.top = (10 + Math.random() * (arena.clientHeight - 30)) + 'px';
  arena.appendChild(p);
  const start = performance.now(), dur = 650, W = arena.clientWidth;
  const step = (now) => {
    const t = Math.min((now - start) / dur, 1);
    p.style.left = (4 + (stopAt * W - 4) * t) + 'px';
    if (t < 1) return requestAnimationFrame(step);
    p.style.boxShadow = '0 0 10px ' + css(glow);
    setTimeout(() => { p.style.transition = 'opacity .4s'; p.style.opacity = '0'; setTimeout(() => { p.remove(); flying--; }, 400); }, 150);
  };
  requestAnimationFrame(step);
}
function log(text, cls) {
  const d = document.createElement('div'); d.className = 'le ' + cls; d.textContent = text;
  logEl.insertBefore(d, logEl.firstChild);
  while (logEl.children.length > 80) logEl.removeChild(logEl.lastChild);
}
const VECTORS = [
  ['replay', 'a replayed record'], ['flip', 'one byte flipped'], ['unpinned', 'a key that is not pinned'],
  ['nodomain', 'signed without the domain'], ['truncated', 'a truncated record'], ['out-of-range', 'an out-of-range record'],
];
const vecState = Object.fromEntries(VECTORS.map(([k]) => [k, '']));
function renderVectors() {
  $('vectors').innerHTML = VECTORS.map(([k, what]) => {
    const st = vecState[k];
    return '<span class="vec ' + st + '" title="' + esc(what) + '">' + esc(k) + (st === 'immune' ? ' ✓✓' : st === 'learned' ? ' ✓' : '') + '</span>';
  }).join('') + (vecState.yours ? '<span class="vec ' + vecState.yours + '">your own ✓</span>' : '');
}

// ── the feed: the real UCI records, signed in this tab, sent through the gate one by one ──────────────────────────
let records = null, fed = 0, cc = 1n, lastGenuine = null, booksBad = 0, speed = 'live', running = false, feedErr = '';
async function loadFeed() {
  try {
    const r = recordsFrom(await (await fetch('feeds/credit-default.csv')).text());
    if (!r.ok) { feedErr = 'the feed was refused at line ' + r.line + ': ' + r.why; return false; }
    records = r.records; return true;
  } catch { feedErr = 'the feed did not load'; return false; }
}
function checkBooks() {
  // the books the feed alone says the app must hold for every record so far, against what the app holds
  const want = books(records.slice(0, fed)), got = app.state();
  booksBad = 0;
  for (const k of Object.keys(want)) if (got[k] !== want[k]) booksBad++;
  for (const k of Object.keys(got)) if (!(k in want)) booksBad++;
}
async function feedOne(animate) {
  if (!records || fed >= records.length) { running = false; return false; }
  const rec = records[fed];
  const pkt = await signPacket(encodeUnsigned({ sender: 1, counter: cc, op: OPS.REC, account: rec.account, period: rec.period, amount: rec.amount }), feedKey);
  const r = await sendPacket(pkt, 'feed');
  if (r.admit) {
    cc += 1n; fed++; lastGenuine = pkt;
    if (r.breach) breachShown(r, pkt);
    if (animate) { fly('--blue', CORE_X, '--grn'); log('[feed] record ' + n0(fed) + ' · account ' + rec.account + ' · ' + monthOf(rec.period) + ' · ' + n0(rec.amount) + ' NT$ → admitted, ledger ' + n0(packets.length), 'feed'); }
  } else {
    log('[feed] record ' + n0(fed + 1) + ' REFUSED at ' + r.stage + ': ' + r.reason, 'breach');
    running = false;
  }
  return true;
}
const PACE = { live: [1, 160], fast: [10, 40], full: [200, 0] };
async function loop() {
  while (running) {
    const [batch, wait] = PACE[speed];
    for (let i = 0; i < batch && running; i++) await feedOne(i === 0);
    if (fed % 1000 < batch) checkBooks();
    render();
    await new Promise((s) => setTimeout(s, wait));
  }
  checkBooks(); render();
}
function setRunning(on) {
  if (on && (!records || fed >= records.length)) return;
  running = on; $('play').textContent = running ? '❚❚ pause the feed' : '▶ play the feed';
  if (running) loop();
}

// ── the six known shapes (the pilot's injections), each built from the latest genuine record ──────────────────────
const be = (v, n) => Array.from({ length: n }, (_, i) => (v >>> (8 * (n - 1 - i))) & 0xff);
async function build(kind) {
  const last = lastGenuine, next = lastCounter(1) + 1n;
  const u = () => encodeUnsigned({ sender: 1, counter: next, op: OPS.REC, account: 1, period: 63, amount: 1 });
  if (kind === 'replay') return last && last.slice();
  if (kind === 'flip') { if (!last) return null; const b = last.slice(); b[HEADER + 10] ^= 1; return b; }
  if (kind === 'unpinned') { const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']); return signPacket(u(), kp.privateKey); }
  if (kind === 'nodomain') { const x = u(); return new Uint8Array([...x, ...(await signAsync(x, feedKey))]); }
  if (kind === 'truncated') return last && last.slice(0, last.length - 10);
  if (kind === 'out-of-range') {
    const body = [OPS.REC, ...be(1, 4), ...be(1200, 2), ...be(1, 4)], x = new Uint8Array(HEADER + body.length);
    x.set(MAGIC, 0); x[4] = VERSION; x[5] = 1; new DataView(x.buffer).setBigUint64(6, next); x[14] = 0; x[15] = body.length; x.set(body, HEADER);
    // signed raw, as the attack kit's signRaw does: withSignature() refuses to wrap bytes the grammar forbids
    const sig = await signAsync(signedBytes(new Uint8Array([...x, ...new Uint8Array(SIG)]), body.length), feedKey);
    return new Uint8Array([...x, ...sig]);
  }
  return null;
}
const lastBuilt = {};
async function attack(kind, { again = false } = {}) {
  const bytes = again && lastBuilt[kind] ? lastBuilt[kind] : await build(kind);
  if (!bytes) { log('[' + kind + '] needs one genuine record first: play the feed for a moment', 'info'); return null; }
  lastBuilt[kind] = bytes;
  const r = await sendPacket(bytes, 'you');
  showAttack(kind, r);
  return r;
}
function showAttack(kind, r) {
  if (r.admit) {
    if (r.breach) { fly('--red', CORE_X, '--red'); log('[' + kind + '] ★ REACHED THE CORE: the referee calls a breach: ' + r.breach.why, 'breach'); }
    else { fly('--gold', CORE_X, '--gold'); log('[' + kind + '] admitted: a valid packet (that is how genuine records pass, not a break)', 'info'); }
  } else if (r.stage === 'recognised') {
    fly('--purp', GATE_X, '--grn'); log('[' + kind + '] dropped on sight by an exact antibody (' + r.family + ') before any work', 'drop');
    if (vecState[kind] !== undefined) vecState[kind] = 'immune'; else vecState.yours = 'immune';
  } else {
    fly('--pink', GATE_X, '--grn');
    log('[' + kind + '] REFUSED at ' + r.stage + ': ' + r.reason + (r.recognisedAs ? ' · its shape is the ' + r.recognisedAs + ' family already learned' : ''), 'drop');
    log('   └ learned: family ' + r.family + (r.antibody ? ' · exact antibody minted' : ' · shape antibody') + (r.novel ? ' · a new fingerprint' : ''), 'learn');
    if (vecState[kind] !== undefined) { if (vecState[kind] !== 'immune') vecState[kind] = 'learned'; } else if (!vecState.yours) vecState.yours = 'learned';
  }
  render();
}
async function pilotSix() {
  for (const [k] of VECTORS) { await attack(k); await new Promise((s) => setTimeout(s, 220)); await attack(k, { again: true }); await new Promise((s) => setTimeout(s, 220)); }
}

// ── render ──────────────────────────────────────────────────────────────────────────────────────────────────────
function render() {
  $('s-seen').textContent = n0(S.seen); $('s-admit').textContent = n0(S.admitted); $('s-gate').textContent = n0(S.gate);
  $('s-recog').textContent = n0(S.recognised); $('s-behav').textContent = n0(S.behavior);
  $('s-ab').textContent = n0(Object.keys(library.exact).length) + ' exact · ' + n0(library.shapes.length) + ' shape';
  const br = referee.breaches.length;
  $('s-breach').textContent = n0(br); $('s-breach').className = br ? 'red' : '';
  const known = VECTORS.filter(([k]) => vecState[k] === 'immune').length;
  $('s-imm').textContent = known + ' of ' + VECTORS.length + ' shapes dropped on sight';
  $('imm-bar').style.width = Math.round((known / VECTORS.length) * 100) + '%';
  $('s-books').textContent = !records ? (feedErr || 'loading the feed…') : booksBad ? booksBad + ' keys differ' : 'equal · ' + n0(fed) + ' records';
  $('s-books').className = booksBad ? 'red' : '';
  $('s-fed').textContent = records ? n0(fed) + ' / ' + n0(records.length) : '—';
  const owe = difficultyFor(yourRefusals);
  $('s-you').textContent = n0(yourRefusals) + ' refused';
  $('s-owe').textContent = owe ? n0(released(yourRefusals)) + ' hashes a look (' + owe + ' bits)' : 'nothing yet (free under ' + REBOUND_LADDER.BLOCK + ')';
  $('s-def').textContent = DEFENDER_COST + ' hash to check a token';
  const v = $('verdict');
  if (br) { v.className = 'breached'; v.textContent = '★ ' + br + ' BREACH' + (br > 1 ? 'ES' : '') + ': the referee saw the app act on something it should not have'; }
  else { v.className = ''; v.textContent = '◊ THE GATE HOLDS · 0 breaches · the referee has checked ' + n0(referee.checked); }
  renderVectors();
  $('captured').value = lastGenuine ? toHex(lastGenuine) : '';
}
function renderRebound() {
  $('rebound').innerHTML = [0, REBOUND_LADDER.BLOCK - 1, REBOUND_LADDER.BLOCK, REBOUND_LADDER.ISOLATE].map((r) =>
    '<tr><td>' + n0(r) + '</td><td class="mono">' + n0(released(r)) + '</td><td class="mono">' + DEFENDER_COST + '</td></tr>').join('');
}

// ── the console: any bytes you like, through the same node ─────────────────────────────────────────────────────
const LADDER = ['size', 'magic', 'schema', 'sender', 'signature', 'counter', 'admitted'];
function showConsole(r) {
  const lad = $('ladder'); lad.innerHTML = '';
  const hit = LADDER.indexOf(r.stage);
  for (const [i, s] of LADDER.entries()) {
    const el = document.createElement('span');
    el.className = 'stage' + (r.admit && s === 'admitted' ? ' admit' : i === hit ? ' hit' : (hit > i || r.admit || r.stage === 'behavior') ? ' pass' : '');
    el.textContent = s; lad.appendChild(el);
  }
  if (r.stage === 'recognised' || r.stage === 'behavior') { const el = document.createElement('span'); el.className = 'stage hit'; el.textContent = r.stage; lad.appendChild(el); }
  const a = $('answer');
  if (r.breach) { a.className = 'answer breach'; a.textContent = '★ REFEREE BREACH: you reached the app. ' + r.breach.why; breachShown(r); }
  else if (r.admit) { a.className = 'answer admitted'; a.textContent = 'ADMITTED: a valid packet. That is how genuine records pass; it is not a break.'; }
  else { a.className = 'answer'; a.textContent = 'REFUSED at ' + r.stage + ': ' + r.reason; }
}
function breachShown() { $('rune').className = 'rune show'; $('rune').textContent = '⟐ THE BREAKER’S RUNE ⟐ the referee saw the app act on bytes it should not have. Write it up in FINDINGS.md (repository) with the bytes from the console, and the node will mint the signed rune when you reproduce it against node run.mjs.'; }

// ── the pilot's receipt, by role ───────────────────────────────────────────────────────────────────────────────
let receipt = null;
const ROLES = [['COO', 'COO: does the work'], ['CISO', 'CISO: nothing leaves'], ['Security', 'Security: it holds'], ['Regulator', 'Regulator: every decision explained']];
async function loadReceipt() {
  try { receipt = await (await fetch('receipts/pilot.json')).json(); } catch { receipt = null; }
  if (!receipt || !Array.isArray(receipt.verdicts)) { $('roles').textContent = 'The pilot’s receipt (receipts/pilot.json) did not load.'; return; }
  const f = receipt.facts;
  $('p-sum').textContent = receipt.held + ' of ' + receipt.verdicts.length + ' sealed claims held' + (receipt.failed ? ', ' + receipt.failed + ' failed (kept, explained below)' : '');
  $('roles').innerHTML = ROLES.map(([role, title]) => '<div class="role"><h4>' + esc(title) + '</h4>' + receipt.verdicts.filter((v) => v.role === role).map((v) =>
    '<div class="claim"><span class="tagx ' + (v.held ? 'held">HELD' : 'failed">FAILED') + '</span><b>' + esc(v.id) + '</b> ' + esc(v.claim) + '<div class="measured">measured: ' + esc(v.measured) + '</div></div>').join('') + '</div>').join('');
  const facts = [
    ['records ingested', n0(f.admitted) + ' of ' + n0(receipt.feed.records)], ['records a second', n0(f.perSecond) + ' (' + n0(f.seconds) + ' s)'],
    ['rate-limit retries', n0(f.retries)], ['outbound once listening', n0(f.egress.afterListening)],
    ['attacks injected · refused · dropped on sight', f.injections.length + ' · ' + f.injections.filter((i) => i.first.status === 403).length + ' · ' + f.injections.filter((i) => i.second.stage === 'recognised').length],
    ['referee breaches', f.referee.breached ? 'BREACHED' : '0'], ['red-team battery', f.redteam.cases + ' cases, ' + (f.redteam.held ? 'all held' : 'NOT all held')],
    ['ledger head (node = offline)', receipt.deterministic.ledgerHead.slice(0, 16) + '… ' + (receipt.deterministic.ledgerHead === receipt.deterministic.derivedHead ? '=' : '≠') + ' ' + receipt.deterministic.derivedHead.slice(0, 16) + '…'],
    ['books (node = feed)', receipt.deterministic.booksSha256 === receipt.deterministic.feedBooksSha256 ? 'equal, sha256 ' + receipt.deterministic.booksSha256.slice(0, 16) + '…' : 'DIFFER'],
    ['machine', receipt.ran.cpu + ' · ' + receipt.ran.os + ' · Node ' + receipt.ran.node], ['run', receipt.ran.at.replace('T', ' ').slice(0, 16) + ' UTC'],
    ['claims sealed', receipt.sealed.map((s) => s.path + ' @ ' + s.commit.slice(0, 7)).join(' · ')],
  ];
  $('p-facts').innerHTML = facts.map(([k, v]) => '<tr><td>' + esc(k) + '</td><td class="mono">' + esc(v) + '</td></tr>').join('');
  $('p-seals').innerHTML = receipt.sealed.map((s) => '<a href="https://github.com/sjgant80-hub/break-it/commit/' + esc(s.commit) + '">' + esc(s.path) + ' @ ' + esc(s.commit.slice(0, 7)) + '</a>').join(' · ');
  $('p-attempts').innerHTML = (receipt.attempts || []).map((a) => '<li>' + esc(a) + '</li>').join('');
  for (const [id, val] of [['d-in', n0(f.admitted + f.injections.length * 2)], ['d-onsight', n0(f.injections.filter((i) => i.second.stage === 'recognised').length)],
    ['d-gate', n0(f.injections.filter((i) => i.first.status === 403).length)], ['d-ledger', n0(f.ledgerEntries)], ['d-app', n0(f.books.keys) + ' keys'], ['d-ref', f.referee.breached ? 'BREACHED' : '0 breaches'],
    ['d-rate', n0(f.perSecond) + '/s'], ['d-egress', n0(f.egress.afterListening) + ' out']]) { const el = $(id); if (el) el.textContent = val; }
  $('h-records').textContent = n0(f.admitted); $('h-held').textContent = receipt.held + ' / ' + receipt.verdicts.length; $('h-out').textContent = n0(f.egress.afterListening);
  $('h-battery').textContent = f.redteam.cases + ' / ' + f.redteam.cases;
  const rate = Math.max(1, Math.floor(f.perSecond));
  $('c-rate').value = String(rate); $('c-rate-note').textContent = 'measured in the pilot: ' + n0(f.perSecond) + ' a second on one laptop';
  cost();
}

// ── the blueprint's mutation scores, from the gate's own receipt ──────────────────────────────────────────────
async function loadWitness() {
  let w = null;
  try { w = await (await fetch('receipts/witness.json')).json(); } catch { w = null; }
  if (!w || !Array.isArray(w.kernels)) return;
  for (const k of w.kernels) { const td = document.querySelector('[data-k="' + CSS.escape(k.src) + '"]'); if (td) td.textContent = n0(k.killed) + ' / ' + n0(k.total) + ' killed' + (k.ignored ? ' · ' + k.ignored + ' reviewed' : '') + (k.clean ? '' : ' · NOT CLEAN'); }
  $('bp-total').textContent = (w.clean ? 'CLEAN: ' : 'NOT CLEAN: ') + n0(w.killed) + ' of ' + n0(w.total) + ' mutants killed across ' + w.kernels.length + ' kernels, the rest reviewed-equivalent with a written reason · CI re-runs it on every push and the receipt must come out byte for byte the same';
}

// ── the CFO's case ────────────────────────────────────────────────────────────────────────────────────────────
let prices = null, sources = [];
async function loadSources() {
  try { const j = await (await fetch('costs/sources.json')).json(); const p = pricesFrom(j); if (p.ok) { prices = p.prices; sources = j.sources; } } catch { prices = null; }
  $('c-sources').innerHTML = sources.map((s) => '<li><a href="' + esc(s.url) + '">' + esc(s.what) + '</a> <span class="dim">(read ' + esc(s.read) + ')</span></li>').join('');
  cost();
}
const int = (id) => { const v = Number($(id).value); return Number.isFinite(v) ? Math.round(v) : NaN; };
const pence = (id) => { const v = Number($(id).value); return Number.isFinite(v) ? Math.round(v * 100) : NaN; };
function cost() {
  if (!prices) return;
  const inputs = { requests: int('c-req'), acls: int('c-acl'), rules: int('c-rules'), api: $('c-api').value, rate: int('c-rate'), watts: int('c-watts'), hours: int('c-hours'),
    fx10k: Math.round(Number($('c-fx').value) * 10000), machinePence: pence('c-machine'), lifeMonths: int('c-life'), staffHours: int('c-staffh'), staffRatePence: pence('c-staffr'), staffShare: int('c-share') };
  const r = costCase(inputs, prices);
  if (!r.ok) { $('c-out').innerHTML = '<p class="no">' + esc(r.why) + '</p>'; return; }
  const save = r.monthlyPence;
  $('c-out').innerHTML =
    '<p class="bottom">The managed path costs <b>' + esc(usd(r.managed.totalCents)) + '</b> a month (' + esc(gbp(r.managed.totalPence)) + '). ' +
    (r.node.nodes === 1 ? 'One break-it node' : esc(n0(r.node.nodes)) + ' break-it nodes') + ' cost' + (r.node.nodes === 1 ? 's' : '') + ' <b>' + esc(gbp(r.node.totalPence)) + '</b>. ' +
    (save >= 0 ? 'You keep <b>' + esc(gbp(save)) + '</b> a month, <b>' + esc(gbp(r.yearlyPence)) + '</b> a year.' : 'At these figures the node path costs <b>' + esc(gbp(-save)) + '</b> a month more.') + '</p>' +
    [['AWS WAF (web ACLs, rules, requests)', usd(r.managed.wafCents)], ['API Gateway (' + inputs.api + ')', usd(r.managed.gatewayCents)], ['Managed path, in pounds at the Bank of England rate you set', gbp(r.managed.totalPence)],
      ['Nodes the measured rate needs for this volume', n0(r.node.nodes)], ['Their electricity at the Ofgem cap', gbp(r.node.electricityPence)], ['Machines you buy, spread over their life', gbp(r.node.machinePence)],
      ['Staff time the journal takes off your people', gbp(r.staffPence)], ['Licence', 'MIT, no licence fee']]
      .map(([k, v]) => '<div class="line"><span>' + esc(k) + '</span><span>' + esc(v) + '</span></div>').join('');
  $('c-scale').innerHTML = [10000000, 100000000, 1000000000, 5000000000].map((requests) => {
    const s = costCase({ ...inputs, requests }, prices);
    return s.ok ? '<tr><td class="mono">' + esc(n0(requests)) + '</td><td class="mono">' + esc(usd(s.managed.totalCents)) + '</td><td class="mono">' + esc(n0(s.node.nodes)) + '</td><td class="mono">' + esc(gbp(s.node.totalPence)) + '</td><td class="mono">' + esc(gbp(s.yearlyPence)) + '</td></tr>'
      : '<tr><td class="mono">' + esc(n0(requests)) + '</td><td colspan="4" class="no">' + esc(s.why) + '</td></tr>';
  }).join('');
}
for (const id of ['c-req', 'c-acl', 'c-rules', 'c-api', 'c-rate', 'c-watts', 'c-hours', 'c-fx', 'c-machine', 'c-life', 'c-staffh', 'c-staffr', 'c-share']) $(id).addEventListener('input', cost);

// ── wire up ───────────────────────────────────────────────────────────────────────────────────────────────────
$('play').addEventListener('click', () => setRunning(!running));
for (const b of document.querySelectorAll('[data-speed]')) b.addEventListener('click', () => {
  speed = b.dataset.speed; for (const x of document.querySelectorAll('[data-speed]')) x.setAttribute('aria-pressed', String(x === b));
});
for (const b of document.querySelectorAll('[data-atk]')) b.addEventListener('click', () => attack(b.dataset.atk));
$('six').addEventListener('click', pilotSix);
$('reset').addEventListener('click', () => {
  running = false; counters.clear(); senders.clear(); memory = emptyMemory(); library = emptyLibrary(); app = makeApp(); referee = makeReferee();
  packets = []; admittedHashes = new Set(); yourRefusals = 0; fed = 0; cc = 1n; lastGenuine = null; booksBad = 0; for (const k of Object.keys(S)) S[k] = 0;
  for (const k of Object.keys(vecState)) vecState[k] = ''; delete vecState.yours; logEl.innerHTML = ''; $('rune').className = 'rune';
  $('play').textContent = '▶ play the feed'; log('reset: an empty ledger, an empty immune memory, the same gate', 'info'); render();
});
$('load').addEventListener('click', () => { if (lastGenuine) $('attack').value = toHex(lastGenuine); });
for (const b of document.querySelectorAll('[data-fill]')) b.addEventListener('click', async () => { const x = await build(b.dataset.fill); if (x) $('attack').value = toHex(x); });
$('send').addEventListener('click', async () => {
  const hex = $('attack').value.trim(); if (!hex) return;
  const r = await sendPacket(fromHex(hex), 'you');
  showConsole(r); showAttack('yours', r);
});

(async function boot() {
  renderRebound(); renderVectors(); loadSources(); loadReceipt(); loadWitness();
  try {
    const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    feedKey = kp.privateKey;
    const pubKp = kp.publicKey;
    feedPub = new Uint8Array(await crypto.subtle.exportKey('raw', pubKp));
    keyset = sha256(new TextEncoder().encode(JSON.stringify([[1, toHex(feedPub)]])));
    $('kstat').textContent = 'kernel live in this tab'; $('kstat').className = 'pill live';
  } catch {
    $('kstat').textContent = 'this browser has no WebCrypto Ed25519: use a current Chrome, Edge, Firefox or Safari'; $('kstat').className = 'pill bad';
    log('This browser cannot sign or verify Ed25519, so the live gate cannot run here. Every number in the pilot below is from a real node, and the receipts still load.', 'breach');
    render(); return;
  }
  log('online: verify-before-parse gate, immune system, sentinel, referee, the same kernels CI gates', 'info');
  if (await loadFeed()) {
    log('the feed: ' + n0(records.length) + ' real payment records (UCI, CC BY 4.0) · press play, or launch an attack', 'info');
    for (let i = 0; i < 12; i++) await feedOne(i % 3 === 0);
    checkBooks();
  } else log(feedErr, 'breach');
  render();
  $('play').disabled = !records;
})();
