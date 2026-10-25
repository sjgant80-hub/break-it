import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { recordsFrom, books, MONTHS, FIRST_PERIOD } from '../src/feed.mjs';

const TEXT = readFileSync(new URL('../feeds/credit-default.csv', import.meta.url), 'utf8');
const SOURCES = JSON.parse(readFileSync(new URL('../feeds/SOURCES.json', import.meta.url), 'utf8'));
const H = 'ID,X,PAY_AMT1,PAY_AMT2,PAY_AMT3,PAY_AMT4,PAY_AMT5,PAY_AMT6';
const row = (id, a = [1, 2, 3, 4, 5, 6]) => [id, 'x', ...a].join(',');

test('the committed feed is the one SOURCES.json names, byte for byte', () => {
  assert.equal(createHash('sha256').update(TEXT).digest('hex'), SOURCES.files[0].sha256);
  assert.ok(!TEXT.includes('\r'), 'LF only');
});

test('the real feed: 30,000 clients, 180,000 records, April to September 2005 in that order', () => {
  const r = recordsFrom(TEXT);
  assert.equal(r.ok, true);
  assert.equal(r.accounts, 30000);
  assert.equal(r.records.length, 180000);
  assert.deepEqual(r.records.slice(0, 7), [
    { account: 1, period: 63, amount: 0 }, { account: 1, period: 64, amount: 0 }, { account: 1, period: 65, amount: 0 },
    { account: 1, period: 66, amount: 0 }, { account: 1, period: 67, amount: 689 }, { account: 1, period: 68, amount: 0 },
    { account: 2, period: 63, amount: 2000 }]);
  assert.deepEqual(r.records.at(-1), { account: 30000, period: 68, amount: 2078 });
  assert.equal(r.records.reduce((s, x) => s + x.amount, 0), 949541777);
  const b = books(r.records);
  assert.equal(Object.keys(b).length, 210000);
  assert.equal(b.A1, 689);
  assert.equal(b.A30000, 8308);
  assert.equal(b['P1.67'], 689);
});

test('columns are found by name, not by place; the months run PAY_AMT6 → PAY_AMT1', () => {
  assert.deepEqual(MONTHS, ['PAY_AMT6', 'PAY_AMT5', 'PAY_AMT4', 'PAY_AMT3', 'PAY_AMT2', 'PAY_AMT1']);
  assert.equal(FIRST_PERIOD, 63);
  const r = recordsFrom(H + '\n' + row(7, [10, 20, 30, 40, 50, 60]) + '\n');
  assert.deepEqual(r, { ok: true, accounts: 1, records: [60, 50, 40, 30, 20, 10].map((amount, m) => ({ account: 7, period: 63 + m, amount })) });
});

test('a trailing CR is read past; a missing final newline is fine; one trailing blank line is the end', () => {
  const a = recordsFrom(H + '\r\n' + row(1) + '\r\n' + row(2) + '\r\n');
  const b = recordsFrom(H + '\n' + row(1) + '\n' + row(2));
  assert.equal(a.ok, true); assert.equal(a.records.length, 12);
  assert.deepEqual(a, b);
});

test('a bad line refuses the whole feed, naming the line and the reason', () => {
  const cases = [
    [null, 0, 'the feed is not text'],
    ['', 1, 'the header lacks ID or a PAY_AMT column'],
    ['X,PAY_AMT1,PAY_AMT2,PAY_AMT3,PAY_AMT4,PAY_AMT5,PAY_AMT6\n1,1,1,1,1,1,1', 1, 'the header lacks ID or a PAY_AMT column'],
    ['ID,PAY_AMT1,PAY_AMT2,PAY_AMT3,PAY_AMT4,PAY_AMT5\n1,1,1,1,1,1', 1, 'the header lacks ID or a PAY_AMT column'],
    [H + '\n' + row(1) + '\n\n' + row(2), 3, 'an empty line inside the feed'],
    [H + '\n' + row(1) + ',9', 2, 'the line has 9 fields, the header 8'],
    [H + '\n1,x,1,2', 2, 'the line has 4 fields, the header 8'],
    [H + '\n' + row('a'), 2, 'the ID is not a whole number'],
    [H + '\n' + row('-1'), 2, 'the ID is not a whole number'],
    [H + '\n' + row(''), 2, 'the ID is not a whole number'],
    [H + '\n' + row('1.5'), 2, 'the ID is not a whole number'],
    [H + '\n' + row('1234567890'), 2, 'the ID is not a whole number'],
    [H + '\n' + row(0), 2, 'the ID is outside 1–99999999'],
    [H + '\n' + row(100000000), 2, 'the ID is outside 1–99999999'],
    [H + '\n' + row(5) + '\n' + row(5), 3, 'the ID 5 is already in the feed'],
    [H + '\n' + row(1, [1, 2, 3, 4, 5, -6]), 2, 'PAY_AMT6 is not a whole amount from 0 to 100000000'],
    [H + '\n' + row(1, ['x', 2, 3, 4, 5, 6]), 2, 'PAY_AMT1 is not a whole amount from 0 to 100000000'],
    [H + '\n' + row(1, [1, 2, 3, 4, 5, 100000001]), 2, 'PAY_AMT6 is not a whole amount from 0 to 100000000'],
    [H + '\n' + row(1, [1, 2, 3, 4, 5, '']), 2, 'PAY_AMT6 is not a whole amount from 0 to 100000000'],
    [H + '\n' + row(1, [1, 2, 3, 4, 5, '1.5']), 2, 'PAY_AMT6 is not a whole amount from 0 to 100000000'],
  ];
  for (const [text, line, why] of cases) assert.deepEqual(recordsFrom(text), { ok: false, line, why }, JSON.stringify(text));
});

test('the edges are accepted: ID 1 and 99999999, amounts 0 and 100000000', () => {
  const r = recordsFrom(H + '\n' + row(1, [0, 0, 0, 0, 0, 100000000]) + '\n' + row(99999999));
  assert.equal(r.ok, true);
  assert.equal(r.accounts, 2);
  assert.deepEqual(r.records[0], { account: 1, period: 63, amount: 100000000 });
  assert.equal(r.records[6].account, 99999999);
});

test('books: balances sum, account-months hold the last amount, junk entries count for nothing', () => {
  assert.deepEqual(books([{ account: 3, period: 63, amount: 5 }, { account: 3, period: 64, amount: 7 }, null, 'x', { account: 4, period: 63, amount: 0 }]),
    { A3: 12, 'P3.63': 5, 'P3.64': 7, A4: 0, 'P4.63': 0 });
  assert.deepEqual(books([{ account: 3, period: 63, amount: 5 }, { account: 3, period: 63, amount: 9 }]), { A3: 14, 'P3.63': 9 });
  for (const junk of [null, undefined, 5, 'x', {}]) assert.deepEqual(books(junk), {});
});
