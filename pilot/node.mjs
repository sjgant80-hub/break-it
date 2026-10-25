// pilot/node.mjs — the pilot's node, in a process of its own so that the egress meter (loaded first, with --import)
// sees only the node: `node --import ./pilot/egress-trap.mjs pilot/node.mjs`, forked by pilot/measure.mjs and
// pilot/check.mjs. It is the same startNode `node run.mjs` uses, on the real clock, with no peers.
//   --canary   do one of each outbound thing instead, so the pilot can prove the meter sees them
import { egress, outbound } from './egress-trap.mjs';
import { join } from 'node:path';
import net from 'node:net';
import dgram from 'node:dgram';
import dns from 'node:dns';

if (process.argv.includes('--canary')) {
  await new Promise((r) => { const s = net.connect({ host: '127.0.0.1', port: 9 }); s.on('error', r); s.on('connect', () => { s.destroy(); r(); }); });
  await new Promise((r) => { const u = dgram.createSocket('udp4'); u.close(r); });
  await new Promise((r) => dns.lookup('localhost', () => r()));
  try { await fetch('http://127.0.0.1:9/'); } catch { /* refused: only the attempt counts */ }
  process.send({ canary: { ...egress, outbound: outbound() } });
  process.exit(0);
}

const { startNode } = await import('../src/server.mjs');
const { keyFromSeed } = await import('../src/keys.mjs');
const env = JSON.parse(process.env.PILOT || '{}');
const node = await startNode({
  port: 0, ledgerPath: join(env.dir, 'ledger.jsonl'), journalPath: join(env.dir, 'journal.jsonl'),
  pubkeys: env.pubkeys, nodeKey: keyFromSeed(Buffer.from(env.nodeSeed, 'hex')), peers: [],
});
process.send({ ready: true, url: node.url, node: node.node });
process.on('message', async (m) => {
  if (m && m.bye) {
    const stats = { ...node.stats }, antibodies = { exact: Object.keys(node.library.exact).length, shapes: node.library.shapes.length };
    await node.close();
    process.send({ egress: { ...egress, outbound: outbound() }, stats, antibodies });
    process.exit(0);
  }
});
