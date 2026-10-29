// tarpit/node.mjs — one break-it node in its own process for the tarpit measurement (tarpit/run.mjs forks it), so the
// attacker's proof-of-work, solved in the measuring process, never shares an event loop with the node it is measuring.
//   argv[2] = JSON { ledgerPath, journalPath, lootPath, tarpit }   → sends { url } once listening
// Asked 'report', it sends what the measurement reads (its antibody library, stats, held count); asked 'close', it
// closes and exits. The node is src/server.mjs startNode as `node run.mjs` starts it, pinning the pilot's ingest key.
import { startNode } from '../src/server.mjs';
import { PUBKEYS } from '../pilot/lib.mjs';

const o = JSON.parse(process.argv[2]);
const n = await startNode({ port: 0, ledgerPath: o.ledgerPath, journalPath: o.journalPath, lootPath: o.lootPath, pubkeys: PUBKEYS, tarpit: o.tarpit });
process.on('message', async (m) => {
  if (m === 'holding') process.send({ holding: n.holding });
  if (m === 'report') process.send({ report: { library: n.library, stats: n.stats, holding: n.holding } });
  if (m === 'close') { await n.close(); process.send({ closed: true }); process.exit(0); }
});
process.send({ url: n.url });
