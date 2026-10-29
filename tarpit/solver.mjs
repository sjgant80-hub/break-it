// tarpit/solver.mjs — a worker thread that pays the rebound's price for the measuring process: given a challenge and
// its bits, it finds the nonce with the rebound's own solve() (src/rebound.mjs, "for the honest client and the attack
// kit"). In a worker, so solving never blocks the timings the measuring process takes.
import { parentPort } from 'node:worker_threads';
import { createHash } from 'node:crypto';
import { solve } from '../src/rebound.mjs';

const sha = (s) => createHash('sha256').update(s).digest('hex');
parentPort.on('message', ({ id, challenge, bits }) => parentPort.postMessage({ id, nonce: solve(challenge, bits, sha) }));
