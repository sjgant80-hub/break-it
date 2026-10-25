// pilot/egress-trap.mjs — the CISO's meter. Loaded into the node's process BEFORE the node, with --import, it counts
// every attempt the process makes to reach out: a TCP connect (http, https, fetch and raw sockets all end in one), a
// TLS connect, a UDP socket, a DNS lookup or resolve, a fetch. It also writes down every address the process listens
// on, and whether each attempt came before or after the process first listened. It blocks nothing and changes
// nothing. A meter that cannot see is a fake green, so the pilot first runs a canary through this same file that does
// each of those things once, and refuses to trust a zero unless the canary was seen.
import net from 'node:net';
import tls from 'node:tls';
import dgram from 'node:dgram';
import dns from 'node:dns';
import { syncBuiltinESMExports } from 'node:module';

export const egress = { tcp: 0, tls: 0, udp: 0, dns: 0, fetch: 0, afterListening: 0, seen: [], listening: [] };
let listened = false;                                           // every attempt is written down as before or after the first listen
const note = (kind, what) => {
  egress[kind]++;
  if (listened) egress.afterListening++;
  if (egress.seen.length < 32) egress.seen.push(kind + ' ' + String(what).slice(0, 96) + (listened ? ' (after listening)' : ' (before listening)'));
};
const where = (a) => { try { return typeof a[0] === 'object' && a[0] ? (a[0].host || a[0].path || '') + ':' + (a[0].port || '') : a.slice(0, 2).join(':'); } catch { return '?'; } };

const connect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...a) { note('tcp', where(a)); return connect.apply(this, a); };
const tlsConnect = tls.connect;
tls.connect = function (...a) { note('tls', where(a)); return tlsConnect.apply(this, a); };
const udp = dgram.createSocket;
dgram.createSocket = function (...a) { note('udp', JSON.stringify(a[0])); return udp.apply(this, a); };
for (const fn of ['lookup', 'lookupService', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCname', 'resolveMx', 'resolveNs', 'resolveTxt', 'resolveSrv', 'reverse']) {
  if (typeof dns[fn] === 'function') { const f = dns[fn]; dns[fn] = function (...a) { note('dns', fn + ' ' + a[0]); return f.apply(this, a); }; }
  if (dns.promises && typeof dns.promises[fn] === 'function') { const f = dns.promises[fn]; dns.promises[fn] = function (...a) { note('dns', fn + ' ' + a[0]); return f.apply(this, a); }; }
}
if (typeof globalThis.fetch === 'function') { const f = globalThis.fetch; globalThis.fetch = function (...a) { note('fetch', a[0]); return f.apply(this, a); }; }
const listen = net.Server.prototype.listen;
net.Server.prototype.listen = function (...a) {
  this.once('listening', () => { listened = true; try { const ad = this.address(); egress.listening.push(typeof ad === 'string' ? ad : ad.address + ':' + ad.port); } catch { /* the count stays */ } });
  return listen.apply(this, a);
};
syncBuiltinESMExports();

/** Everything but the listening list is an outbound attempt. */
export const outbound = () => egress.tcp + egress.tls + egress.udp + egress.dns + egress.fetch;
