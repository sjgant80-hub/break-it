// keys.mjs — Ed25519 keys (node:crypto) and the pinned key table. One algorithm, raw 32-byte public keys, no key
// ever read from a packet. Private keys live in secrets/ (git-ignored, never served); public keys in config/.
import { generateKeyPairSync, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
/** The raw 32-byte public key of a key object (private or public). */
export const rawPublic = (keyObject) => new Uint8Array(createPublicKey(keyObject).export({ format: 'der', type: 'spki' }).subarray(12));
export const publicFromRaw = (raw) => createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]), format: 'der', type: 'spki' });
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
/** A key pair from a 32-byte seed — for deterministic tests and receipts only. */
export const keyFromSeed = (seed32) => createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed32)]), format: 'der', type: 'pkcs8' });

/** Load a private key PEM from secrets/, creating it the first time. */
export function loadOrCreate(secretsDir, name) {
  mkdirSync(secretsDir, { recursive: true });
  const path = join(secretsDir, name + '.pem');
  if (!existsSync(path)) {
    const { privateKey } = generateKeyPairSync('ed25519');
    writeFileSync(path, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  }
  return createPrivateKey(readFileSync(path));
}

export const signWith = (privateKey) => (bytes) => new Uint8Array(edSign(null, Buffer.from(bytes), privateKey));

/**
 * The pinned table: { senderId → raw public key }. keyFor/verify are the gate's injected crypto. verify never
 * throws: a malformed key or signature is simply not a valid signature.
 */
export function keyTable(pubkeysHex) {
  const raw = new Map(), objects = new Map();
  for (const [id, hex] of Object.entries(pubkeysHex || {})) {
    const n = Number(id);
    if (!Number.isInteger(n) || n < 0 || n > 255 || !/^[0-9a-f]{64}$/.test(hex)) throw new Error('bad pinned key for sender ' + id);
    raw.set(n, new Uint8Array(Buffer.from(hex, 'hex')));
    objects.set(hex, publicFromRaw(Buffer.from(hex, 'hex')));
  }
  const keyset = createHash('sha256').update(JSON.stringify([...raw.entries()].sort((a, b) => a[0] - b[0]).map(([i, k]) => [i, Buffer.from(k).toString('hex')]))).digest('hex');
  return {
    keyset,
    keyFor: (id) => raw.get(id) || null,
    verify(message, signature, publicKey) {
      try {
        const obj = objects.get(Buffer.from(publicKey).toString('hex')) || publicFromRaw(publicKey);
        return edVerify(null, Buffer.from(message), obj, Buffer.from(signature)) === true;
      } catch { return false; }
    },
  };
}
