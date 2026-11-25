import { createCipheriv, randomBytes } from 'node:crypto';

/**
 * AES-256-GCM helpers. Node's built-in crypto only.
 *
 * - 32-byte key from the environment (base64), validated by loadKey().
 * - Fresh random 12-byte IV for every encryption (never reused, never derived).
 * - 16-byte auth tag stored next to the ciphertext.
 * - AAD binds a ciphertext to its audit record (see auditAad), so entries cannot be swapped or edited.
 * - There is deliberately NO decrypt function here: nothing in the service ever reads originals back.
 *   Tests carry their own independent decrypt (tests/helpers/crypto.ts), which also proves interoperability.
 *
 * Limits: random 96-bit IVs are safe for roughly 2^32 messages per key (NIST SP 800-38D). Rotate the key
 * (bump KEY_VERSION) well before that; at 1 message/second that is over a century, but a busy deployment
 * must plan for rotation.
 *
 * Error messages are fixed strings: they never include key, plaintext or ciphertext.
 */

const ALGORITHM = 'aes-256-gcm';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MIN_DISTINCT_KEY_BYTES = 16;
/** Bumped when the key or algorithm changes, so old records stay decryptable. */
export const KEY_VERSION = 1;

export interface EncryptedPayload {
  alg: typeof ALGORITHM;
  keyVersion: number;
  iv: string; // base64, 12 bytes
  tag: string; // base64, 16 bytes
  ciphertext: string; // base64
}

export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoError';
  }
}

/** Parse the base64 key from env. Throws a generic error that never echoes the value. */
export function loadKey(base64: string | undefined): Buffer {
  const hint = 'AUDIT_ENCRYPTION_KEY must be 32 random bytes, base64-encoded (see .env.example)';
  if (!base64) throw new CryptoError(hint);
  const key = Buffer.from(base64, 'base64');
  // Re-encoding rejects strings that are not canonical base64 (Buffer.from silently skips bad chars).
  if (key.length !== KEY_BYTES || key.toString('base64') !== base64.trim()) {
    throw new CryptoError(hint);
  }
  // Reject obviously non-random keys (all zeros, repeated patterns). A random key has ~31 distinct bytes.
  if (new Set(key).size < MIN_DISTINCT_KEY_BYTES) throw new CryptoError(hint);
  return key;
}

export function encrypt(plaintext: string, key: Buffer, aad: string): EncryptedPayload {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    alg: ALGORITHM,
    keyVersion: KEY_VERSION,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}
