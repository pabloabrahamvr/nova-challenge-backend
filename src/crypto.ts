import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/**
 * AES-256-GCM helpers. Node's built-in crypto only.
 *
 * - 32-byte key from the environment (base64), validated by loadKey().
 * - Fresh random 12-byte IV for every encryption (never reused, never derived).
 * - 16-byte auth tag stored next to the ciphertext.
 * - AAD binds a ciphertext to its audit record, so entries cannot be swapped.
 *
 * Error messages are fixed strings: they never include key, plaintext or ciphertext.
 */

const ALGORITHM = 'aes-256-gcm';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
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
  const hint = 'AUDIT_ENCRYPTION_KEY must be 32 bytes, base64-encoded (see .env.example)';
  if (!base64) throw new CryptoError(hint);
  const key = Buffer.from(base64, 'base64');
  // Re-encoding rejects strings that are not canonical base64 (Buffer.from silently skips bad chars).
  if (key.length !== KEY_BYTES || key.toString('base64') !== base64.trim()) {
    throw new CryptoError(hint);
  }
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

/**
 * Decrypt a payload. Intended for tests and offline audit tooling only:
 * no request path calls this, and the API exposes no decrypt endpoint.
 */
export function decrypt(payload: EncryptedPayload, key: Buffer, aad: string): string {
  try {
    if (payload.alg !== ALGORITHM) throw new Error('alg');
    const iv = Buffer.from(payload.iv, 'base64');
    const tag = Buffer.from(payload.tag, 'base64');
    // Node accepts truncated tags unless the length is checked explicitly.
    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) throw new Error('length');
    const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(Buffer.from(payload.ciphertext, 'base64')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    // Same message for wrong key, tampering, wrong AAD or malformed input: no oracle.
    throw new CryptoError('Decryption failed');
  }
}
