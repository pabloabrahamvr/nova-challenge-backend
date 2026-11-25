import { createDecipheriv } from 'node:crypto';
import type { EncryptedPayload } from '../../src/crypto.js';

/**
 * Independent AES-256-GCM decrypt for tests and offline verification only.
 * It lives outside src/ on purpose: the service never decrypts anything.
 * One fixed error for every failure (wrong key, tampering, wrong AAD, malformed input).
 */
export function decrypt(payload: EncryptedPayload, key: Buffer, aad: string): string {
  try {
    if (payload.alg !== 'aes-256-gcm') throw new Error('alg');
    const iv = Buffer.from(payload.iv, 'base64');
    const tag = Buffer.from(payload.tag, 'base64');
    // Node accepts truncated tags unless the length is checked explicitly.
    if (iv.length !== 12 || tag.length !== 16) throw new Error('length');
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(payload.ciphertext, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    throw new Error('Decryption failed');
  }
}
