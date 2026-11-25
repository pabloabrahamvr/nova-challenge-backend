import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { CryptoError, encrypt, loadKey } from '../src/crypto.js';
import { decrypt } from './helpers/crypto.js';

const key = randomBytes(32);
const AAD = 'req-1';
const SECRET = 'my SSN is 123-45-6789 and mail john@example.com';

const flip = (b64: string): string => {
  const buf = Buffer.from(b64, 'base64');
  buf[0] = buf[0]! ^ 0x01;
  return buf.toString('base64');
};

describe('loadKey', () => {
  it('accepts a 32-byte random base64 key', () => {
    expect(loadKey(key.toString('base64')).equals(key)).toBe(true);
  });

  it.each([
    ['undefined', undefined],
    ['empty', ''],
    ['16 bytes', randomBytes(16).toString('base64')],
    ['33 bytes', randomBytes(33).toString('base64')],
    ['not base64', 'not-a-key!!!'],
    ['hex instead of base64', randomBytes(32).toString('hex')],
  ])('rejects %s', (_label, value) => {
    expect(() => loadKey(value)).toThrow(CryptoError);
  });

  // review #17: weak keys
  it.each([
    ['all zero bytes', Buffer.alloc(32, 0)],
    ['all 0xff bytes', Buffer.alloc(32, 0xff)],
    ['repeating 2-byte pattern', Buffer.from('abababababababababababababababab')],
    ['ASCII counter (only 10 distinct bytes)', Buffer.from('01234567890123456789012345678901')],
  ])('rejects a low-entropy key: %s', (_label, bytes) => {
    expect(bytes).toHaveLength(32);
    expect(() => loadKey(bytes.toString('base64'))).toThrow(CryptoError);
  });

  it('never echoes the bad value in the error', () => {
    for (const bad of [randomBytes(16).toString('base64'), Buffer.alloc(32, 7).toString('base64')]) {
      try {
        loadKey(bad);
        expect.unreachable();
      } catch (e) {
        expect((e as Error).message).not.toContain(bad);
      }
    }
  });
});

describe('encrypt / decrypt (independent test-side decrypt)', () => {
  it('round-trips with the authorized key', () => {
    expect(decrypt(encrypt(SECRET, key, AAD), key, AAD)).toBe(SECRET);
  });

  it('round-trips empty, unicode and large input', () => {
    for (const text of ['', 'héllo 世界 🔐', 'x'.repeat(100_000)]) {
      expect(decrypt(encrypt(text, key, AAD), key, AAD)).toBe(text);
    }
  });

  it('uses AES-256-GCM with a 12-byte IV and 16-byte tag', () => {
    const p = encrypt(SECRET, key, AAD);
    expect(p.alg).toBe('aes-256-gcm');
    expect(Buffer.from(p.iv, 'base64')).toHaveLength(12);
    expect(Buffer.from(p.tag, 'base64')).toHaveLength(16);
  });

  it('uses a fresh IV every time, so equal plaintexts give different ciphertexts', () => {
    const ivs = new Set<string>();
    const first = encrypt(SECRET, key, AAD);
    for (let i = 0; i < 1000; i++) ivs.add(encrypt(SECRET, key, AAD).iv);
    expect(ivs.size).toBe(1000);
    expect(encrypt(SECRET, key, AAD).ciphertext).not.toBe(first.ciphertext);
  });

  it('does not contain the plaintext in any field', () => {
    const json = JSON.stringify(encrypt(SECRET, key, AAD));
    expect(json).not.toContain('123-45-6789');
    expect(json).not.toContain('john@example.com');
  });

  it('exposes no decrypt function from the production module', async () => {
    const mod = await import('../src/crypto.js');
    expect(Object.keys(mod)).not.toContain('decrypt');
  });
});

describe('tamper detection', () => {
  const p = encrypt(SECRET, key, AAD);

  it.each([
    ['ciphertext', { ...p, ciphertext: flip(p.ciphertext) }, key, AAD],
    ['tag', { ...p, tag: flip(p.tag) }, key, AAD],
    ['iv', { ...p, iv: flip(p.iv) }, key, AAD],
    ['truncated tag', { ...p, tag: Buffer.from(p.tag, 'base64').subarray(0, 4).toString('base64') }, key, AAD],
    ['short iv', { ...p, iv: Buffer.from(p.iv, 'base64').subarray(0, 8).toString('base64') }, key, AAD],
    ['wrong AAD (record swap)', p, key, 'req-2'],
    ['wrong key', p, randomBytes(32), AAD],
    ['wrong alg label', { ...p, alg: 'aes-128-cbc' as never }, key, AAD],
  ])('rejects %s', (_label, payload, k, aad) => {
    expect(() => decrypt(payload, k, aad)).toThrow('Decryption failed');
  });

  it('failure message leaks neither plaintext nor key', () => {
    try {
      decrypt({ ...p, tag: flip(p.tag) }, key, AAD);
      expect.unreachable();
    } catch (e) {
      const msg = (e as Error).message;
      expect(msg).not.toContain('123-45-6789');
      expect(msg).not.toContain(key.toString('base64'));
    }
  });
});
