import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { decrypt } from '../src/crypto.js';
import { AuditWriteError, createAuditLog, type AuditInput, type AuditRecord } from '../src/auditStore.js';

const key = randomBytes(32);
const ORIGINAL = 'Card 4111 1111 1111 1111, mail john@example.com, ssn 123-45-6789';
const REDACTED = 'Card <REDACTED: CREDIT_CARD>, mail <REDACTED: EMAIL>, ssn <REDACTED: SSN>';
const FIXED = new Date('2026-01-02T03:04:05.000Z');

const input = (n: number | string = 1, over: Partial<AuditInput> = {}): AuditInput => ({
  requestId: `req-${n}`,
  userId: 'user-1',
  providerStatus: 'success',
  originalMessage: ORIGINAL,
  redactedMessage: REDACTED,
  ...over,
});

let dir: string;
let file: string;
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'audit-test-'));
  file = join(dir, 'nested', 'audit.jsonl'); // nested: store must create the directory
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

const readRecords = async (): Promise<AuditRecord[]> =>
  (await readFile(file, 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l) as AuditRecord);

describe('audit persistence', () => {
  it('writes every required field, with the redacted message in plaintext', async () => {
    const log = createAuditLog({ filePath: file, key, now: () => FIXED });
    await log.write(input(1, { providerStatus: 'failed' }));

    const [rec] = await readRecords();
    expect(rec).toMatchObject({
      requestId: 'req-1',
      userId: 'user-1',
      timestamp: '2026-01-02T03:04:05.000Z',
      providerStatus: 'failed',
      redactedMessage: REDACTED,
    });
    expect(rec!.encryptedOriginalMessage).toMatchObject({ alg: 'aes-256-gcm', keyVersion: 1 });
  });

  it('never stores the plaintext original on disk', async () => {
    await createAuditLog({ filePath: file, key }).write(input());
    const raw = await readFile(file, 'utf8');
    for (const s of ['4111', 'john@example.com', '123-45-6789']) expect(raw).not.toContain(s);
  });

  it('lets the authorized key decrypt the stored original', async () => {
    await createAuditLog({ filePath: file, key }).write(input(7));
    const [rec] = await readRecords();
    expect(decrypt(rec!.encryptedOriginalMessage, key, rec!.requestId)).toBe(ORIGINAL);
  });

  it('cannot be decrypted with another key or moved to another record', async () => {
    await createAuditLog({ filePath: file, key }).write(input(7));
    const [rec] = await readRecords();
    expect(() => decrypt(rec!.encryptedOriginalMessage, randomBytes(32), rec!.requestId)).toThrow();
    expect(() => decrypt(rec!.encryptedOriginalMessage, key, 'req-other')).toThrow();
  });

  it('keeps multi-line messages on a single line per record', async () => {
    const log = createAuditLog({ filePath: file, key });
    await log.write(input(1, { originalMessage: 'a\nb', redactedMessage: 'a\nb\r\nc' }));
    await log.write(input(2));
    expect((await readFile(file, 'utf8')).trimEnd().split('\n')).toHaveLength(2);
    expect(await readRecords()).toHaveLength(2);
  });

  it('appends to an existing file instead of overwriting it', async () => {
    await createAuditLog({ filePath: file, key }).write(input(1));
    await createAuditLog({ filePath: file, key }).write(input(2)); // e.g. after a restart
    expect((await readRecords()).map((r) => r.requestId)).toEqual(['req-1', 'req-2']);
  });

  it.skipIf(process.platform === 'win32')('creates the file readable by the owner only', async () => {
    await createAuditLog({ filePath: file, key }).write(input());
    expect((await stat(file)).mode & 0o077).toBe(0);
  });
});

describe('concurrent writes', () => {
  it('50 simultaneous writes produce 50 intact records in call order', async () => {
    const log = createAuditLog({ filePath: file, key });
    await Promise.all(Array.from({ length: 50 }, (_, i) => log.write(input(i))));

    const records = await readRecords();
    expect(records.map((r) => r.requestId)).toEqual(Array.from({ length: 50 }, (_, i) => `req-${i}`));
    for (const r of records) {
      expect(decrypt(r.encryptedOriginalMessage, key, r.requestId)).toBe(ORIGINAL);
    }
  });

  it('never has more than one append in flight', async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const order: string[] = [];
    const log = createAuditLog({
      filePath: file,
      key,
      appendFile: async (_p, data) => {
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((r) => setTimeout(r, 5));
        order.push((JSON.parse(data) as AuditRecord).requestId);
        inFlight--;
      },
    });
    await Promise.all([1, 2, 3, 4, 5].map((n) => log.write(input(n))));
    expect(maxInFlight).toBe(1);
    expect(order).toEqual(['req-1', 'req-2', 'req-3', 'req-4', 'req-5']);
  });
});

describe('write failures', () => {
  it('rejects with a generic AuditWriteError that leaks no path or content', async () => {
    const log = createAuditLog({
      filePath: file,
      key,
      appendFile: async () => {
        throw Object.assign(new Error(`ENOSPC writing ${file}: ${ORIGINAL}`), { code: 'ENOSPC' });
      },
    });
    const err = await log.write(input()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuditWriteError);
    const e = err as AuditWriteError;
    expect(e.code).toBe('ENOSPC');
    expect(e.message).toBe('Failed to persist audit record');
    expect(JSON.stringify(e) + e.message + String(e.stack?.split('\n')[0])).not.toContain('john@example.com');
    expect(e.message).not.toContain(dir);
  });

  it('keeps working after a failed write (queue is not poisoned)', async () => {
    let calls = 0;
    const written: string[] = [];
    const log = createAuditLog({
      filePath: file,
      key,
      appendFile: async (_p, data) => {
        if (++calls === 2) throw new Error('disk hiccup');
        written.push((JSON.parse(data) as AuditRecord).requestId);
      },
    });
    const results = await Promise.allSettled([log.write(input(1)), log.write(input(2)), log.write(input(3))]);
    expect(results.map((r) => r.status)).toEqual(['fulfilled', 'rejected', 'fulfilled']);
    expect(written).toEqual(['req-1', 'req-3']);
  });

  it('reports a real filesystem failure (parent path is a file)', async () => {
    const blocker = join(dir, 'blocker');
    await writeFile(blocker, 'x');
    const log = createAuditLog({ filePath: join(blocker, 'audit.jsonl'), key });
    await expect(log.write(input())).rejects.toBeInstanceOf(AuditWriteError);
  });
});

describe('repository hygiene', () => {
  it('ignores .env, audit data and node_modules in .gitignore', async () => {
    const lines = (await readFile(new URL('../.gitignore', import.meta.url), 'utf8')).split('\n').map((l) => l.trim());
    for (const entry of ['.env', 'data/', 'node_modules/']) expect(lines).toContain(entry);
  });

  it('.env.example contains no real key', async () => {
    const text = await readFile(new URL('../.env.example', import.meta.url), 'utf8');
    expect(text).toMatch(/^AUDIT_ENCRYPTION_KEY=$/m);
  });
});
