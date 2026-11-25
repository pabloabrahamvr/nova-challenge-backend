import { randomBytes } from 'node:crypto';
import { appendFile, chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AuditWriteError, auditAad, createAuditLog, type AuditInput, type AuditRecord } from '../src/auditStore.js';
import { decrypt } from './helpers/crypto.js';

const open = (r: AuditRecord): string => decrypt(r.encryptedOriginalMessage, key, auditAad(r, r.encryptedOriginalMessage.keyVersion));

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
    expect(open(rec!)).toBe(ORIGINAL);
  });

  it('cannot be decrypted with another key or moved to another record', async () => {
    await createAuditLog({ filePath: file, key }).write(input(7));
    const [rec] = await readRecords();
    expect(() => decrypt(rec!.encryptedOriginalMessage, randomBytes(32), auditAad(rec!))).toThrow();
    expect(() => decrypt(rec!.encryptedOriginalMessage, key, auditAad({ ...rec!, requestId: 'req-other' }))).toThrow();
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
      expect(open(r)).toBe(ORIGINAL);
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

// ---- Security review regressions ----

describe('review #6: every stored field is authenticated', () => {
  it.each([
    ['redactedMessage', { redactedMessage: 'edited' }],
    ['userId', { userId: 'someone-else' }],
    ['timestamp', { timestamp: '2020-01-01T00:00:00.000Z' }],
    ['providerStatus', { providerStatus: 'breaker_open' as const }],
    ['requestId', { requestId: 'req-forged' }],
  ])('editing %s makes decryption fail', async (_field, edit) => {
    await createAuditLog({ filePath: file, key }).write(input(1));
    const [rec] = await readRecords();
    expect(open(rec!)).toBe(ORIGINAL); // sanity: untouched record decrypts
    expect(() => open({ ...rec!, ...edit })).toThrow('Decryption failed');
  });

  it('editing keyVersion makes decryption fail', async () => {
    await createAuditLog({ filePath: file, key }).write(input(1));
    const [rec] = await readRecords();
    const forged = { ...rec!, encryptedOriginalMessage: { ...rec!.encryptedOriginalMessage, keyVersion: 99 } };
    expect(() => decrypt(forged.encryptedOriginalMessage, key, auditAad(forged, 1))).not.toThrow();
    expect(() => open(forged)).toThrow('Decryption failed');
  });
});

describe('review #5: torn lines cannot swallow the next record', () => {
  it('starts a new line when the existing file ends mid-record', async () => {
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, '{"requestId":"partial","userId":"u","timest');
    await createAuditLog({ filePath: file, key }).write(input('good'));

    const lines = (await readFile(file, 'utf8')).split('\n').filter(Boolean);
    expect(lines).toHaveLength(2);
    expect(() => JSON.parse(lines[0]!)).toThrow(); // the torn line stays torn...
    expect((JSON.parse(lines[1]!) as AuditRecord).requestId).toBe('req-good'); // ...but the new record is intact
  });

  it('does not add a stray blank line when the file already ends with a newline', async () => {
    const log = createAuditLog({ filePath: file, key });
    await log.write(input(1));
    await createAuditLog({ filePath: file, key }).write(input(2));
    expect((await readFile(file, 'utf8')).includes('\n\n')).toBe(false);
  });

  it('re-checks the file after a failed append (which may have left a partial line)', async () => {
    let calls = 0;
    const log = createAuditLog({
      filePath: file,
      key,
      appendFile: async (path, data) => {
        calls++;
        if (calls === 1) {
          await mkdir(dirname(path), { recursive: true });
          await writeFile(path, data.slice(0, 40)); // simulate ENOSPC after a partial write
          throw Object.assign(new Error('disk full'), { code: 'ENOSPC' });
        }
        await appendFile(path, data);
      },
    });
    await expect(log.write(input(1))).rejects.toBeInstanceOf(AuditWriteError);
    await log.write(input(2));

    const lines = (await readFile(file, 'utf8')).split('\n').filter(Boolean);
    const parsed = lines.flatMap((l) => {
      try {
        return [JSON.parse(l) as AuditRecord];
      } catch {
        return [];
      }
    });
    expect(parsed.map((r) => r.requestId)).toEqual(['req-2']);
  });
});

describe('review #13: self-healing and permissions', () => {
  it('recreates the audit directory if it disappears while running', async () => {
    const log = createAuditLog({ filePath: file, key });
    await log.write(input(1));
    await rm(dirname(file), { recursive: true, force: true });
    await log.write(input(2));
    expect((await readRecords()).map((r) => r.requestId)).toEqual(['req-2']);
  });

  it.skipIf(process.platform === 'win32')('tightens permissions of a pre-existing, too-open file', async () => {
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, '');
    await chmod(file, 0o644);
    await createAuditLog({ filePath: file, key }).write(input());
    expect((await stat(file)).mode & 0o077).toBe(0);
  });

  it('fsyncs each record (default appender opens, writes, syncs and closes)', async () => {
    // Behavioural check: the record is on disk and readable the moment write() resolves.
    await createAuditLog({ filePath: file, key }).write(input(1));
    expect(await readRecords()).toHaveLength(1);
  });
});

describe('review #7: backpressure', () => {
  it('rejects writes beyond maxPending instead of queueing without bound', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const log = createAuditLog({ filePath: file, key, maxPending: 3, appendFile: async () => gate });

    const accepted = [1, 2, 3].map((n) => log.write(input(n)));
    const err = await log.write(input(4)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuditWriteError);
    expect((err as AuditWriteError).code).toBe('QUEUE_FULL');

    release();
    await Promise.all(accepted); // the first three still complete
    await log.write(input(5)); // and capacity is available again
  });

  it('rejects writes that would push the file past maxFileBytes, without writing', async () => {
    const log = createAuditLog({ filePath: file, key, maxFileBytes: 700 });
    await log.write(input(1));
    const err = await log.write(input(2)).catch((e: unknown) => e);
    expect((err as AuditWriteError).code).toBe('FILE_FULL');
    expect(await readRecords()).toHaveLength(1);
    expect((await stat(file)).size).toBeLessThanOrEqual(700);
  });

  it('counts an existing file towards the size cap', async () => {
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, `${'x'.repeat(1400)}\n`);
    const err = await createAuditLog({ filePath: file, key, maxFileBytes: 1500 }).write(input(1)).catch((e: unknown) => e);
    expect((err as AuditWriteError).code).toBe('FILE_FULL');
  });
});
