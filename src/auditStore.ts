import { chmod, mkdir, open, stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { encrypt, KEY_VERSION, type EncryptedPayload } from './crypto.js';

/**
 * Mock audit database: one JSON object per line (JSON Lines) in a local file.
 *
 * Concurrency: Node is single-threaded but file I/O is async, so overlapping requests could interleave.
 * Every write is chained onto a single promise queue: at most one append is in flight and records land in
 * call order. A failed write rejects only its own caller; the queue keeps working. This protects ONE process.
 * Several processes appending to the same file are not coordinated (use a real datastore for that).
 *
 * Crash / partial-write safety: a failed or interrupted append can leave a line without its trailing
 * newline. The store checks the file's last byte before its first write, and again after any failed write,
 * and starts a new line if needed, so a torn line can never swallow the next good record.
 * Readers should still skip lines that fail to parse.
 *
 * Durability: each record is fsync'ed before the request is acknowledged.
 *
 * Backpressure: the queue is bounded (maxPending) and the file is capped (maxFileBytes). Past either limit
 * writes are rejected with AuditWriteError('QUEUE_FULL' | 'FILE_FULL') instead of exhausting memory or disk.
 * There is no rotation: operators must archive the file.
 *
 * Privacy: the original message is encrypted before it reaches the queue; only the redacted message is
 * stored in plaintext. Nothing here logs record contents.
 *
 * Integrity: every non-ciphertext field is bound into the GCM AAD (auditAad), so anyone holding the key can
 * detect edits to userId, timestamp, providerStatus or redactedMessage, and records cannot be swapped.
 */

export type ProviderStatus = 'success' | 'failed' | 'breaker_open' | 'overloaded';

export interface AuditRecord {
  requestId: string;
  userId: string;
  timestamp: string; // ISO 8601
  providerStatus: ProviderStatus;
  redactedMessage: string;
  encryptedOriginalMessage: EncryptedPayload;
}

/** What callers hand over. Contains the plaintext original, which never leaves this module unencrypted. */
export interface AuditInput {
  requestId: string;
  userId: string;
  providerStatus: ProviderStatus;
  originalMessage: string;
  redactedMessage: string;
}

export interface AuditLog {
  write(input: AuditInput): Promise<void>;
}

export interface AuditLogOptions {
  filePath: string;
  key: Buffer;
  now?: () => Date;
  /** Max writes waiting or in flight. Default 1000. */
  maxPending?: number;
  /** Max audit file size in bytes. Default 100 MiB. */
  maxFileBytes?: number;
  /** Injectable for deterministic failure/ordering tests. Default: append + fsync. */
  appendFile?: (path: string, data: string, options: { mode: number }) => Promise<void>;
}

export const DEFAULT_MAX_PENDING = 1000;
export const DEFAULT_MAX_FILE_BYTES = 100 * 1024 * 1024;

/** Generic on purpose: no path, no message content, no underlying error text. */
export class AuditWriteError extends Error {
  readonly code: string | undefined;
  constructor(code?: string) {
    super('Failed to persist audit record');
    this.name = 'AuditWriteError';
    this.code = code;
  }
}

/** The additional authenticated data for a record: every field except the ciphertext itself. */
export function auditAad(
  r: Pick<AuditRecord, 'requestId' | 'userId' | 'timestamp' | 'providerStatus' | 'redactedMessage'>,
  keyVersion: number = KEY_VERSION,
): string {
  // A JSON array has a fixed field order and unambiguous string boundaries.
  return JSON.stringify(['audit-v1', keyVersion, r.requestId, r.userId, r.timestamp, r.providerStatus, r.redactedMessage]);
}

async function appendDurably(path: string, data: string, { mode }: { mode: number }): Promise<void> {
  const handle = await open(path, 'a', mode);
  try {
    await handle.appendFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

const errnoCode = (err: unknown): string | undefined => {
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  return typeof code === 'string' ? code : undefined;
};

export function createAuditLog(options: AuditLogOptions): AuditLog {
  const { filePath, key } = options;
  const now = options.now ?? (() => new Date());
  const append = options.appendFile ?? appendDurably;
  const maxPending = options.maxPending ?? DEFAULT_MAX_PENDING;
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;

  let tail: Promise<void> = Promise.resolve();
  let pending = 0;
  // Learned lazily on the first write (and re-learned after a failure).
  let ready = false;
  let fileSize = 0;
  let needsNewline = false;
  let permissionsChecked = false;

  /** Inspect the existing file: its size, and whether it ends mid-line. */
  const inspectFile = async (): Promise<void> => {
    try {
      const { size } = await stat(filePath);
      fileSize = size;
      needsNewline = false;
      if (size > 0) {
        const handle = await open(filePath, 'r');
        try {
          const buf = Buffer.alloc(1);
          await handle.read(buf, 0, 1, size - 1);
          needsNewline = buf[0] !== 0x0a;
        } finally {
          await handle.close();
        }
      }
    } catch (err) {
      if (errnoCode(err) !== 'ENOENT') throw err;
      fileSize = 0;
      needsNewline = false;
    }
    ready = true;
  };

  const persist = async (line: string): Promise<void> => {
    try {
      if (!ready) await inspectFile();
      const data = (needsNewline ? '\n' : '') + line;
      const bytes = Buffer.byteLength(data);
      if (fileSize + bytes > maxFileBytes) throw new AuditWriteError('FILE_FULL');

      try {
        await append(filePath, data, { mode: 0o600 });
      } catch (err) {
        if (errnoCode(err) !== 'ENOENT') throw err;
        // Directory (or file) vanished since we last looked: recreate and retry once.
        await mkdir(dirname(filePath), { recursive: true, mode: 0o700 });
        await append(filePath, data, { mode: 0o600 });
      }
      fileSize += bytes;
      needsNewline = false;

      if (!permissionsChecked) {
        // `mode` only applies when a file is created; tighten a pre-existing file once.
        await chmod(filePath, 0o600).catch(() => undefined);
        permissionsChecked = true;
      }
    } catch (err) {
      if (err instanceof AuditWriteError) throw err;
      ready = false; // a failed append may have left a partial line: look again before the next write
      throw new AuditWriteError(errnoCode(err));
    }
  };

  return {
    write(input) {
      if (pending >= maxPending) return Promise.reject(new AuditWriteError('QUEUE_FULL'));

      let line: string;
      try {
        const base = {
          requestId: input.requestId,
          userId: input.userId,
          timestamp: now().toISOString(),
          providerStatus: input.providerStatus,
          redactedMessage: input.redactedMessage,
        };
        const record: AuditRecord = {
          ...base,
          encryptedOriginalMessage: encrypt(input.originalMessage, key, auditAad(base)),
        };
        line = `${JSON.stringify(record)}\n`; // JSON escapes newlines, so one record = one line
      } catch {
        return Promise.reject(new AuditWriteError('ENCRYPT'));
      }

      pending += 1;
      const result = tail.then(() => persist(line));
      tail = result.then(
        () => undefined,
        () => undefined, // a failure must not poison later writes
      );
      return result.finally(() => {
        pending -= 1;
      });
    },
  };
}
