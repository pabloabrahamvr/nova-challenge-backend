import { appendFile as fsAppendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { encrypt, type EncryptedPayload } from './crypto.js';

/**
 * Mock audit database: one JSON object per line (JSON Lines) in a local file.
 *
 * Concurrency: Node is single-threaded but appendFile is async, so overlapping
 * requests could interleave. Every write is chained onto a single promise queue,
 * so at most one append is in flight and records land in call order.
 * A failed write rejects only its own caller; the queue keeps working.
 *
 * Privacy: the original message is encrypted before it reaches the queue; only
 * the redacted message is stored in plaintext. Nothing here logs record contents.
 */

export type ProviderStatus = 'success' | 'failed' | 'breaker_open';

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
  /** Injectable for deterministic failure/ordering tests. */
  appendFile?: (path: string, data: string, options: { mode: number }) => Promise<void>;
}

/** Generic on purpose: no path, no message content, no underlying error text. */
export class AuditWriteError extends Error {
  readonly code: string | undefined;
  constructor(code?: string) {
    super('Failed to persist audit record');
    this.name = 'AuditWriteError';
    this.code = code;
  }
}

export function createAuditLog(options: AuditLogOptions): AuditLog {
  const { filePath, key } = options;
  const now = options.now ?? (() => new Date());
  const append = options.appendFile ?? ((p, d, o) => fsAppendFile(p, d, o));
  let tail: Promise<void> = Promise.resolve();
  let dirReady = false;

  const persist = async (line: string): Promise<void> => {
    try {
      if (!dirReady) {
        await mkdir(dirname(filePath), { recursive: true, mode: 0o700 });
        dirReady = true;
      }
      await append(filePath, line, { mode: 0o600 });
    } catch (err) {
      // Keep only the errno code (e.g. ENOSPC) for diagnostics.
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      throw new AuditWriteError(typeof code === 'string' ? code : undefined);
    }
  };

  return {
    write(input) {
      const record: AuditRecord = {
        requestId: input.requestId,
        userId: input.userId,
        timestamp: now().toISOString(),
        providerStatus: input.providerStatus,
        redactedMessage: input.redactedMessage,
        // requestId as AAD ties the ciphertext to this record.
        encryptedOriginalMessage: encrypt(input.originalMessage, key, input.requestId),
      };
      const line = `${JSON.stringify(record)}\n`; // JSON escapes newlines, so one record = one line

      const result = tail.then(() => persist(line));
      tail = result.catch(() => undefined); // a failure must not poison later writes
      return result;
    },
  };
}
