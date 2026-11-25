import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { loadKey, CryptoError } from './crypto.js';

/** Messages list variable NAMES only, never values (they may be secrets). */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

/**
 * Optional integer env var. Unset, empty or whitespace-only means "use the default" (never 0: an empty
 * `BREAKER_COOLDOWN_MS=` must not silently disable the breaker). Anything else must be plain digits.
 */
const intVar = (def: number, min: number, max = 2_000_000_000) =>
  z
    .string()
    .optional()
    .transform((raw, ctx) => {
      const v = raw?.trim();
      if (v === undefined || v === '') return def;
      const n = /^\d{1,10}$/.test(v) ? Number(v) : NaN;
      if (!Number.isInteger(n) || n < min || n > max) {
        ctx.addIssue({ code: 'custom', message: 'invalid integer' });
        return z.NEVER;
      }
      return n;
    });

const schema = z.object({
  NODE_ENV: z.string().optional().default('development'),
  PORT: intVar(3000, 1, 65535),
  AUDIT_ENCRYPTION_KEY: z.string().optional(),
  AUDIT_ENCRYPTION_KEY_FILE: z.string().optional(),
  AUDIT_FILE_PATH: z.string().optional().default('data/audit.jsonl'),
  AUDIT_MAX_FILE_BYTES: intVar(100 * 1024 * 1024, 1024),
  PROVIDER_DELAY_MS: intVar(2000, 0),
  PROVIDER_TIMEOUT_MS: intVar(5000, 1),
  PROVIDER_MAX_CONCURRENCY: intVar(50, 1),
  BREAKER_FAILURE_THRESHOLD: intVar(3, 1),
  BREAKER_COOLDOWN_MS: intVar(10_000, 1),
  PROVIDER_FAIL_FIRST_N: intVar(0, 0),
  RATE_LIMIT_MAX: intVar(300, 0),
  RATE_LIMIT_WINDOW_MS: intVar(60_000, 1),
});

export interface Config {
  port: number;
  auditFilePath: string;
  auditMaxFileBytes: number;
  encryptionKey: Buffer;
  providerDelayMs: number;
  providerTimeoutMs: number;
  providerMaxConcurrency: number;
  breakerFailureThreshold: number;
  breakerCooldownMs: number;
  providerFailFirstN: number;
  /** 0 disables rate limiting. */
  rateLimitMax: number;
  rateLimitWindowMs: number;
}

/** Key from AUDIT_ENCRYPTION_KEY, or from the file named by AUDIT_ENCRYPTION_KEY_FILE (Docker/K8s secret). */
function readKeySource(e: z.output<typeof schema>): string {
  const inline = e.AUDIT_ENCRYPTION_KEY?.trim();
  const file = e.AUDIT_ENCRYPTION_KEY_FILE?.trim();
  if (inline && file) throw new ConfigError('Set only one of AUDIT_ENCRYPTION_KEY and AUDIT_ENCRYPTION_KEY_FILE');
  if (file) {
    try {
      return readFileSync(file, 'utf8').trim(); // startup only, so a synchronous read is fine
    } catch {
      throw new ConfigError('Cannot read the file named by AUDIT_ENCRYPTION_KEY_FILE');
    }
  }
  if (inline) return inline;
  throw new ConfigError('AUDIT_ENCRYPTION_KEY (or AUDIT_ENCRYPTION_KEY_FILE) is required');
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const names = [...new Set(parsed.error.issues.map((i) => String(i.path[0] ?? 'env')))];
    throw new ConfigError(`Invalid configuration: ${names.join(', ')}`);
  }
  const e = parsed.data;

  let encryptionKey: Buffer;
  const source = readKeySource(e);
  try {
    encryptionKey = loadKey(source);
  } catch (err) {
    throw new ConfigError(err instanceof CryptoError ? err.message : 'Invalid configuration: AUDIT_ENCRYPTION_KEY');
  }

  if (e.NODE_ENV === 'production' && e.PROVIDER_FAIL_FIRST_N > 0) {
    throw new ConfigError('PROVIDER_FAIL_FIRST_N must be 0 when NODE_ENV=production');
  }

  return {
    port: e.PORT,
    auditFilePath: e.AUDIT_FILE_PATH.trim() || 'data/audit.jsonl',
    auditMaxFileBytes: e.AUDIT_MAX_FILE_BYTES,
    encryptionKey,
    providerDelayMs: e.PROVIDER_DELAY_MS,
    providerTimeoutMs: e.PROVIDER_TIMEOUT_MS,
    providerMaxConcurrency: e.PROVIDER_MAX_CONCURRENCY,
    breakerFailureThreshold: e.BREAKER_FAILURE_THRESHOLD,
    breakerCooldownMs: e.BREAKER_COOLDOWN_MS,
    providerFailFirstN: e.PROVIDER_FAIL_FIRST_N,
    rateLimitMax: e.RATE_LIMIT_MAX,
    rateLimitWindowMs: e.RATE_LIMIT_WINDOW_MS,
  };
}
