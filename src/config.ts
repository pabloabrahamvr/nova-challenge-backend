import { z } from 'zod';
import { loadKey, CryptoError } from './crypto.js';

/** Messages list variable NAMES only, never values (they may be secrets). */
export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

const int = (def: number, min: number) => z.coerce.number().int().min(min).default(def);

const schema = z.object({
  NODE_ENV: z.string().default('development'),
  PORT: int(3000, 0),
  AUDIT_ENCRYPTION_KEY: z.string().min(1),
  AUDIT_FILE_PATH: z.string().min(1).default('data/audit.jsonl'),
  PROVIDER_DELAY_MS: int(2000, 0),
  PROVIDER_TIMEOUT_MS: int(5000, 1),
  BREAKER_FAILURE_THRESHOLD: int(3, 1),
  BREAKER_COOLDOWN_MS: int(10_000, 0),
  PROVIDER_FAIL_FIRST_N: int(0, 0),
});

export interface Config {
  port: number;
  auditFilePath: string;
  encryptionKey: Buffer;
  providerDelayMs: number;
  providerTimeoutMs: number;
  breakerFailureThreshold: number;
  breakerCooldownMs: number;
  providerFailFirstN: number;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const names = [...new Set(parsed.error.issues.map((i) => String(i.path[0] ?? 'env')))];
    throw new ConfigError(`Invalid configuration: ${names.join(', ')}`);
  }
  const e = parsed.data;

  let encryptionKey: Buffer;
  try {
    encryptionKey = loadKey(e.AUDIT_ENCRYPTION_KEY);
  } catch (err) {
    throw new ConfigError(err instanceof CryptoError ? err.message : 'Invalid configuration: AUDIT_ENCRYPTION_KEY');
  }

  if (e.NODE_ENV === 'production' && e.PROVIDER_FAIL_FIRST_N > 0) {
    throw new ConfigError('PROVIDER_FAIL_FIRST_N must be 0 when NODE_ENV=production');
  }

  return {
    port: e.PORT,
    auditFilePath: e.AUDIT_FILE_PATH,
    encryptionKey,
    providerDelayMs: e.PROVIDER_DELAY_MS,
    providerTimeoutMs: e.PROVIDER_TIMEOUT_MS,
    breakerFailureThreshold: e.BREAKER_FAILURE_THRESHOLD,
    breakerCooldownMs: e.BREAKER_COOLDOWN_MS,
    providerFailFirstN: e.PROVIDER_FAIL_FIRST_N,
  };
}
