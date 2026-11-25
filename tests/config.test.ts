import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../src/config.js';

const KEY = randomBytes(32).toString('base64');

describe('loadConfig', () => {
  it('applies the documented defaults', () => {
    const c = loadConfig({ AUDIT_ENCRYPTION_KEY: KEY });
    expect(c).toMatchObject({
      port: 3000,
      providerDelayMs: 2000,
      providerTimeoutMs: 5000,
      breakerFailureThreshold: 3,
      breakerCooldownMs: 10_000,
      providerFailFirstN: 0,
    });
    expect(c.encryptionKey).toHaveLength(32);
  });

  it('fails fast without a key, naming the variable but no value', () => {
    expect(() => loadConfig({})).toThrow(ConfigError);
    expect(() => loadConfig({})).toThrow(/AUDIT_ENCRYPTION_KEY/);
  });

  it('rejects a malformed key without echoing it', () => {
    const bad = randomBytes(16).toString('base64');
    expect(() => loadConfig({ AUDIT_ENCRYPTION_KEY: bad })).toThrow(ConfigError);
    try {
      loadConfig({ AUDIT_ENCRYPTION_KEY: bad });
    } catch (e) {
      expect((e as Error).message).not.toContain(bad);
    }
  });

  it('rejects invalid numbers, naming only the variable', () => {
    expect(() => loadConfig({ AUDIT_ENCRYPTION_KEY: KEY, BREAKER_FAILURE_THRESHOLD: 'abc' })).toThrow(
      /BREAKER_FAILURE_THRESHOLD/,
    );
    expect(() => loadConfig({ AUDIT_ENCRYPTION_KEY: KEY, BREAKER_FAILURE_THRESHOLD: '0' })).toThrow(ConfigError);
  });

  it('allows failure simulation outside production', () => {
    expect(loadConfig({ AUDIT_ENCRYPTION_KEY: KEY, PROVIDER_FAIL_FIRST_N: '3' }).providerFailFirstN).toBe(3);
  });

  it('refuses failure simulation in production', () => {
    expect(() => loadConfig({ AUDIT_ENCRYPTION_KEY: KEY, NODE_ENV: 'production', PROVIDER_FAIL_FIRST_N: '3' })).toThrow(
      /production/,
    );
  });
});

// ---- Security review regressions ----
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll } from 'vitest';

describe('review #11: blank or malformed numbers never become 0', () => {
  const base = { AUDIT_ENCRYPTION_KEY: KEY };

  it.each([
    ['BREAKER_COOLDOWN_MS', 'breakerCooldownMs', 10_000],
    ['PROVIDER_DELAY_MS', 'providerDelayMs', 2000],
    ['PROVIDER_TIMEOUT_MS', 'providerTimeoutMs', 5000],
    ['BREAKER_FAILURE_THRESHOLD', 'breakerFailureThreshold', 3],
    ['PORT', 'port', 3000],
    ['RATE_LIMIT_MAX', 'rateLimitMax', 300],
  ] as const)('%s= (empty) and whitespace fall back to the default %s', (name, field, def) => {
    expect(loadConfig({ ...base, [name]: '' })[field]).toBe(def);
    expect(loadConfig({ ...base, [name]: '   ' })[field]).toBe(def);
  });

  it.each([
    ['cooldown of 0 (would disable the breaker)', { BREAKER_COOLDOWN_MS: '0' }],
    ['port 0', { PORT: '0' }],
    ['port above 65535', { PORT: '70000' }],
    ['negative', { PROVIDER_DELAY_MS: '-1' }],
    ['exponent notation', { PROVIDER_DELAY_MS: '1e3' }],
    ['hex', { PROVIDER_DELAY_MS: '0x10' }],
    ['decimal', { PROVIDER_DELAY_MS: '1.5' }],
    ['trailing text', { PROVIDER_DELAY_MS: '10ms' }],
    ['timeout of 0', { PROVIDER_TIMEOUT_MS: '0' }],
    ['concurrency of 0', { PROVIDER_MAX_CONCURRENCY: '0' }],
    ['absurdly large', { PROVIDER_DELAY_MS: '99999999999999' }],
  ])('rejects %s', (_label, extra) => {
    const name = Object.keys(extra)[0]!;
    expect(() => loadConfig({ ...base, ...extra })).toThrow(ConfigError);
    expect(() => loadConfig({ ...base, ...extra })).toThrow(new RegExp(name));
  });

  it('accepts RATE_LIMIT_MAX=0 (explicitly disabled)', () => {
    expect(loadConfig({ ...base, RATE_LIMIT_MAX: '0' }).rateLimitMax).toBe(0);
  });

  it('rejects a low-entropy key', () => {
    expect(() => loadConfig({ AUDIT_ENCRYPTION_KEY: Buffer.alloc(32).toString('base64') })).toThrow(ConfigError);
  });
});

describe('review #9: key from a secret file (Docker/K8s secrets)', () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'cfg-test-'));
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('reads the key from AUDIT_ENCRYPTION_KEY_FILE, ignoring a trailing newline', async () => {
    const file = join(dir, 'key');
    await writeFile(file, `${KEY}\n`);
    const c = loadConfig({ AUDIT_ENCRYPTION_KEY_FILE: file });
    expect(c.encryptionKey.toString('base64')).toBe(KEY);
  });

  it('rejects setting both the inline key and the file', async () => {
    const file = join(dir, 'key2');
    await writeFile(file, KEY);
    expect(() => loadConfig({ AUDIT_ENCRYPTION_KEY: KEY, AUDIT_ENCRYPTION_KEY_FILE: file })).toThrow(/only one/);
  });

  it('reports an unreadable file without leaking its path', () => {
    const missing = join(dir, 'does-not-exist');
    try {
      loadConfig({ AUDIT_ENCRYPTION_KEY_FILE: missing });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigError);
      expect((e as Error).message).not.toContain(missing);
    }
  });

  it('rejects a malformed key inside the file without echoing it', async () => {
    const file = join(dir, 'bad');
    const bad = randomBytes(16).toString('base64');
    await writeFile(file, bad);
    try {
      loadConfig({ AUDIT_ENCRYPTION_KEY_FILE: file });
      expect.unreachable();
    } catch (e) {
      expect((e as Error).message).not.toContain(bad);
    }
  });
});
