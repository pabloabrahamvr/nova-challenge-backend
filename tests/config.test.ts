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
