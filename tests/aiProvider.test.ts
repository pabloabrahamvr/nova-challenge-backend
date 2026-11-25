import { describe, expect, it } from 'vitest';
import { ProviderError, createMockProvider, withTimeout } from '../src/aiProvider.js';

describe('mock provider', () => {
  it('returns "Generated Answer" after the configured delay', async () => {
    const provider = createMockProvider({ delayMs: 60, failFirstN: 0 });
    const start = performance.now();
    await expect(provider.generate('hi')).resolves.toBe('Generated Answer');
    expect(performance.now() - start).toBeGreaterThanOrEqual(50);
  });

  it('fails the first N calls (after the delay), then succeeds', async () => {
    const provider = createMockProvider({ delayMs: 0, failFirstN: 2 });
    await expect(provider.generate('x')).rejects.toBeInstanceOf(ProviderError);
    await expect(provider.generate('x')).rejects.toBeInstanceOf(ProviderError);
    await expect(provider.generate('x')).resolves.toBe('Generated Answer');
  });

  it('simulated failures also take the full delay', async () => {
    const provider = createMockProvider({ delayMs: 60, failFirstN: 1 });
    const start = performance.now();
    await provider.generate('x').catch(() => undefined);
    expect(performance.now() - start).toBeGreaterThanOrEqual(50);
  });
});

describe('withTimeout', () => {
  it('rejects with ProviderError when the promise is too slow', async () => {
    await expect(withTimeout(new Promise(() => undefined), 20)).rejects.toBeInstanceOf(ProviderError);
  });
  it('passes through results and errors', async () => {
    await expect(withTimeout(Promise.resolve(1), 1000)).resolves.toBe(1);
    await expect(withTimeout(Promise.reject(new Error('x')), 1000)).rejects.toThrow('x');
  });
});
