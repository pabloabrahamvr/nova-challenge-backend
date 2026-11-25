import { describe, expect, it } from 'vitest';
import { ProviderError, createMockProvider } from '../src/aiProvider.js';

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

describe('abort signal', () => {
  it('stops waiting and rejects when the signal is aborted', async () => {
    const provider = createMockProvider({ delayMs: 10_000, failFirstN: 0 });
    const controller = new AbortController();
    const pending = provider.generate('x', controller.signal);
    setTimeout(() => controller.abort(), 10);
    const start = performance.now();
    await expect(pending).rejects.toBeInstanceOf(ProviderError);
    expect(performance.now() - start).toBeLessThan(1000);
  });

  it('rejects immediately for an already-aborted signal', async () => {
    const provider = createMockProvider({ delayMs: 10_000, failFirstN: 0 });
    await expect(provider.generate('x', AbortSignal.abort())).rejects.toBeInstanceOf(ProviderError);
  });
});
