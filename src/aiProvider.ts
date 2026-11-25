/**
 * Mock external AI provider.
 *
 * The only message input is the already-redacted text: the original is never passed here.
 * Failure simulation is deterministic and env-driven (failFirstN), never request-driven,
 * so clients cannot trigger it. Timeouts are enforced by the circuit breaker, which passes an
 * AbortSignal so abandoned calls stop instead of lingering.
 */

export class ProviderError extends Error {
  constructor(message = 'AI provider failed') {
    super(message);
    this.name = 'ProviderError';
  }
}

export interface AiProvider {
  generate(sanitizedMessage: string, signal?: AbortSignal): Promise<string>;
}

export interface MockProviderOptions {
  delayMs: number;
  /** The first N calls fail (after the delay), then calls succeed. 0 disables simulation. */
  failFirstN: number;
}

export function createMockProvider({ delayMs, failFirstN }: MockProviderOptions): AiProvider {
  let calls = 0;
  return {
    async generate(_sanitizedMessage, signal) {
      const shouldFail = ++calls <= failFirstN;
      await new Promise<void>((resolve, reject) => {
        if (signal?.aborted) return reject(new ProviderError('AI provider call aborted'));
        const timer = setTimeout(() => {
          signal?.removeEventListener('abort', onAbort);
          resolve();
        }, delayMs);
        const onAbort = (): void => {
          clearTimeout(timer);
          reject(new ProviderError('AI provider call aborted'));
        };
        signal?.addEventListener('abort', onAbort, { once: true });
      });
      if (shouldFail) throw new ProviderError('Simulated provider failure');
      return 'Generated Answer';
    },
  };
}
