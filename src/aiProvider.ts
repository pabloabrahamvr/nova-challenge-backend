/**
 * Mock external AI provider.
 *
 * The only input is the already-redacted message: the original text is never passed here.
 * Failure simulation is deterministic and env-driven (failFirstN), never request-driven,
 * so clients cannot trigger it.
 */

export class ProviderError extends Error {
  constructor(message = 'AI provider failed') {
    super(message);
    this.name = 'ProviderError';
  }
}

export interface AiProvider {
  generate(sanitizedMessage: string): Promise<string>;
}

export interface MockProviderOptions {
  delayMs: number;
  /** The first N calls fail (after the delay), then calls succeed. 0 disables simulation. */
  failFirstN: number;
}

export function createMockProvider({ delayMs, failFirstN }: MockProviderOptions): AiProvider {
  let calls = 0;
  return {
    async generate(_sanitizedMessage) {
      const shouldFail = ++calls <= failFirstN;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      if (shouldFail) throw new ProviderError('Simulated provider failure');
      return 'Generated Answer';
    },
  };
}

/** Reject with ProviderError if the promise does not settle in time. Always clears its timer. */
export function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new ProviderError('AI provider timed out')), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}
