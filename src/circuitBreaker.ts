/**
 * Circuit breaker around the AI provider.
 *
 *   CLOSED --N consecutive failures--> OPEN --cooldown elapsed--> HALF_OPEN
 *   HALF_OPEN --probe succeeds--> CLOSED        HALF_OPEN --probe fails--> OPEN (fresh cooldown)
 *
 * - While OPEN, execute() rejects immediately with BreakerOpenError and never calls fn.
 * - HALF_OPEN admits exactly ONE probe. The check "cooldown elapsed and no probe in flight" and the
 *   assignment of the probe slot happen in one synchronous step, so concurrent callers cannot both probe.
 * - Every state change bumps an epoch. A call that started under an older epoch (e.g. a slow request
 *   that began while CLOSED) is ignored when it settles, so a late success cannot close an OPEN breaker
 *   and a late failure cannot re-open or extend it.
 * - Only errors thrown by fn count as failures. Callers must validate client input BEFORE calling
 *   execute(), so client mistakes never reach the breaker.
 */

export type BreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export class BreakerOpenError extends Error {
  constructor() {
    super('Circuit breaker is open');
    this.name = 'BreakerOpenError';
  }
}

export interface CircuitBreakerOptions {
  failureThreshold: number;
  cooldownMs: number;
  /** Injectable clock for deterministic tests. */
  now?: () => number;
}

export class CircuitBreaker {
  private current: BreakerState = 'CLOSED';
  private consecutiveFailures = 0;
  private openedAt = 0;
  private probeInFlight = false;
  private epoch = 0;
  private readonly now: () => number;

  constructor(private readonly options: CircuitBreakerOptions) {
    this.now = options.now ?? Date.now;
  }

  get state(): BreakerState {
    return this.current;
  }

  /** Whole seconds until a probe is allowed (for Retry-After). At least 1. */
  retryAfterSeconds(): number {
    if (this.current !== 'OPEN') return 1;
    const remaining = this.options.cooldownMs - (this.now() - this.openedAt);
    return Math.max(1, Math.ceil(remaining / 1000));
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.current === 'OPEN' && this.now() - this.openedAt >= this.options.cooldownMs) {
      this.transition('HALF_OPEN');
    }
    if (this.current === 'OPEN') throw new BreakerOpenError();
    if (this.current === 'HALF_OPEN') {
      if (this.probeInFlight) throw new BreakerOpenError();
      this.probeInFlight = true; // synchronous with the check above: single probe
    }

    const epoch = this.epoch;
    let result: T;
    try {
      result = await fn();
    } catch (err) {
      this.onFailure(epoch);
      throw err;
    }
    this.onSuccess(epoch);
    return result;
  }

  private onSuccess(epoch: number): void {
    if (epoch !== this.epoch) return; // stale: started under a previous state
    if (this.current === 'HALF_OPEN') this.transition('CLOSED');
    else this.consecutiveFailures = 0;
  }

  private onFailure(epoch: number): void {
    if (epoch !== this.epoch) return;
    if (this.current === 'HALF_OPEN') {
      this.transition('OPEN');
      return;
    }
    this.consecutiveFailures += 1;
    if (this.consecutiveFailures >= this.options.failureThreshold) this.transition('OPEN');
  }

  private transition(next: BreakerState): void {
    this.current = next;
    this.epoch += 1;
    this.consecutiveFailures = 0;
    this.probeInFlight = false;
    if (next === 'OPEN') this.openedAt = this.now();
  }
}
