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
 * - Bulkhead: failures only count when calls settle, so a burst can put many calls in flight before the
 *   breaker trips. maxConcurrent caps calls in flight; extra callers get BreakerBusyError immediately
 *   (not a failure; the probe is exempt).
 * - Watchdog: callTimeoutMs aborts a call (via AbortSignal) and counts it as a failure, so a provider
 *   that never answers cannot leave the breaker stuck in HALF_OPEN or hold resources forever.
 * - The default clock is monotonic (performance.now), so wall-clock jumps cannot shorten or extend OPEN.
 * - Only errors thrown by fn (or its timeout) count as failures. Callers must validate client input
 *   BEFORE calling execute(), so client mistakes never reach the breaker.
 */

export type BreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export class BreakerOpenError extends Error {
  constructor() {
    super('Circuit breaker is open');
    this.name = 'BreakerOpenError';
  }
}

export class BreakerBusyError extends Error {
  constructor() {
    super('Too many provider calls in flight');
    this.name = 'BreakerBusyError';
  }
}

export class CallTimeoutError extends Error {
  constructor() {
    super('Provider call timed out');
    this.name = 'CallTimeoutError';
  }
}

export interface CircuitBreakerOptions {
  failureThreshold: number;
  cooldownMs: number;
  /** Max concurrent calls to fn. Unlimited when omitted. */
  maxConcurrent?: number;
  /** Abort and fail a call that takes longer than this. No timeout when omitted. */
  callTimeoutMs?: number;
  /** Injectable clock (milliseconds, monotonic) for deterministic tests. */
  now?: () => number;
}

export class CircuitBreaker {
  private current: BreakerState = 'CLOSED';
  private consecutiveFailures = 0;
  private openedAt = 0;
  private probeInFlight = false;
  private epoch = 0;
  private active = 0;
  private readonly now: () => number;

  constructor(private readonly options: CircuitBreakerOptions) {
    this.now = options.now ?? (() => performance.now());
  }

  get state(): BreakerState {
    return this.current;
  }

  /** Calls to fn currently in flight. */
  get inFlight(): number {
    return this.active;
  }

  /** Whole seconds until a probe is allowed (for Retry-After). At least 1. */
  retryAfterSeconds(): number {
    if (this.current !== 'OPEN') return 1;
    const remaining = this.options.cooldownMs - (this.now() - this.openedAt);
    return Math.max(1, Math.ceil(remaining / 1000));
  }

  async execute<T>(fn: (signal: AbortSignal) => Promise<T>): Promise<T> {
    if (this.current === 'OPEN' && this.now() - this.openedAt >= this.options.cooldownMs) {
      this.transition('HALF_OPEN');
    }
    if (this.current === 'OPEN') throw new BreakerOpenError();

    if (this.current === 'HALF_OPEN') {
      if (this.probeInFlight) throw new BreakerOpenError();
      this.probeInFlight = true; // synchronous with the check above: single probe
    } else if (this.options.maxConcurrent !== undefined && this.active >= this.options.maxConcurrent) {
      throw new BreakerBusyError();
    }

    const epoch = this.epoch;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    this.active += 1;

    let result: T;
    try {
      const run = fn(controller.signal);
      if (this.options.callTimeoutMs === undefined) {
        result = await run;
      } else {
        const timeout = new Promise<never>((_resolve, reject) => {
          timer = setTimeout(() => {
            controller.abort();
            reject(new CallTimeoutError());
          }, this.options.callTimeoutMs);
        });
        result = await Promise.race([run, timeout]);
      }
    } catch (err) {
      this.onFailure(epoch);
      throw err;
    } finally {
      clearTimeout(timer);
      this.active -= 1;
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
