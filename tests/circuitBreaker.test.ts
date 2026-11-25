import { describe, expect, it, vi } from 'vitest';
import { BreakerBusyError, BreakerOpenError, CallTimeoutError, CircuitBreaker } from '../src/circuitBreaker.js';

const COOLDOWN = 10_000;

function setup(threshold = 3) {
  let t = 1_000;
  const breaker = new CircuitBreaker({ failureThreshold: threshold, cooldownMs: COOLDOWN, now: () => t });
  return { breaker, advance: (ms: number) => (t += ms) };
}

const ok = () => Promise.resolve('ok');
const fail = () => Promise.reject(new Error('boom'));

function deferred<T = string>() {
  let resolve!: (v: T) => void;
  let reject!: (e: Error) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

async function trip(breaker: CircuitBreaker, n = 3) {
  for (let i = 0; i < n; i++) await breaker.execute(fail).catch(() => undefined);
}

describe('CLOSED', () => {
  it('passes results and errors through unchanged', async () => {
    const { breaker } = setup();
    await expect(breaker.execute(ok)).resolves.toBe('ok');
    await expect(breaker.execute(fail)).rejects.toThrow('boom');
  });

  it('stays closed below the threshold', async () => {
    const { breaker } = setup();
    await trip(breaker, 2);
    expect(breaker.state).toBe('CLOSED');
  });

  it('only CONSECUTIVE failures count: a success resets the counter', async () => {
    const { breaker } = setup();
    await trip(breaker, 2);
    await breaker.execute(ok);
    await trip(breaker, 2);
    expect(breaker.state).toBe('CLOSED');
    await trip(breaker, 1);
    expect(breaker.state).toBe('OPEN');
  });

  it('opens on the 3rd consecutive failure', async () => {
    const { breaker } = setup();
    await trip(breaker, 3);
    expect(breaker.state).toBe('OPEN');
  });
});

describe('OPEN', () => {
  it('rejects immediately without invoking fn', async () => {
    const { breaker } = setup();
    await trip(breaker);
    let calls = 0;
    const err = await breaker.execute(() => (calls++, ok())).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BreakerOpenError);
    expect(calls).toBe(0);
  });

  it('stays open until the cooldown has elapsed', async () => {
    const { breaker, advance } = setup();
    await trip(breaker);
    advance(COOLDOWN - 1);
    await expect(breaker.execute(ok)).rejects.toBeInstanceOf(BreakerOpenError);
    expect(breaker.state).toBe('OPEN');
  });

  it('reports a Retry-After of at least 1 second that shrinks with time', async () => {
    const { breaker, advance } = setup();
    await trip(breaker);
    expect(breaker.retryAfterSeconds()).toBe(10);
    advance(9_500);
    expect(breaker.retryAfterSeconds()).toBe(1);
  });
});

describe('HALF_OPEN recovery', () => {
  it('a successful probe closes the breaker and resets the counter', async () => {
    const { breaker, advance } = setup();
    await trip(breaker);
    advance(COOLDOWN);
    await expect(breaker.execute(ok)).resolves.toBe('ok');
    expect(breaker.state).toBe('CLOSED');
    await trip(breaker, 2); // needs a full 3 again
    expect(breaker.state).toBe('CLOSED');
  });

  it('a failed probe re-opens with a fresh cooldown', async () => {
    const { breaker, advance } = setup();
    await trip(breaker);
    advance(COOLDOWN);
    await breaker.execute(fail).catch(() => undefined);
    expect(breaker.state).toBe('OPEN');
    advance(COOLDOWN - 1);
    await expect(breaker.execute(ok)).rejects.toBeInstanceOf(BreakerOpenError);
    advance(1);
    await expect(breaker.execute(ok)).resolves.toBe('ok');
  });

  it('admits exactly one probe among concurrent callers', async () => {
    const { breaker, advance } = setup();
    await trip(breaker);
    advance(COOLDOWN);

    const probe = deferred();
    let calls = 0;
    const fn = () => (calls++, probe.promise);
    const results = Array.from({ length: 10 }, () => breaker.execute(fn).then(() => 'ran', () => 'rejected'));

    expect(calls).toBe(1);
    expect(breaker.state).toBe('HALF_OPEN');
    probe.resolve('ok');
    const settled = await Promise.all(results);
    expect(settled.filter((r) => r === 'ran')).toHaveLength(1);
    expect(settled.filter((r) => r === 'rejected')).toHaveLength(9);
    expect(breaker.state).toBe('CLOSED');
  });
});

describe('stale results (started under an older state)', () => {
  it('a late success from a pre-open call does not close an OPEN breaker', async () => {
    const { breaker } = setup();
    const slow = deferred();
    const slowCall = breaker.execute(() => slow.promise);
    await trip(breaker);
    expect(breaker.state).toBe('OPEN');
    slow.resolve('late');
    await slowCall;
    expect(breaker.state).toBe('OPEN');
  });

  it('a late failure from a pre-open call does not disturb a recovered breaker', async () => {
    const { breaker, advance } = setup();
    const slow = deferred();
    const slowCall = breaker.execute(() => slow.promise).catch(() => undefined);
    await trip(breaker);
    advance(COOLDOWN);
    await breaker.execute(ok); // probe closes the breaker
    slow.reject(new Error('late'));
    await slowCall;
    await trip(breaker, 2); // late failure was ignored, so two more are not enough
    expect(breaker.state).toBe('CLOSED');
  });
});

describe('threshold configuration', () => {
  it('honours a custom threshold', async () => {
    const { breaker } = setup(1);
    await trip(breaker, 1);
    expect(breaker.state).toBe('OPEN');
  });
});

// ---- Security review regressions ----

describe('review #8: concurrency cap (bulkhead)', () => {
  const limited = (max: number) => {
    let t = 1_000;
    const breaker = new CircuitBreaker({ failureThreshold: 3, cooldownMs: COOLDOWN, maxConcurrent: max, now: () => t });
    return { breaker, advance: (ms: number) => (t += ms) };
  };

  it('a burst of 20 against a hanging provider reaches it at most maxConcurrent times', async () => {
    const { breaker } = limited(3);
    let calls = 0;
    const hang = deferred();
    const results = Array.from({ length: 20 }, () =>
      breaker.execute(() => (calls++, hang.promise)).then(() => 'ran', (e: unknown) => (e instanceof BreakerBusyError ? 'busy' : 'other')),
    );
    expect(calls).toBe(3);
    expect(breaker.inFlight).toBe(3);
    hang.resolve('ok');
    const settled = await Promise.all(results);
    expect(settled.filter((r) => r === 'busy')).toHaveLength(17);
    expect(breaker.inFlight).toBe(0);
  });

  it('rejections for being busy are not failures and do not open the breaker', async () => {
    const { breaker } = limited(1);
    const hang = deferred();
    const first = breaker.execute(() => hang.promise);
    for (let i = 0; i < 10; i++) await expect(breaker.execute(ok)).rejects.toBeInstanceOf(BreakerBusyError);
    expect(breaker.state).toBe('CLOSED');
    hang.resolve('ok');
    await first;
  });

  it('frees capacity when calls fail, too', async () => {
    const { breaker } = limited(1);
    await breaker.execute(fail).catch(() => undefined);
    expect(breaker.inFlight).toBe(0);
    await expect(breaker.execute(ok)).resolves.toBe('ok');
  });
});

describe('review #15: per-call timeout and abort', () => {
  const timed = (callTimeoutMs: number) => {
    let t = 1_000;
    const breaker = new CircuitBreaker({ failureThreshold: 3, cooldownMs: COOLDOWN, callTimeoutMs, now: () => t });
    return { breaker, advance: (ms: number) => (t += ms) };
  };

  it('fails a call that never settles with CallTimeoutError and aborts its signal', async () => {
    const { breaker } = timed(20);
    let signal!: AbortSignal;
    const err = await breaker
      .execute((s) => ((signal = s), new Promise<string>(() => undefined)))
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CallTimeoutError);
    expect(signal.aborted).toBe(true);
    expect(breaker.inFlight).toBe(0);
  });

  it('timeouts count as failures and open the breaker', async () => {
    const { breaker } = timed(10);
    for (let i = 0; i < 3; i++) await breaker.execute(() => new Promise<string>(() => undefined)).catch(() => undefined);
    expect(breaker.state).toBe('OPEN');
  });

  it('a probe that never answers is released by the watchdog, so HALF_OPEN cannot get stuck', async () => {
    const { breaker, advance } = timed(20);
    await trip(breaker);
    advance(COOLDOWN);
    await breaker.execute(() => new Promise<string>(() => undefined)).catch(() => undefined);
    expect(breaker.state).toBe('OPEN'); // failed probe re-opened it
    advance(COOLDOWN);
    await expect(breaker.execute(ok)).resolves.toBe('ok'); // and a later probe is allowed
    expect(breaker.state).toBe('CLOSED');
  });

  it('does not leave timers running after a fast success', async () => {
    const { breaker } = timed(60_000);
    await breaker.execute(ok);
    // If the 60 s timer were still pending, vitest would keep the process alive; also nothing may throw later.
    expect(breaker.inFlight).toBe(0);
  });

  it('a late rejection from an abandoned call is not an unhandled rejection', async () => {
    const { breaker } = timed(10);
    const late = deferred();
    await breaker.execute(() => late.promise).catch(() => undefined);
    late.reject(new Error('late failure'));
    await new Promise((r) => setTimeout(r, 20)); // would crash the test run if unhandled
  });
});

describe('review #15: default clock is monotonic', () => {
  it('ignores wall-clock jumps backwards when deciding the cooldown', async () => {
    const breaker = new CircuitBreaker({ failureThreshold: 1, cooldownMs: 40 });
    await breaker.execute(fail).catch(() => undefined);
    expect(breaker.state).toBe('OPEN');

    const real = Date.now();
    const spy = vi.spyOn(Date, 'now').mockReturnValue(real - 3_600_000); // wall clock jumps back an hour
    try {
      await new Promise((r) => setTimeout(r, 60));
      await expect(breaker.execute(ok)).resolves.toBe('ok'); // cooldown measured on a monotonic clock
    } finally {
      spy.mockRestore();
    }
  });
});
