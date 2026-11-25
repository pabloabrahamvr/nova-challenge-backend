import { describe, expect, it } from 'vitest';
import { BreakerOpenError, CircuitBreaker } from '../src/circuitBreaker.js';

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
