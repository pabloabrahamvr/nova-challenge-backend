import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app.js';
import { ProviderError, createMockProvider, type AiProvider } from '../src/aiProvider.js';
import { auditAad, createAuditLog, type AuditLog, type AuditRecord } from '../src/auditStore.js';
import { CircuitBreaker } from '../src/circuitBreaker.js';
import { decrypt } from './helpers/crypto.js';
import type { RateLimitOptions } from '../src/rateLimit.js';

const key = randomBytes(32);
const COOLDOWN = 10_000;
const EMAIL = 'john@example.com';
const CARD = '4111 1111 1111 1111';
const SSN = '123-45-6789';
const PII_MESSAGE = `Mail ${EMAIL}, card ${CARD}, ssn ${SSN}, alt 987654321`;
const PII_FRAGMENTS = [EMAIL, '4111', SSN, '987654321'];
const open = (r: AuditRecord): string => decrypt(r.encryptedOriginalMessage, key, auditAad(r));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface StubProvider extends AiProvider {
  received: string[];
  signals: Array<AbortSignal | undefined>;
}

/** Records what it was sent; behaviour is set by the test. */
function stubProvider(impl: (call: number) => Promise<string> = async () => 'Generated Answer'): StubProvider {
  const received: string[] = [];
  const signals: Array<AbortSignal | undefined> = [];
  return {
    received,
    signals,
    generate(message, signal) {
      received.push(message);
      signals.push(signal);
      return impl(received.length);
    },
  };
}

let dir: string;
let file: string;
let clock: number;
let logs: Record<string, unknown>[];

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'inquiry-test-'));
  file = join(dir, 'audit.jsonl');
  clock = 1_000;
  logs = [];
});
afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

function build(
  opts: { provider?: AiProvider; auditLog?: AuditLog; timeoutMs?: number; maxConcurrent?: number; rateLimit?: RateLimitOptions } = {},
) {
  const breaker = new CircuitBreaker({
    failureThreshold: 3,
    cooldownMs: COOLDOWN,
    callTimeoutMs: opts.timeoutMs ?? 5000,
    ...(opts.maxConcurrent !== undefined ? { maxConcurrent: opts.maxConcurrent } : {}),
    now: () => clock,
  });
  const provider = opts.provider ?? stubProvider();
  const auditLog = opts.auditLog ?? createAuditLog({ filePath: file, key });
  const app = createApp({
    auditLog,
    provider,
    breaker,
    ...(opts.rateLimit ? { rateLimit: opts.rateLimit } : {}),
    log: (entry) => logs.push(entry),
  });
  return { app, breaker, provider };
}

const post = (app: ReturnType<typeof build>['app'], body: unknown = { userId: 'user-123', message: 'hello' }) =>
  request(app).post('/secure-inquiry').send(body as object);

const records = async (): Promise<AuditRecord[]> => {
  try {
    return (await readFile(file, 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l) as AuditRecord);
  } catch {
    return [];
  }
};

const expectNoPii = (value: unknown) => {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const f of PII_FRAGMENTS) expect(text).not.toContain(f);
};

describe('success', () => {
  it('returns requestId, status and the generated answer', async () => {
    const { app } = build();
    const res = await post(app, { userId: 'user-123', message: 'Hello john@example.com' });
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ requestId: expect.stringMatching(UUID), status: 'success', answer: 'Generated Answer' });
  });

  it('answers only after the mock provider delay', async () => {
    const { app } = build({ provider: createMockProvider({ delayMs: 120, failFirstN: 0 }) });
    const start = performance.now();
    const res = await post(app);
    expect(res.status).toBe(200);
    expect(performance.now() - start).toBeGreaterThanOrEqual(100);
  });

  it('writes an audit record whose original decrypts with the key', async () => {
    const { app } = build();
    const message = 'Hello john@example.com';
    const res = await post(app, { userId: 'user-123', message });
    const [rec] = await records();
    expect(rec).toMatchObject({
      requestId: res.body.requestId,
      userId: 'user-123',
      providerStatus: 'success',
      redactedMessage: 'Hello <REDACTED: EMAIL>',
    });
    expect(open(rec!)).toBe(message);
  });

  it('gives each request its own requestId', async () => {
    const { app } = build();
    const [a, b] = await Promise.all([post(app), post(app)]);
    expect(a.body.requestId).not.toBe(b.body.requestId);
  });

  it('serves a health check', async () => {
    const { app } = build();
    expect((await request(app).get('/health')).body).toEqual({ status: 'ok' });
  });
});

describe('redaction', () => {
  it('sends only the sanitized message to the provider', async () => {
    const provider = stubProvider();
    const { app } = build({ provider });
    await post(app, { userId: 'u1', message: PII_MESSAGE });
    expect(provider.received).toEqual([
      'Mail <REDACTED: EMAIL>, card <REDACTED: CREDIT_CARD>, ssn <REDACTED: SSN>, alt <REDACTED: SSN>',
    ]);
    expectNoPii(provider.received);
  });

  it('stores the redacted message in plaintext and keeps PII off disk and out of the response and logs', async () => {
    const { app } = build();
    const res = await post(app, { userId: 'u1', message: PII_MESSAGE });
    const [rec] = await records();
    expect(rec!.redactedMessage).toBe(
      'Mail <REDACTED: EMAIL>, card <REDACTED: CREDIT_CARD>, ssn <REDACTED: SSN>, alt <REDACTED: SSN>',
    );
    expectNoPii(await readFile(file, 'utf8'));
    expectNoPii(res.body);
    expectNoPii(logs);
    expect(open(rec!)).toBe(PII_MESSAGE);
  });
});

describe('invalid input', () => {
  it.each([
    ['missing userId', { message: 'hi' }],
    ['missing message', { userId: 'u1' }],
    ['non-string message', { userId: 'u1', message: 123 }],
    ['non-string userId', { userId: 5, message: 'hi' }],
    ['empty message', { userId: 'u1', message: '' }],
    ['message too long', { userId: 'u1', message: 'x'.repeat(4001) }],
    ['userId with illegal characters', { userId: 'bad id\n{}', message: 'hi' }],
    ['userId too long', { userId: 'a'.repeat(65), message: 'hi' }],
    ['unexpected extra field', { userId: 'u1', message: 'hi', admin: true }],
    ['array body', [{ userId: 'u1', message: 'hi' }]],
    ['null body', null],
    ['string body', 'just text'],
  ])('400 for %s', async (_label, body) => {
    const provider = stubProvider();
    const { app } = build({ provider });
    const res = await request(app).post('/secure-inquiry').set('Content-Type', 'application/json').send(JSON.stringify(body));
    expect(res.status).toBe(400);
    // Top-level null/string bodies are rejected earlier by express.json's strict mode ("Bad Request").
    expect(res.body.status).toBe('invalid_request');
    expect(['Invalid request', 'Bad Request']).toContain(res.body.error);
    expect(provider.received).toHaveLength(0);
    expect(await records()).toHaveLength(0);
  });

  it('reports field names only, never client-supplied values', async () => {
    const { app } = build();
    const res = await post(app, { userId: 'u1', message: PII_MESSAGE, [`leak-${EMAIL}`]: 1 });
    expect(res.status).toBe(400);
    expectNoPii(res.body);
  });

  it('415 for a non-JSON content type', async () => {
    const { app } = build();
    const res = await request(app).post('/secure-inquiry').set('Content-Type', 'text/plain').send('hello');
    expect(res.status).toBe(415);
  });

  it('400 for malformed JSON without echoing the body', async () => {
    const { app } = build();
    const res = await request(app)
      .post('/secure-inquiry')
      .set('Content-Type', 'application/json')
      .send(`{"userId":"u1","message":"${PII_MESSAGE}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Bad Request');
    expectNoPii(res.body);
    expectNoPii(logs);
  });

  it('413 for an oversized body', async () => {
    const { app } = build();
    const res = await post(app, { userId: 'u1', message: 'x'.repeat(100_000) });
    expect(res.status).toBe(413);
    expect(res.body.error).toBe('Payload Too Large');
  });

  it('404 for unknown routes', async () => {
    const { app } = build();
    expect((await request(app).get('/nope')).status).toBe(404);
  });

  it('client errors never count as provider failures', async () => {
    const { app, breaker } = build();
    for (let i = 0; i < 10; i++) await post(app, { userId: 'u1' });
    expect(breaker.state).toBe('CLOSED');
    expect((await post(app)).status).toBe(200);
  });
});

describe('AI provider failures', () => {
  it('returns 503 Service Unavailable and audits the failure with the original encrypted', async () => {
    const provider = stubProvider(async () => {
      throw new ProviderError('Simulated provider failure');
    });
    const { app } = build({ provider });
    const res = await post(app, { userId: 'u1', message: PII_MESSAGE });
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ requestId: expect.stringMatching(UUID), status: 'failed', error: 'Service Unavailable' });
    const [rec] = await records();
    expect(rec).toMatchObject({ requestId: res.body.requestId, providerStatus: 'failed' });
    expect(open(rec!)).toBe(PII_MESSAGE);
  });

  it('does not leak PII carried by a provider error message', async () => {
    const provider = stubProvider(async () => {
      throw new Error(`upstream rejected ${PII_MESSAGE}`);
    });
    const { app } = build({ provider });
    const res = await post(app, { userId: 'u1', message: PII_MESSAGE });
    expect(res.status).toBe(503);
    expectNoPii(res.body);
    expectNoPii(logs);
    expectNoPii(await readFile(file, 'utf8'));
  });

  it('treats a provider timeout as a failure', async () => {
    const provider = stubProvider(() => new Promise<string>(() => undefined));
    const { app } = build({ provider, timeoutMs: 30 });
    const res = await post(app);
    expect(res.status).toBe(503);
    expect(res.body.status).toBe('failed');
  });

  it('a provider that throws synchronously is handled as a failure', async () => {
    const provider: AiProvider = {
      generate() {
        throw new Error('sync boom');
      },
    };
    const { app } = build({ provider });
    expect((await post(app)).body.status).toBe('failed');
  });
});

describe('circuit breaker fallback', () => {
  const failing = () =>
    stubProvider(async () => {
      throw new ProviderError();
    });

  it('opens after 3 consecutive failures, then returns 503 "Service Busy" without calling the provider', async () => {
    const provider = failing();
    const { app, breaker } = build({ provider });
    for (let i = 0; i < 3; i++) expect((await post(app)).body.status).toBe('failed');
    expect(breaker.state).toBe('OPEN');

    const start = performance.now();
    const res = await post(app, { userId: 'u1', message: PII_MESSAGE });
    expect(performance.now() - start).toBeLessThan(500);
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ requestId: expect.stringMatching(UUID), status: 'breaker_open', error: 'Service Busy' });
    expect(res.headers['retry-after']).toBe('10');
    expect(provider.received).toHaveLength(3);
  });

  it('responds instantly even when the provider would take far longer', async () => {
    let call = 0;
    const provider = stubProvider(() =>
      ++call <= 3 ? Promise.reject(new ProviderError()) : new Promise<string>((r) => setTimeout(() => r('late'), 5000)),
    );
    const { app } = build({ provider });
    for (let i = 0; i < 3; i++) await post(app);
    const start = performance.now();
    const res = await post(app);
    expect(res.body.error).toBe('Service Busy');
    expect(performance.now() - start).toBeLessThan(500);
  });

  it('audits failed, breaker_open and success outcomes, always with the original encrypted', async () => {
    let call = 0;
    const provider = stubProvider(async () => {
      if (++call <= 3) throw new ProviderError();
      return 'Generated Answer';
    });
    const { app } = build({ provider });
    for (let i = 0; i < 3; i++) await post(app, { userId: 'u1', message: PII_MESSAGE });
    await post(app, { userId: 'u1', message: PII_MESSAGE }); // open
    clock += COOLDOWN;
    await post(app, { userId: 'u1', message: PII_MESSAGE }); // probe succeeds

    const recs = await records();
    expect(recs.map((r) => r.providerStatus)).toEqual(['failed', 'failed', 'failed', 'breaker_open', 'success']);
    for (const r of recs) expect(open(r)).toBe(PII_MESSAGE);
    expectNoPii(await readFile(file, 'utf8'));
  });

  it('recovers: after the cooldown a successful probe closes the breaker', async () => {
    let healthy = false;
    const provider = stubProvider(async () => {
      if (!healthy) throw new ProviderError();
      return 'Generated Answer';
    });
    const { app, breaker } = build({ provider });
    for (let i = 0; i < 3; i++) await post(app);
    expect((await post(app)).body.status).toBe('breaker_open');

    healthy = true;
    clock += COOLDOWN;
    expect((await post(app)).status).toBe(200);
    expect(breaker.state).toBe('CLOSED');
    expect((await post(app)).status).toBe(200);
  });

  it('a failed probe re-opens the breaker', async () => {
    const provider = failing();
    const { app, breaker } = build({ provider });
    for (let i = 0; i < 3; i++) await post(app);
    clock += COOLDOWN;
    expect((await post(app)).body.status).toBe('failed'); // the probe ran and failed
    expect(breaker.state).toBe('OPEN');
    expect((await post(app)).body.status).toBe('breaker_open');
    expect(provider.received).toHaveLength(4);
  });

  it('sends exactly one probe when many requests arrive after the cooldown', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let call = 0;
    const provider = stubProvider(async () => {
      if (++call <= 3) throw new ProviderError();
      await gate;
      return 'Generated Answer';
    });
    const { app, breaker } = build({ provider });
    for (let i = 0; i < 3; i++) await post(app);
    clock += COOLDOWN;

    const done: number[] = [];
    const inflight = Array.from({ length: 5 }, () => post(app).then((r) => (done.push(r.status), r)));
    await vi.waitFor(() => expect(done).toHaveLength(4)); // the four non-probe requests answered at once
    expect(provider.received).toHaveLength(4); // 3 failures + exactly 1 probe
    expect(breaker.state).toBe('HALF_OPEN');
    release();

    const all = await Promise.all(inflight);
    const bodies = all.map((r) => r.body.status).sort();
    expect(bodies).toEqual(['breaker_open', 'breaker_open', 'breaker_open', 'breaker_open', 'success']);
    expect(breaker.state).toBe('CLOSED');
  });
});

describe('audit failures and unexpected errors', () => {
  it('fails closed with a generic 500 when the audit write fails, leaking nothing', async () => {
    const auditLog = createAuditLog({
      filePath: file,
      key,
      appendFile: async () => {
        throw Object.assign(new Error(`disk error for ${PII_MESSAGE}`), { code: 'ENOSPC' });
      },
    });
    const { app, breaker } = build({ auditLog });
    const res = await post(app, { userId: 'u1', message: PII_MESSAGE });
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ requestId: expect.stringMatching(UUID), status: 'error', error: 'Internal Server Error' });
    expect(res.body.answer).toBeUndefined();
    expectNoPii(res.body);
    expectNoPii(logs);
    expect(logs.some((l) => l.event === 'unhandled_error' && l.errorCode === 'ENOSPC')).toBe(true);
    expect(breaker.state).toBe('CLOSED'); // audit problems are not provider failures
  });

  it('audit failures do not count toward opening the breaker', async () => {
    const auditLog = createAuditLog({
      filePath: file,
      key,
      appendFile: async () => {
        throw new Error('nope');
      },
    });
    const { app, breaker } = build({ auditLog });
    for (let i = 0; i < 5; i++) await post(app);
    expect(breaker.state).toBe('CLOSED');
  });

  it('returns a generic 500 for an unexpected async error and keeps its message private', async () => {
    const auditLog: AuditLog = {
      async write() {
        throw new Error(`unexpected: ${PII_MESSAGE}`);
      },
    };
    const { app } = build({ auditLog });
    const res = await post(app, { userId: 'u1', message: PII_MESSAGE });
    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Internal Server Error');
    expectNoPii(res.body);
    expectNoPii(logs);
  });

  it('keeps serving after an unexpected error', async () => {
    let fail = true;
    const real = createAuditLog({ filePath: file, key });
    const auditLog: AuditLog = {
      write: (i) => (fail ? Promise.reject(new Error('x')) : real.write(i)),
    };
    const { app } = build({ auditLog });
    expect((await post(app)).status).toBe(500);
    fail = false;
    expect((await post(app)).status).toBe(200);
  });
});

describe('logging', () => {
  it('logs ids, statuses, counts and timings only', async () => {
    const { app } = build();
    const res = await post(app, { userId: 'secret-user', message: PII_MESSAGE });
    const entry = logs.find((l) => l.event === 'inquiry_completed');
    expect(entry).toMatchObject({
      requestId: res.body.requestId,
      providerStatus: 'success',
      breakerState: 'CLOSED',
      redactions: { EMAIL: 1, CREDIT_CARD: 1, SSN: 2 },
    });
    const text = JSON.stringify(logs);
    expectNoPii(text);
    expect(text).not.toContain('secret-user');
    expect(text).not.toContain('Mail ');
  });
});

// ---- Security review regressions ----

describe('review #4: userId must not carry PII into the plaintext audit log', () => {
  it.each([
    ['an SSN with hyphens', '123-45-6789'],
    ['a 9-digit SSN', '123456789'],
    ['a card number', '4111111111111111'],
    ['a dotted SSN', '123.45.6789'],
  ])('400 for a userId that is %s, and nothing is audited', async (_label, userId) => {
    const provider = stubProvider();
    const { app } = build({ provider });
    const res = await post(app, { userId, message: 'hi' });
    expect(res.status).toBe(400);
    expect(res.body.fields).toEqual(['userId']);
    expect(JSON.stringify(res.body)).not.toContain(userId);
    expect(provider.received).toHaveLength(0);
    expect(await records()).toHaveLength(0);
  });

  it.each(['user-123', 'john.doe', 'svc:billing', 'a_b-c', 'USER42', '12345678'])('still accepts a normal id: %s', async (userId) => {
    const { app } = build();
    expect((await post(app, { userId, message: 'hi' })).status).toBe(200);
  });
});

describe('review #16: message validation', () => {
  const raw = (app: ReturnType<typeof build>['app'], json: string) =>
    request(app).post('/secure-inquiry').set('Content-Type', 'application/json').send(json);

  it.each([
    ['whitespace only', '{"userId":"u1","message":"   \\n\\t "}'],
    ['a lone high surrogate', '{"userId":"u1","message":"bad \\ud800 char"}'],
    ['a lone low surrogate', '{"userId":"u1","message":"bad \\udc00 char"}'],
    ['a NUL character', '{"userId":"u1","message":"a\\u0000b"}'],
    ['an escape character', '{"userId":"u1","message":"a\\u001bb"}'],
    ['a DEL character', '{"userId":"u1","message":"a\\u007fb"}'],
  ])('400 for %s', async (_label, json) => {
    const provider = stubProvider();
    const { app } = build({ provider });
    const res = await raw(app, json);
    expect(res.status).toBe(400);
    expect(res.body.fields).toEqual(['message']);
    expect(provider.received).toHaveLength(0);
    expect(await records()).toHaveLength(0);
  });

  it('still accepts newlines, tabs, emoji (surrogate PAIRS) and non-Latin text', async () => {
    const message = 'line1\nline2\tcol 🔐 日本語 العربية';
    const { app } = build();
    const res = await post(app, { userId: 'u1', message });
    expect(res.status).toBe(200);
    const [rec] = await records();
    expect(open(rec!)).toBe(message); // exact round trip, nothing silently altered
  });
});

describe('review #14: HTTP semantics', () => {
  it.each(['get', 'put', 'delete', 'patch'] as const)('405 with Allow: POST for %s /secure-inquiry', async (method) => {
    const { app } = build();
    const res = await request(app)[method]('/secure-inquiry');
    expect(res.status).toBe(405);
    expect(res.headers.allow).toBe('POST');
    expect(res.body.error).toBe('Method Not Allowed');
  });

  it('405 for POST /health', async () => {
    const { app } = build();
    const res = await request(app).post('/health').send({});
    expect(res.status).toBe(405);
    expect(res.headers.allow).toContain('GET');
  });

  it('404, not 415, for a POST to an unknown path with a non-JSON body', async () => {
    const { app } = build();
    const res = await request(app).post('/nope').set('Content-Type', 'text/plain').send('x');
    expect(res.status).toBe(404);
  });

  it('415 is still returned for the real endpoint with a non-JSON body', async () => {
    const { app } = build();
    expect((await request(app).post('/secure-inquiry').set('Content-Type', 'text/plain').send('x')).status).toBe(415);
  });

  it('wrong-method requests never touch the provider, breaker or audit log', async () => {
    const provider = stubProvider();
    const { app, breaker } = build({ provider });
    await request(app).get('/secure-inquiry');
    expect(provider.received).toHaveLength(0);
    expect(breaker.state).toBe('CLOSED');
    expect(await records()).toHaveLength(0);
  });
});

describe('review #18: response headers', () => {
  it.each([
    ['success', () => post(build().app)],
    ['400', () => post(build().app, { userId: 'u' })],
    ['404', () => request(build().app).get('/nope')],
    ['health', () => request(build().app).get('/health')],
  ])('sets no-store, nosniff and a locked-down CSP on %s responses', async (_label, send) => {
    const res = await send();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});

describe('review #8: concurrency cap', () => {
  it('a burst against a hanging provider reaches it at most maxConcurrent times; the rest get Service Busy at once', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const provider = stubProvider(async () => {
      await gate;
      return 'Generated Answer';
    });
    const { app, breaker } = build({ provider, maxConcurrent: 3 });

    const done: Array<{ status: number; body: Record<string, unknown> }> = [];
    const inflight = Array.from({ length: 8 }, () => post(app).then((r) => (done.push({ status: r.status, body: r.body }), r)));
    await vi.waitFor(() => expect(done).toHaveLength(5)); // the 5 over the cap answer immediately
    expect(provider.received).toHaveLength(3);
    expect(done.every((d) => d.status === 503 && d.body.status === 'overloaded' && d.body.error === 'Service Busy')).toBe(true);
    expect(breaker.state).toBe('CLOSED'); // being busy is not a provider failure

    release();
    const all = await Promise.all(inflight);
    expect(all.filter((r) => r.status === 200)).toHaveLength(3);
    const statuses = (await records()).map((r) => r.providerStatus).sort();
    expect(statuses).toEqual(['overloaded', 'overloaded', 'overloaded', 'overloaded', 'overloaded', 'success', 'success', 'success']);
  });

  it('sends a Retry-After on overload responses', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const provider = stubProvider(() => gate.then(() => 'x'));
    const { app } = build({ provider, maxConcurrent: 1 });
    const first = post(app).then((r) => r); // supertest requests are lazy: .then() sends it
    await vi.waitFor(() => expect(provider.received).toHaveLength(1)); // the only slot is now taken
    const res = await post(app);
    expect(res.status).toBe(503);
    expect(res.headers['retry-after']).toBe('1');
    release();
    await first;
  });
});

describe('review #15: provider timeout aborts the provider call', () => {
  it('aborts the signal handed to the provider when the call times out', async () => {
    const provider = stubProvider(() => new Promise<string>(() => undefined));
    const { app } = build({ provider, timeoutMs: 20 });
    const res = await post(app);
    expect(res.status).toBe(503);
    expect(res.body.status).toBe('failed');
    expect(provider.signals[0]?.aborted).toBe(true);
  });
});

describe('review #7: backpressure and rate limiting', () => {
  it('answers 503 Service Busy (not 500) when the audit queue is full, and recovers', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let started = 0;
    const auditLog = createAuditLog({
      filePath: file,
      key,
      maxPending: 1,
      appendFile: async () => {
        started++;
        await gate;
      },
    });
    const { app } = build({ auditLog });

    const first = post(app).then((r) => r); // its audit write occupies the only slot
    await vi.waitFor(() => expect(started).toBe(1));
    const res = await post(app);
    expect(res.status).toBe(503);
    expect(res.body).toEqual({ requestId: expect.stringMatching(UUID), status: 'overloaded', error: 'Service Busy' });
    expect(res.headers['retry-after']).toBe('1');
    release();
    expect((await first).status).toBe(200);
    expect((await post(app)).status).toBe(200); // capacity is back
  });

  it('answers a generic 500 when the audit file is full, without leaking anything', async () => {
    const auditLog = createAuditLog({ filePath: file, key, maxFileBytes: 200 });
    const { app } = build({ auditLog });
    expect((await post(app)).status).toBe(500); // one record is bigger than 200 bytes
    const res = await post(app, { userId: 'u1', message: PII_MESSAGE });
    expect(res.body).toEqual({ requestId: expect.stringMatching(UUID), status: 'error', error: 'Internal Server Error' });
    expectNoPii(res.body);
    expectNoPii(logs);
  });

  it('rate-limits per client with 429 and Retry-After, counting invalid requests too, but not /health', async () => {
    const { app } = build({ rateLimit: { max: 3, windowMs: 60_000 } });
    expect((await post(app)).status).toBe(200);
    expect((await post(app, { userId: 'u' })).status).toBe(400); // still counts
    expect((await post(app)).status).toBe(200);
    const limited = await post(app);
    expect(limited.status).toBe(429);
    expect(limited.headers['retry-after']).toBeDefined();
    expect(limited.body).toEqual({ requestId: expect.stringMatching(UUID), status: 'rate_limited', error: 'Too Many Requests' });
    expect((await request(app).get('/health')).status).toBe(200);
  });

  it('rate-limited requests never reach the provider or the audit log', async () => {
    const provider = stubProvider();
    const { app } = build({ provider, rateLimit: { max: 1, windowMs: 60_000 } });
    await post(app);
    await post(app);
    await post(app);
    expect(provider.received).toHaveLength(1);
    expect(await records()).toHaveLength(1);
  });
});

describe('review #6: integration — stored records are tamper-evident', () => {
  it('editing any plaintext field of a stored record breaks decryption', async () => {
    const { app } = build();
    await post(app, { userId: 'user-123', message: PII_MESSAGE });
    const [rec] = await records();
    expect(open(rec!)).toBe(PII_MESSAGE);
    expect(() => open({ ...rec!, providerStatus: 'failed' })).toThrow();
    expect(() => open({ ...rec!, redactedMessage: 'clean' })).toThrow();
    expect(() => open({ ...rec!, userId: 'user-999' })).toThrow();
  });
});
