import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createApp } from '../src/app.js';
import { ProviderError, createMockProvider, type AiProvider } from '../src/aiProvider.js';
import { createAuditLog, type AuditLog, type AuditRecord } from '../src/auditStore.js';
import { CircuitBreaker } from '../src/circuitBreaker.js';
import { decrypt } from '../src/crypto.js';

const key = randomBytes(32);
const COOLDOWN = 10_000;
const EMAIL = 'john@example.com';
const CARD = '4111 1111 1111 1111';
const SSN = '123-45-6789';
const PII_MESSAGE = `Mail ${EMAIL}, card ${CARD}, ssn ${SSN}, alt 987654321`;
const PII_FRAGMENTS = [EMAIL, '4111', SSN, '987654321'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface StubProvider extends AiProvider {
  received: string[];
}

/** Records what it was sent; behaviour is set by the test. */
function stubProvider(impl: (call: number) => Promise<string> = async () => 'Generated Answer'): StubProvider {
  const received: string[] = [];
  return {
    received,
    generate(message) {
      received.push(message);
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

function build(opts: { provider?: AiProvider; auditLog?: AuditLog; timeoutMs?: number } = {}) {
  const breaker = new CircuitBreaker({ failureThreshold: 3, cooldownMs: COOLDOWN, now: () => clock });
  const provider = opts.provider ?? stubProvider();
  const auditLog = opts.auditLog ?? createAuditLog({ filePath: file, key });
  const app = createApp({
    auditLog,
    provider,
    breaker,
    providerTimeoutMs: opts.timeoutMs ?? 5000,
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
    expect(decrypt(rec!.encryptedOriginalMessage, key, rec!.requestId)).toBe(message);
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
    expect(decrypt(rec!.encryptedOriginalMessage, key, rec!.requestId)).toBe(PII_MESSAGE);
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
    expect(decrypt(rec!.encryptedOriginalMessage, key, rec!.requestId)).toBe(PII_MESSAGE);
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
    for (const r of recs) expect(decrypt(r.encryptedOriginalMessage, key, r.requestId)).toBe(PII_MESSAGE);
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
