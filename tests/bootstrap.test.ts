import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createServer } from '../src/bootstrap.js';
import type { Config } from '../src/config.js';

let dir: string;
let server: Server | undefined;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'boot-test-'));
});
afterEach(async () => {
  await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
  server = undefined;
  await rm(dir, { recursive: true, force: true });
});

const config = (over: Partial<Config> = {}): Config => ({
  port: 0, // let the OS choose
  auditFilePath: join(dir, 'audit.jsonl'),
  auditMaxFileBytes: 1_000_000,
  encryptionKey: randomBytes(32),
  providerDelayMs: 0,
  providerTimeoutMs: 1000,
  providerMaxConcurrency: 10,
  breakerFailureThreshold: 3,
  breakerCooldownMs: 10_000,
  providerFailFirstN: 0,
  rateLimitMax: 0,
  rateLimitWindowMs: 60_000,
  ...over,
});

const start = async (c: Config): Promise<string> => {
  const logs: Record<string, unknown>[] = [];
  server = createServer(c, (e) => logs.push(e));
  await new Promise<void>((resolve) => server!.once('listening', () => resolve()));
  return `http://127.0.0.1:${(server!.address() as AddressInfo).port}`;
};

describe('createServer (real wiring from config)', () => {
  it('applies slow-client protections and a connection cap', async () => {
    await start(config());
    expect(server!.headersTimeout).toBe(10_000);
    expect(server!.requestTimeout).toBe(30_000);
    expect(server!.keepAliveTimeout).toBe(5_000);
    expect(server!.maxConnections).toBe(1000);
  });

  it('serves a real request through the real provider, breaker and audit log', async () => {
    const base = await start(config());
    expect((await fetch(`${base}/health`)).status).toBe(200);

    const res = await fetch(`${base}/secure-inquiry`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'user-1', message: 'mail john@example.com' }),
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { answer: string }).answer).toBe('Generated Answer');

    const raw = await readFile(join(dir, 'audit.jsonl'), 'utf8');
    expect(raw).toContain('mail <REDACTED: EMAIL>');
    expect(raw).not.toContain('john@example.com');
  });

  it('honours the failure-simulation settings: 3 failures open the breaker, the 4th is Service Busy', async () => {
    const base = await start(config({ providerFailFirstN: 3 }));
    const send = () =>
      fetch(`${base}/secure-inquiry`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ userId: 'u', message: 'hi' }),
      }).then(async (r) => ({ status: r.status, body: (await r.json()) as { status: string; error: string } }));
    for (let i = 0; i < 3; i++) expect((await send()).body.status).toBe('failed');
    expect(await send()).toMatchObject({ status: 503, body: { status: 'breaker_open', error: 'Service Busy' } });
  });

  it('enforces the provider timeout from config', async () => {
    const base = await start(config({ providerDelayMs: 5000, providerTimeoutMs: 30 }));
    const res = await fetch(`${base}/secure-inquiry`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'u', message: 'hi' }),
    });
    expect(res.status).toBe(503);
    expect(((await res.json()) as { status: string }).status).toBe('failed');
  });

  it('applies the rate limit from config', async () => {
    const base = await start(config({ rateLimitMax: 2 }));
    const codes: number[] = [];
    for (let i = 0; i < 3; i++) {
      codes.push(
        (
          await fetch(`${base}/secure-inquiry`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ userId: 'u', message: 'hi' }),
          })
        ).status,
      );
    }
    expect(codes).toEqual([200, 200, 429]);
  });
});
