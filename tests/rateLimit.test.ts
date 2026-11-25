import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createRateLimiter } from '../src/rateLimit.js';

function build(opts: { max: number; windowMs?: number; maxKeys?: number }, clock = { t: 0 }) {
  const app = express();
  app.set('trust proxy', true); // lets tests choose the client IP via X-Forwarded-For
  app.use((_req, res, next) => ((res.locals.requestId = 'rid'), next()));
  app.use(createRateLimiter({ windowMs: 1000, now: () => clock.t, ...opts }));
  app.get('/', (_req, res) => void res.json({ ok: true }));
  return { app, clock };
}
const hit = (app: express.Express, ip = '1.1.1.1') => request(app).get('/').set('X-Forwarded-For', ip);

describe('rate limiter', () => {
  it('allows up to max requests per window, then answers 429 with Retry-After', async () => {
    const { app } = build({ max: 3 });
    for (let i = 0; i < 3; i++) expect((await hit(app)).status).toBe(200);
    const res = await hit(app);
    expect(res.status).toBe(429);
    expect(res.headers['retry-after']).toBe('1');
    expect(res.body).toEqual({ requestId: 'rid', status: 'rate_limited', error: 'Too Many Requests' });
  });

  it('tracks clients independently', async () => {
    const { app } = build({ max: 1 });
    expect((await hit(app, '1.1.1.1')).status).toBe(200);
    expect((await hit(app, '1.1.1.1')).status).toBe(429);
    expect((await hit(app, '2.2.2.2')).status).toBe(200);
  });

  it('starts a fresh window after windowMs', async () => {
    const { app, clock } = build({ max: 1 });
    expect((await hit(app)).status).toBe(200);
    expect((await hit(app)).status).toBe(429);
    clock.t += 1000;
    expect((await hit(app)).status).toBe(200);
  });

  it('bounds memory: never tracks more than maxKeys clients', async () => {
    const { app } = build({ max: 1, maxKeys: 5 });
    for (let i = 0; i < 50; i++) await hit(app, `10.0.0.${i}`);
    // The oldest clients were evicted, so they get a fresh allowance (bounded memory beats perfect memory).
    expect((await hit(app, '10.0.0.0')).status).toBe(200);
  });
});
