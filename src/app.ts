import { randomUUID } from 'node:crypto';
import express, { type ErrorRequestHandler, type Express, type RequestHandler } from 'express';
import type { AiProvider } from './aiProvider.js';
import { AuditWriteError, type AuditLog } from './auditStore.js';
import type { CircuitBreaker } from './circuitBreaker.js';
import { createRateLimiter, type RateLimitOptions } from './rateLimit.js';
import { createSecureInquiryRouter, type Logger } from './routes/secureInquiry.js';

export interface AppDeps {
  auditLog: AuditLog;
  provider: AiProvider;
  breaker: CircuitBreaker;
  /** Per-IP rate limit on POST /secure-inquiry. Omit (or max <= 0) to disable. */
  rateLimit?: RateLimitOptions;
  log?: Logger;
}

/** One JSON line per event. Callers pass ids, statuses and counts only, never message content. */
const defaultLog: Logger = (entry) => console.info(JSON.stringify({ ts: new Date().toISOString(), ...entry }));

export function createApp(deps: AppDeps): Express {
  const log = deps.log ?? defaultLog;
  const app = express();
  app.disable('x-powered-by');

  const assignRequestId: RequestHandler = (_req, res, next) => {
    res.locals.requestId = randomUUID();
    next();
  };

  // Responses are JSON API payloads: never sniffed, never cached by intermediaries or browsers.
  const securityHeaders: RequestHandler = (_req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    });
    next();
  };

  app.use(assignRequestId);
  app.use(securityHeaders);

  app
    .route('/health')
    .get((_req, res) => {
      res.json({ status: 'ok' });
    })
    .all((_req, res) => {
      res.status(405).set('Allow', 'GET, HEAD').json({ requestId: res.locals.requestId, status: 'error', error: 'Method Not Allowed' });
    });

  if (deps.rateLimit && deps.rateLimit.max > 0) {
    app.use('/secure-inquiry', createRateLimiter(deps.rateLimit));
  }
  app.use(
    createSecureInquiryRouter({
      auditLog: deps.auditLog,
      provider: deps.provider,
      breaker: deps.breaker,
      log,
    }),
  );

  app.use((_req, res) => {
    res.status(404).json({ requestId: res.locals.requestId, status: 'error', error: 'Not Found' });
  });

  // Fixed messages only. body-parser errors (and Node's JSON.parse errors) can quote the request body,
  // so err.message is never sent to the client or logged.
  const errorHandler: ErrorRequestHandler = (err: unknown, _req, res, _next) => {
    const e = err as { status?: unknown; name?: unknown; code?: unknown };
    const requestId = res.locals.requestId as string;
    const clientStatus = typeof e.status === 'number' && e.status >= 400 && e.status < 500 ? e.status : undefined;

    if (clientStatus !== undefined) {
      const error = clientStatus === 413 ? 'Payload Too Large' : clientStatus === 415 ? 'Unsupported Media Type' : 'Bad Request';
      const status = clientStatus === 413 || clientStatus === 415 ? clientStatus : 400;
      log({ event: 'bad_request', requestId, status });
      res.status(status).json({ requestId, status: 'invalid_request', error });
      return;
    }

    const code = typeof e.code === 'string' ? e.code : undefined;
    log({ event: 'unhandled_error', requestId, errorName: typeof e.name === 'string' ? e.name : 'Error', errorCode: code });
    if (res.headersSent) {
      res.end();
      return;
    }
    // The audit queue is full: we are overloaded, not broken. Tell clients to back off.
    if (err instanceof AuditWriteError && code === 'QUEUE_FULL') {
      res.status(503).set('Retry-After', '1').json({ requestId, status: 'overloaded', error: 'Service Busy' });
      return;
    }
    res.status(500).json({ requestId, status: 'error', error: 'Internal Server Error' });
  };
  app.use(errorHandler);

  return app;
}
