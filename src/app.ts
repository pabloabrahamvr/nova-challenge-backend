import { randomUUID } from 'node:crypto';
import express, { type ErrorRequestHandler, type Express, type RequestHandler } from 'express';
import type { AiProvider } from './aiProvider.js';
import type { AuditLog } from './auditStore.js';
import type { CircuitBreaker } from './circuitBreaker.js';
import { createSecureInquiryRouter, type Logger } from './routes/secureInquiry.js';

export const BODY_LIMIT = '16kb'; // 4000 chars of 4-byte UTF-8 plus JSON overhead

export interface AppDeps {
  auditLog: AuditLog;
  provider: AiProvider;
  breaker: CircuitBreaker;
  providerTimeoutMs: number;
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

  const requireJson: RequestHandler = (req, res, next) => {
    if (req.method === 'POST' && !req.is('application/json')) {
      res.status(415).json({ requestId: res.locals.requestId, status: 'invalid_request', error: 'Unsupported Media Type' });
      return;
    }
    next();
  };

  app.use(assignRequestId);
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });
  app.use(requireJson);
  app.use(express.json({ limit: BODY_LIMIT }));
  app.use(
    createSecureInquiryRouter({
      auditLog: deps.auditLog,
      provider: deps.provider,
      breaker: deps.breaker,
      providerTimeoutMs: deps.providerTimeoutMs,
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
    const parserStatus = typeof e.status === 'number' && e.status >= 400 && e.status < 500 ? e.status : undefined;

    if (parserStatus !== undefined) {
      const error = parserStatus === 413 ? 'Payload Too Large' : parserStatus === 415 ? 'Unsupported Media Type' : 'Bad Request';
      const status = parserStatus === 413 || parserStatus === 415 ? parserStatus : 400;
      log({ event: 'bad_request', requestId, status });
      res.status(status).json({ requestId, status: 'invalid_request', error });
      return;
    }

    log({
      event: 'unhandled_error',
      requestId,
      errorName: typeof e.name === 'string' ? e.name : 'Error',
      errorCode: typeof e.code === 'string' ? e.code : undefined,
    });
    if (res.headersSent) {
      res.end();
      return;
    }
    res.status(500).json({ requestId, status: 'error', error: 'Internal Server Error' });
  };
  app.use(errorHandler);

  return app;
}
