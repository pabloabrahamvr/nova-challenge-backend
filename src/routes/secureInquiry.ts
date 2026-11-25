import express, { Router, type RequestHandler } from 'express';
import { z } from 'zod';
import type { AiProvider } from '../aiProvider.js';
import type { AuditLog, ProviderStatus } from '../auditStore.js';
import { BreakerBusyError, BreakerOpenError, type CircuitBreaker } from '../circuitBreaker.js';
import { redact } from '../redactor.js';

export const MAX_MESSAGE_CHARS = 4000;
export const BODY_LIMIT = '16kb'; // 4000 chars of 4-byte UTF-8 plus JSON overhead

// Control characters other than \t \n \r (NUL, ESC, DEL, ...).
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/;
// A lone surrogate (invalid UTF-16): it would be silently replaced with U+FFFD, so the encrypted
// "original" would no longer be what the client sent.
const LONE_SURROGATE = /\p{Cs}/u;

const bodySchema = z.strictObject({
  userId: z
    .string()
    .regex(/^[A-Za-z0-9_.:-]{1,64}$/)
    // userId is stored in plaintext in the audit log, so it must not itself contain PII
    // (SSN / card digits fit the character set above).
    .refine((id) => redact(id).text === id),
  message: z
    .string()
    .min(1)
    .max(MAX_MESSAGE_CHARS)
    .refine((m) => m.trim().length > 0)
    .refine((m) => !LONE_SURROGATE.test(m))
    .refine((m) => !CONTROL_CHARS.test(m)),
});

export type Logger = (entry: Record<string, unknown>) => void;

export interface SecureInquiryDeps {
  auditLog: AuditLog;
  provider: AiProvider;
  breaker: CircuitBreaker;
  log: Logger;
}

const requireJson: RequestHandler = (req, res, next) => {
  if (!req.is('application/json')) {
    res.status(415).json({ requestId: res.locals.requestId, status: 'invalid_request', error: 'Unsupported Media Type' });
    return;
  }
  next();
};

/**
 * Lifecycle: validate -> redact -> breaker gate -> provider (redacted text only) -> audit -> respond.
 *
 * Validation happens before the breaker, so client errors never count as provider failures.
 * The audit write comes after the provider call so the record carries the real outcome; if it fails
 * we fail closed (500/503) rather than return an answer that has no audit trail.
 * Express 5 forwards rejected promises from async handlers to the error middleware.
 */
export function createSecureInquiryRouter(deps: SecureInquiryDeps): Router {
  const { auditLog, provider, breaker, log } = deps;
  const router = Router();

  router
    .route('/secure-inquiry')
    .post(requireJson, express.json({ limit: BODY_LIMIT }), async (req, res) => {
      const requestId = res.locals.requestId as string;
      const startedAt = performance.now();

      const parsed = bodySchema.safeParse(req.body);
      if (!parsed.success) {
        // Field names only: zod messages for unknown keys would echo client-controlled text.
        const fields = [...new Set(parsed.error.issues.map((i) => String(i.path[0] ?? '(body)')))];
        log({ event: 'validation_failed', requestId });
        res.status(400).json({ requestId, status: 'invalid_request', error: 'Invalid request', fields });
        return;
      }
      const { userId, message } = parsed.data;

      const redacted = redact(message);

      let providerStatus: ProviderStatus;
      let answer = '';
      try {
        answer = await breaker.execute((signal) => provider.generate(redacted.text, signal));
        providerStatus = 'success';
      } catch (err) {
        providerStatus =
          err instanceof BreakerOpenError ? 'breaker_open' : err instanceof BreakerBusyError ? 'overloaded' : 'failed';
      }

      await auditLog.write({
        requestId,
        userId,
        providerStatus,
        originalMessage: message,
        redactedMessage: redacted.text,
      });

      log({
        event: 'inquiry_completed',
        requestId,
        providerStatus,
        breakerState: breaker.state,
        redactions: redacted.counts,
        durationMs: Math.round(performance.now() - startedAt),
      });

      if (providerStatus === 'success') {
        res.status(200).json({ requestId, status: 'success', answer });
      } else if (providerStatus === 'breaker_open') {
        res
          .status(503)
          .set('Retry-After', String(breaker.retryAfterSeconds()))
          .json({ requestId, status: 'breaker_open', error: 'Service Busy' });
      } else if (providerStatus === 'overloaded') {
        res.status(503).set('Retry-After', '1').json({ requestId, status: 'overloaded', error: 'Service Busy' });
      } else {
        res.status(503).json({ requestId, status: 'failed', error: 'Service Unavailable' });
      }
    })
    .all((_req, res) => {
      res.status(405).set('Allow', 'POST').json({ requestId: res.locals.requestId, status: 'error', error: 'Method Not Allowed' });
    });

  return router;
}

