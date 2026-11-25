import { Router } from 'express';
import { z } from 'zod';
import type { AiProvider } from '../aiProvider.js';
import { withTimeout } from '../aiProvider.js';
import type { AuditLog, ProviderStatus } from '../auditStore.js';
import { BreakerOpenError, type CircuitBreaker } from '../circuitBreaker.js';
import { redact } from '../redactor.js';

export const MAX_MESSAGE_CHARS = 4000;

const bodySchema = z.strictObject({
  userId: z.string().regex(/^[A-Za-z0-9_.:-]{1,64}$/),
  message: z.string().min(1).max(MAX_MESSAGE_CHARS),
});

export type Logger = (entry: Record<string, unknown>) => void;

export interface SecureInquiryDeps {
  auditLog: AuditLog;
  provider: AiProvider;
  breaker: CircuitBreaker;
  providerTimeoutMs: number;
  log: Logger;
}

/**
 * Lifecycle: validate -> redact -> breaker gate -> provider (redacted text only) -> audit -> respond.
 *
 * Validation happens before the breaker, so client errors never count as provider failures.
 * The audit write comes after the provider call so the record carries the real outcome; if it fails
 * we fail closed (500) rather than return an answer that has no audit trail.
 * Express 5 forwards rejected promises from async handlers to the error middleware.
 */
export function createSecureInquiryRouter(deps: SecureInquiryDeps): Router {
  const { auditLog, provider, breaker, providerTimeoutMs, log } = deps;
  const router = Router();

  router.post('/secure-inquiry', async (req, res) => {
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
      answer = await breaker.execute(() => withTimeout(provider.generate(redacted.text), providerTimeoutMs));
      providerStatus = 'success';
    } catch (err) {
      providerStatus = err instanceof BreakerOpenError ? 'breaker_open' : 'failed';
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
    } else {
      res.status(503).json({ requestId, status: 'failed', error: 'Service Unavailable' });
    }
  });

  return router;
}
