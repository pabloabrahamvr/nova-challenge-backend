import type { RequestHandler } from 'express';

/**
 * Minimal fixed-window, in-memory rate limiter keyed by client IP (req.ip).
 * Per process only. Behind a reverse proxy, configure Express "trust proxy" so req.ip is the real client,
 * otherwise every client shares the proxy's address and one bucket.
 */
export interface RateLimitOptions {
  max: number;
  windowMs: number;
  /** Cap on tracked clients so the map cannot grow without bound. Default 10_000. */
  maxKeys?: number;
  now?: () => number;
}

export function createRateLimiter(options: RateLimitOptions): RequestHandler {
  const { max, windowMs } = options;
  const maxKeys = options.maxKeys ?? 10_000;
  const now = options.now ?? Date.now;
  const windows = new Map<string, { count: number; resetAt: number }>();

  const prune = (t: number): void => {
    for (const [key, w] of windows) if (w.resetAt <= t) windows.delete(key);
    // Still too many live clients: evict the oldest entries (Map keeps insertion order).
    for (const key of windows.keys()) {
      if (windows.size <= maxKeys) break;
      windows.delete(key);
    }
  };

  return (req, res, next) => {
    const t = now();
    const key = req.ip ?? 'unknown';
    let w = windows.get(key);
    if (!w || w.resetAt <= t) {
      if (windows.size >= maxKeys) prune(t);
      w = { count: 0, resetAt: t + windowMs };
      windows.set(key, w);
    }
    w.count += 1;
    if (w.count > max) {
      res
        .status(429)
        .set('Retry-After', String(Math.max(1, Math.ceil((w.resetAt - t) / 1000))))
        .json({ requestId: res.locals.requestId, status: 'rate_limited', error: 'Too Many Requests' });
      return;
    }
    next();
  };
}
