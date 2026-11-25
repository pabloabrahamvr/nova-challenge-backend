import type { Server } from 'node:http';
import { createApp } from './app.js';
import { createMockProvider } from './aiProvider.js';
import { createAuditLog } from './auditStore.js';
import { CircuitBreaker } from './circuitBreaker.js';
import type { Config } from './config.js';
import type { Logger } from './routes/secureInquiry.js';

/** Wire the real dependencies from configuration. Separate from server.ts so it can be tested. */
export function createServer(config: Config, log?: Logger): Server {
  const app = createApp({
    auditLog: createAuditLog({
      filePath: config.auditFilePath,
      key: config.encryptionKey,
      maxFileBytes: config.auditMaxFileBytes,
    }),
    provider: createMockProvider({ delayMs: config.providerDelayMs, failFirstN: config.providerFailFirstN }),
    breaker: new CircuitBreaker({
      failureThreshold: config.breakerFailureThreshold,
      cooldownMs: config.breakerCooldownMs,
      maxConcurrent: config.providerMaxConcurrency,
      callTimeoutMs: config.providerTimeoutMs,
    }),
    rateLimit: { max: config.rateLimitMax, windowMs: config.rateLimitWindowMs },
    ...(log ? { log } : {}),
  });

  const server = app.listen(config.port);
  return hardenServer(server);
}

/** Slow-client protections beyond Node's defaults. */
export function hardenServer(server: Server): Server {
  server.headersTimeout = 10_000; // time to receive the request headers
  server.requestTimeout = 30_000; // time to receive the whole request
  server.keepAliveTimeout = 5_000;
  server.maxConnections = 1000;
  return server;
}
