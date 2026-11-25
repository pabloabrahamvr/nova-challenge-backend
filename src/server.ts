import { createApp } from './app.js';
import { createMockProvider } from './aiProvider.js';
import { createAuditLog } from './auditStore.js';
import { CircuitBreaker } from './circuitBreaker.js';
import { ConfigError, loadConfig } from './config.js';

let config;
try {
  config = loadConfig();
} catch (err) {
  console.error(err instanceof ConfigError ? err.message : 'Failed to load configuration');
  process.exit(1);
}

const app = createApp({
  auditLog: createAuditLog({ filePath: config.auditFilePath, key: config.encryptionKey }),
  provider: createMockProvider({ delayMs: config.providerDelayMs, failFirstN: config.providerFailFirstN }),
  breaker: new CircuitBreaker({
    failureThreshold: config.breakerFailureThreshold,
    cooldownMs: config.breakerCooldownMs,
  }),
  providerTimeoutMs: config.providerTimeoutMs,
});

const server = app.listen(config.port, () => {
  console.info(JSON.stringify({ event: 'listening', port: config.port }));
});

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
