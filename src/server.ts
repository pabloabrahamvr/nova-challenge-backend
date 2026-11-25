import { createServer } from './bootstrap.js';
import { ConfigError, loadConfig } from './config.js';

let config;
try {
  config = loadConfig();
} catch (err) {
  console.error(err instanceof ConfigError ? err.message : 'Failed to load configuration');
  process.exit(1);
}

const server = createServer(config);
server.on('listening', () => console.info(JSON.stringify({ event: 'listening', port: config.port })));

const shutdown = (): void => {
  server.close(() => process.exit(0));
  server.closeIdleConnections();
  setTimeout(() => process.exit(1), 10_000).unref(); // do not hang forever on stuck connections
};
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.on(signal, shutdown);
