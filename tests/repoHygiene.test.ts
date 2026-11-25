import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';

const read = (name: string): Promise<string> => readFile(new URL(`../${name}`, import.meta.url), 'utf8');
const lines = async (name: string): Promise<string[]> => (await read(name)).split('\n').map((l) => l.trim());
const repoRoot = new URL('..', import.meta.url).pathname;
const hasGit = existsSync(new URL('../.git', import.meta.url)) && spawnSync('git', ['--version']).status === 0;

describe('.gitignore keeps secrets and audit data out of git', () => {
  it('lists the required patterns', async () => {
    const l = await lines('.gitignore');
    for (const entry of ['.env', '.env.*', '!.env.example', 'data/', '*.jsonl', 'secrets/', '*.bak', 'node_modules/']) {
      expect(l).toContain(entry);
    }
  });

  // Asks real git, so ordering mistakes like "!.env.example" before ".env.*" are caught too.
  it.skipIf(!hasGit).each([
    '.env',
    '.env.local',
    '.env.production',
    '.env.bak',
    'data/audit.jsonl',
    'audit.jsonl',
    'backup.jsonl',
    'secrets/audit_encryption_key',
    'server.key',
    'cert.pem',
  ])('git ignores %s', (file) => {
    expect(spawnSync('git', ['check-ignore', '-q', file], { cwd: repoRoot }).status).toBe(0);
  });

  it.skipIf(!hasGit)('git does NOT ignore .env.example', () => {
    expect(spawnSync('git', ['check-ignore', '-q', '.env.example'], { cwd: repoRoot }).status).toBe(1);
  });
});

describe('.dockerignore keeps secrets out of the image', () => {
  it('lists the required patterns and still allows .env.example', async () => {
    const l = await lines('.dockerignore');
    for (const entry of ['.env', '.env.*', '!.env.example', 'secrets/', 'data/', '*.jsonl', '.git/', 'node_modules/']) {
      expect(l).toContain(entry);
    }
  });
});

describe('.env.example', () => {
  it('contains no real key and documents every variable the config reads', async () => {
    const text = await read('.env.example');
    expect(text).toMatch(/^AUDIT_ENCRYPTION_KEY=$/m);
    expect(text).not.toMatch(/[A-Za-z0-9+/]{43}=/); // no 32-byte base64 value anywhere
    for (const v of [
      'AUDIT_ENCRYPTION_KEY_FILE',
      'AUDIT_FILE_PATH',
      'AUDIT_MAX_FILE_BYTES',
      'PORT',
      'RATE_LIMIT_MAX',
      'RATE_LIMIT_WINDOW_MS',
      'PROVIDER_DELAY_MS',
      'PROVIDER_TIMEOUT_MS',
      'PROVIDER_MAX_CONCURRENCY',
      'BREAKER_FAILURE_THRESHOLD',
      'BREAKER_COOLDOWN_MS',
      'PROVIDER_FAIL_FIRST_N',
    ]) {
      expect(text).toContain(v);
    }
  });
});

// compose.yaml is not present in every context (e.g. a stripped build), so skip rather than fail.
describe.skipIf(!existsSync(new URL('../compose.yaml', import.meta.url)))('compose.yaml', () => {
  it('publishes the port on loopback only', async () => {
    const text = await read('compose.yaml');
    expect(text).toMatch(/-\s*"127\.0\.0\.1:3000:3000"/);
    expect(text).not.toMatch(/-\s*"?3000:3000"?\s*$/m);
    expect(text).not.toMatch(/0\.0\.0\.0/);
  });

  it('passes the encryption key as a Docker secret file, never as an environment value', async () => {
    const text = await read('compose.yaml');
    expect(text).toContain('AUDIT_ENCRYPTION_KEY_FILE: /run/secrets/audit_encryption_key');
    expect(text).toMatch(/secrets:\s*\n\s*audit_encryption_key:\s*\n\s*file: \.\/secrets\/audit_encryption_key/);
    expect(text).not.toMatch(/^\s*AUDIT_ENCRYPTION_KEY:/m);
  });

  it('runs hardened: read-only fs, no capabilities, no-new-privileges', async () => {
    const text = await read('compose.yaml');
    expect(text).toContain('read_only: true');
    expect(text).toContain('cap_drop:');
    expect(text).toContain('no-new-privileges:true');
  });
});

describe.skipIf(!existsSync(new URL('../Dockerfile', import.meta.url)))('Dockerfile', () => {
  it('pins the base image by digest and runs as a non-root user', async () => {
    const text = await read('Dockerfile');
    expect(text).toMatch(/^ARG NODE_IMAGE=node:\d+-alpine@sha256:[0-9a-f]{64}$/m);
    expect(text).toMatch(/^USER node$/m);
    expect(text).not.toMatch(/^ENV .*AUDIT_ENCRYPTION_KEY/m);
  });
});
