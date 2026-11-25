# Guardian Integration Gateway

A small Express + TypeScript service that sits between clients and an (external) AI provider. It accepts a message, **redacts PII before anything leaves the service**, calls a mock AI provider behind a **circuit breaker**, and writes an **audit record** containing the *encrypted* original and the *plaintext redacted* message.

## 1. Overview and architecture

```
POST /secure-inquiry { userId, message }
        │
        ▼
 ┌────────────────┐  429 when a client exceeds its rate limit
 │  rate limiter   │
 └──────┬─────────┘
        ▼
 ┌────────────────┐  400 / 413 / 415 on bad input
 │ Zod validation  │──────────────────────────► (never touches the breaker)
 └──────┬─────────┘
        ▼
 ┌────────────────┐  emails (incl. Unicode), credit cards (Luhn), SSNs / 9-digit runs
 │    redactor     │
 └──────┬─────────┘
        ▼
 ┌────────────────┐  OPEN ──► 503 "Service Busy" immediately (provider not called)
 │ circuit breaker │  too many calls in flight ──► 503 "Service Busy" immediately
 └──────┬─────────┘
        ▼  redacted text ONLY (+ AbortSignal)
 ┌────────────────┐  2 s delay, "Generated Answer" (or simulated failure / timeout)
 │    mock AI      │
 └──────┬─────────┘
        ▼
 ┌────────────────┐  AES-256-GCM(original) + redacted text + status → audit.jsonl (fsync'ed)
 │   audit log     │  (write failure ⇒ 500, queue full ⇒ 503; no answer without an audit trail)
 └──────┬─────────┘
        ▼
   JSON response { requestId, status, answer | error }
```

| Module | Responsibility |
|---|---|
| `src/redactor.ts` | Pure PII redaction (email > credit card > SSN priority, no overlapping or partial redactions) |
| `src/crypto.ts` | AES-256-GCM `encrypt` and key loading/validation (there is no `decrypt` in the service) |
| `src/auditStore.ts` | Serialized, bounded, append-only audit log (JSON Lines) with every field authenticated |
| `src/circuitBreaker.ts` | `CLOSED` / `OPEN` / `HALF_OPEN`, single probe, concurrency cap, per-call timeout, monotonic clock |
| `src/aiProvider.ts` | Mock provider and deterministic failure simulation (honours `AbortSignal`) |
| `src/rateLimit.ts` | Per-client fixed-window rate limiter |
| `src/config.ts` | Zod-validated environment (or secret file), fails fast without echoing values |
| `src/routes/secureInquiry.ts`, `src/app.ts` | HTTP layer, error handling, security headers |
| `src/bootstrap.ts`, `src/server.ts` | Wiring from config, slow-client protections, graceful shutdown |

Tech: Node.js, Express 5, TypeScript, Zod, built-in `crypto`, Vitest + Supertest, Docker.

## 2. Installation and Docker commands

### Docker (recommended)

```bash
# 1. Create the encryption key as a git-ignored secret FILE (not an environment variable)
mkdir -p secrets
openssl rand -base64 32 > secrets/audit_encryption_key
chmod 600 secrets/audit_encryption_key

# 2. Optional: non-secret tunables (never put the key in this file when using Docker secrets)
cp .env.example .env        # then delete the AUDIT_ENCRYPTION_KEY= line, or leave it empty

# 3. Build and start (non-root user, read-only filesystem, all capabilities dropped)
docker compose up -d --build

# 4. Check health, logs, stop
curl -s localhost:3000/health
docker compose logs -f app
docker compose down          # keeps the audit volume
docker compose down -v       # also deletes the audit volume
```

Notes:

- The port is published on **127.0.0.1 only**. The API has no authentication; put a gateway with auth and TLS in front before exposing it.
- The key is mounted at `/run/secrets/audit_encryption_key` and read at startup through `AUDIT_ENCRYPTION_KEY_FILE`. It does **not** appear in `docker compose config`, `docker inspect` or the container environment. Setting both `AUDIT_ENCRYPTION_KEY` and the `_FILE` variant is a startup error.
- **Linux hosts:** the container user is uid 1000, and compose mounts the file with its host permissions. Make the secret readable by that uid (for example `sudo chown 1000 secrets/audit_encryption_key`). Docker Desktop (macOS/Windows), which is what this was verified on, does not enforce this.
- The image defaults to `NODE_ENV=production`, which **refuses failure simulation**. To run the demos in sections 5–7, set `NODE_ENV=development` in `.env`.

Audit data lives in the named volume `audit-data` (mounted at `/app/data`), not in the image or the repo:

```bash
docker compose exec app cat /app/data/audit.jsonl
```

### Local (no Docker)

Requires Node.js 20+ (verified on Node 24 in the container and Node 26 locally).

```bash
npm ci
cp .env.example .env     # set AUDIT_ENCRYPTION_KEY=$(openssl rand -base64 32), or AUDIT_ENCRYPTION_KEY_FILE
npm run dev              # watch mode, loads .env
# or
npm run build && npm start
```

## 3. Environment variables

Copy `.env.example` to `.env`. **Never commit `.env`** (every `.env*` file except `.env.example` is git-ignored and docker-ignored). Numeric variables must be plain digits; an **empty or blank value falls back to the default** (it never silently becomes `0`).

| Variable | Default | Description |
|---|---|---|
| `AUDIT_ENCRYPTION_KEY` *or* `AUDIT_ENCRYPTION_KEY_FILE` | *(one required)* | 32 random bytes, base64 (`openssl rand -base64 32`). Low-entropy keys (all zeros, repeating patterns) are rejected. The service refuses to start if the key is missing or malformed; errors never print the value. |
| `AUDIT_FILE_PATH` | `data/audit.jsonl` | Audit file (fixed to `/app/data/audit.jsonl` in Docker). |
| `AUDIT_MAX_FILE_BYTES` | `104857600` | Audit writes are rejected once the file reaches this size (no rotation). |
| `PORT` | `3000` | Listen port (1–65535). |
| `NODE_ENV` | `development` | `production` disables failure simulation. |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS` | `300` / `60000` | Per-client-IP limit on `POST /secure-inquiry`. `0` disables. |
| `PROVIDER_DELAY_MS` | `2000` | Mock AI latency. |
| `PROVIDER_TIMEOUT_MS` | `5000` | A provider call slower than this is aborted and counts as a failure. |
| `PROVIDER_MAX_CONCURRENCY` | `50` | Max provider calls in flight; extra requests get `503 Service Busy` instantly. |
| `BREAKER_FAILURE_THRESHOLD` | `3` | Consecutive provider failures that open the breaker. |
| `BREAKER_COOLDOWN_MS` | `10000` | Time the breaker stays `OPEN` before allowing one probe (minimum 1). |
| `PROVIDER_FAIL_FIRST_N` | `0` | Demo switch: the first N provider calls fail, then calls succeed. `0` = off. Refused at startup when `NODE_ENV=production`. |

## 4. Example requests

```bash
# Success (takes ~2 s because of the mock AI delay)
curl -s -X POST localhost:3000/secure-inquiry \
  -H 'content-type: application/json' \
  -d '{"userId":"user-123","message":"Hello john@example.com, card 4111 1111 1111 1111, ssn 123-45-6789"}'
# {"requestId":"…","status":"success","answer":"Generated Answer"}

# Invalid input -> 400, lists field names only (never echoes values)
curl -s -X POST localhost:3000/secure-inquiry -H 'content-type: application/json' -d '{"userId":"u"}'
# {"requestId":"…","status":"invalid_request","error":"Invalid request","fields":["message"]}
```

| Situation | HTTP | Body |
|---|---|---|
| OK | 200 | `{ requestId, status: "success", answer }` |
| Invalid body / malformed JSON | 400 | `{ requestId, status: "invalid_request", error, fields? }` |
| Wrong method (e.g. `GET /secure-inquiry`) | 405 | `Allow: POST` |
| Body > 16 KB | 413 | `error: "Payload Too Large"` |
| Not `application/json` (on `/secure-inquiry`) | 415 | `error: "Unsupported Media Type"` |
| Client over the rate limit | 429 | `{ status: "rate_limited" }` + `Retry-After` |
| Provider failed or timed out | 503 | `{ requestId, status: "failed", error: "Service Unavailable" }` |
| Breaker `OPEN` (or probe in flight) | 503 | `{ requestId, status: "breaker_open", error: "Service Busy" }` + `Retry-After` |
| Too many provider calls in flight, or audit queue full | 503 | `{ requestId, status: "overloaded", error: "Service Busy" }` + `Retry-After: 1` |
| Audit write failed / file full / unexpected error | 500 | `{ requestId, status: "error", error: "Internal Server Error" }` |

Validation: `userId` matches `^[A-Za-z0-9_.:-]{1,64}$` **and must not itself contain PII** (an SSN- or card-shaped id is rejected, because `userId` is stored in plaintext); `message` is 1–4000 characters, not blank, with no control characters (other than tab/newline) and no lone surrogates; unknown fields are rejected. All responses carry `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and a locked-down CSP.

## 5. Trigger three consecutive failures

Failure simulation is controlled by the **server environment only**. There is deliberately no header or payload a client can use to trip it.

```bash
# in .env  (NODE_ENV=development is required: the image defaults to production)
NODE_ENV=development
PROVIDER_FAIL_FIRST_N=3

docker compose up -d --force-recreate     # restart so the counter and breaker start fresh
```

Send the same request three times. Each one fails after the full mock delay (~2 s):

```bash
for i in 1 2 3; do
  curl -s -w '  -> HTTP %{http_code} in %{time_total}s\n' -X POST localhost:3000/secure-inquiry \
    -H 'content-type: application/json' -d '{"userId":"user-123","message":"hello john@example.com"}'
done
# {"…","status":"failed","error":"Service Unavailable"}  -> HTTP 503 in 2.0xs   (x3)
```

The third failure opens the breaker.

## 6. Observe the immediate fallback

Immediately after the third failure, send another request. It returns right away and the provider is **not called**:

```bash
curl -si -w '\n-> HTTP %{http_code} in %{time_total}s\n' -X POST localhost:3000/secure-inquiry \
  -H 'content-type: application/json' -d '{"userId":"user-123","message":"hello"}'
# HTTP/1.1 503 Service Unavailable
# Retry-After: 10
# {"requestId":"…","status":"breaker_open","error":"Service Busy"}
# -> HTTP 503 in 0.0xs
```

Observed in the Docker run: failures took 2.05 s / 2.03 s / 2.05 s; the fourth request returned in about 18 ms.
The server log shows `"breakerState":"OPEN"` and `"providerStatus":"breaker_open"` for these requests.

## 7. How HALF_OPEN recovery works

```
CLOSED --3 consecutive failures--> OPEN --cooldown elapsed--> HALF_OPEN
HALF_OPEN --probe succeeds--> CLOSED
HALF_OPEN --probe fails-----> OPEN (new cooldown)
```

1. **OPEN:** every request gets `503 Service Busy` instantly. The cooldown (`BREAKER_COOLDOWN_MS`, default 10 s) is measured from the moment the breaker opened, on a **monotonic clock**, so wall-clock changes cannot shorten or extend it.
2. **After the cooldown**, the *next* request becomes the single **probe** and is sent to the provider (state `HALF_OPEN`). While the probe is in flight, every other request still gets `Service Busy`. The "is a probe running?" check and claiming the probe slot happen in one synchronous step, so concurrent requests cannot start duplicate probes (covered by unit and integration tests).
3. **Probe succeeds** → `CLOSED`, counters reset, normal traffic resumes. **Probe fails** → `OPEN` again with a fresh cooldown.
4. **A probe can never hang forever:** every provider call is aborted (via `AbortSignal`) and counted as a failure after `PROVIDER_TIMEOUT_MS`, so the breaker cannot get stuck in `HALF_OPEN`.
5. Results from requests that started *before* the last state change are ignored, so a slow old request cannot close an open breaker or re-open a recovered one.
6. Failures are only counted when calls *finish*, so a burst could otherwise put hundreds of calls in flight before the breaker trips. `PROVIDER_MAX_CONCURRENCY` caps calls in flight; extra requests get `503 Service Busy` (status `overloaded`) immediately. Being busy is not counted as a provider failure.
7. Only provider failures and timeouts count. Validation errors (400/413/415) never reach the breaker, and audit-write problems do not count either.

Demo (continuing from section 6): wait for the cooldown, then send a request. With `PROVIDER_FAIL_FIRST_N=3` the probe is the 4th provider call, so it succeeds:

```bash
sleep 11
curl -s -w '  -> HTTP %{http_code} in %{time_total}s\n' -X POST localhost:3000/secure-inquiry \
  -H 'content-type: application/json' -d '{"userId":"user-123","message":"hello"}'
# {"…","status":"success","answer":"Generated Answer"}  -> HTTP 200 in 2.0xs
```

To demo a **failed probe** instead, use `PROVIDER_FAIL_FIRST_N=4`: the probe fails, the breaker re-opens, and the next probe after another cooldown succeeds.

## 8. PII redaction, encryption and audit logs

**Redaction** (`src/redactor.ts`) replaces matches with `<REDACTED: EMAIL>`, `<REDACTED: CREDIT_CARD>` and `<REDACTED: SSN>`:

- **Emails:** RFC 5322 local-part characters plus Unicode letters and digits (`josé@exämple.com`, `o'brien@…`), IDN and punycode domains, IP-literal domains (`john@[192.168.0.1]`). The whole local part is always redacted, never just its tail.
- **Credit cards:** 13–19 digits in whole groups that pass the **Luhn** check. Separators: spaces, newlines/tabs, `.`, `-`, `/` and Unicode dashes (up to two in a row).
- **SSNs:** `ddd-dd-dddd` (same separator set, one consistent separator) or any standalone 9-digit run.
- **Normalization:** matching runs on a folded view: NFKC, zero-width characters removed, non-ASCII decimal digits (Arabic-Indic, Devanagari, Thai, mathematical digits…) mapped to ASCII, and ideographic full stops mapped to `.`. Only the matched spans are replaced in the original string; unrelated text comes back unchanged.
- **Priority:** email > card > SSN. A lower-priority candidate that overlaps a higher one is dropped, and SSN-shaped groups cannot be absorbed into a card window, so nothing is half-redacted.

**Only the redacted text is sent to the AI provider.** The provider function has no access to the original.

**Encryption** (`src/crypto.ts`): AES-256-GCM, 32-byte key, a fresh random 12-byte IV per message, 16-byte auth tag stored with the ciphertext. The GCM **AAD covers every other field of the record** (`requestId`, `userId`, `timestamp`, `providerStatus`, `redactedMessage`, key version), so editing any stored field, or moving a ciphertext onto another record, makes decryption fail for anyone holding the key. The service never decrypts anything and has no `decrypt` function; tests use an independent implementation in `tests/helpers/crypto.ts`.

**Audit log** (`src/auditStore.ts`): one JSON object per line in `AUDIT_FILE_PATH` (JSON Lines), file mode `0600` (tightened if the file already existed).

```json
{
  "requestId": "6c0f…",
  "userId": "user-123",
  "timestamp": "2026-11-25T21:47:31.070Z",
  "providerStatus": "success | failed | breaker_open | overloaded",
  "redactedMessage": "Hello <REDACTED: EMAIL>, card <REDACTED: CREDIT_CARD>, ssn <REDACTED: SSN>",
  "encryptedOriginalMessage": { "alg": "aes-256-gcm", "keyVersion": 1, "iv": "…", "tag": "…", "ciphertext": "…" }
}
```

- **Concurrency:** all writes go through one promise queue, so at most one append is in flight and records land in call order. A failed write rejects only its own request. This protects one process; several processes appending to one file are not coordinated.
- **Torn lines:** the store checks the file's last byte before its first write and after any failed write, and starts a new line if needed, so a partial record can never swallow the next good one. Readers should skip lines that fail to parse.
- **Durability and resilience:** each record is `fsync`ed before the request is acknowledged; a deleted audit directory is recreated automatically.
- **Backpressure:** at most 1000 writes may be pending (`503 overloaded` beyond that), and the file is capped by `AUDIT_MAX_FILE_BYTES` (`500` beyond that). There is no rotation.
- **Write errors** become a generic error carrying only an errno-style code (never a path or content). The service fails closed: no answer is returned without an audit record.
- **Logging:** structured JSON lines with request id, status, breaker state, redaction *counts* and timing. Message text, `userId`, keys and underlying error messages are never logged.
- Audit files are git-ignored (`data/`, `*.jsonl`) and excluded from the Docker build context.

## 9. Running the tests

```bash
npm test                              # 325 tests, ~2 s, no network, no real 2 s sleeps
npm run typecheck
docker build --target test .          # runs the suite inside the pinned Node 24 image
```

Coverage by area: `redactor.test.ts` (PII patterns, overlaps, Unicode and separator evasion, adversarial performance), `crypto.test.ts` and `auditStore.test.ts` (encryption, tampering of every field, torn lines, backpressure, concurrent writes, write failures, self-healing), `circuitBreaker.test.ts` (all transitions, single probe, stale results, concurrency cap, timeouts, monotonic clock), `aiProvider.test.ts`, `rateLimit.test.ts`, `config.test.ts` (blank/malformed values, secret files), `bootstrap.test.ts` (real wiring over HTTP, server timeouts), `repoHygiene.test.ts` (git/docker ignore rules via real `git check-ignore`, compose and Dockerfile hardening), and `secureInquiry.test.ts` (Supertest: success, invalid input, redaction, provider failures, breaker fallback and recovery, overload, audit failure, leak checks). Time is injected, so breaker tests are deterministic.

A GitHub Actions workflow (`.github/workflows/ci.yml`) runs typecheck, tests, `npm audit`, the Docker test stage and secret/port assertions on the image and compose config. **It has not been executed yet.**

### Verification performed (2026-11-25)

- `npm test`: 325/325 passed locally (Node 26); `tsc --noEmit` clean; `npm run build` OK; `npm audit --omit=dev`: 0 vulnerabilities.
- `docker build --target test .`: 314 passed in the pinned `node:24-alpine` image; the 11 tests that need the `git` binary are skipped there.
- `docker compose up` with a secret-file key: container `healthy`, published as `127.0.0.1:3000`, key absent from `docker inspect` and the container environment and from `docker compose config`, audit file mode `-rw-------`.
- End to end through the container, with inputs that used to bypass redaction (`josé@exämple.com`, `4111.1111.1111.1111`, `123.45.6789`): all redacted; the audit file contained 0 raw occurrences. Three failures (~2 s each), the 4th request `Service Busy` in ~18 ms, `userId: "123-45-6789"` rejected with 400, `GET /secure-inquiry` answered 405 with security headers, and the probe after the cooldown succeeded.
- Not verified: Linux-host secret-file permissions, multi-instance behaviour, load testing, the CI workflow.

## 10. AI tools used and human review

**AI tool:** Claude Code (Anthropic CLI, Claude Sonnet 5.5) worked as a pair-programming partner under the rules in `CLAUDE.md` (design first, approval before coding, tests with each component). Every prompt and its outcome is recorded in [`PROMPTS.md`](PROMPTS.md).

**Decisions made by the human engineer** (all in `PROMPTS.md`):

- Approved the architecture and assumptions: global breaker, audit written for failures too, fail-closed audit, JSON Lines format, env-driven failure simulation.
- Chose **HTTP 503 `Service Unavailable`** (not 502) for a single provider failure.
- Required **Luhn validation** for credit cards and that unrelated text stays unchanged (overriding the AI's initial "no Luhn" recommendation).
- Defined the audit record fields and the response schema, and the order in which components were built.
- Commissioned an adversarial security review and then instructed that all 19 findings be fixed.

**Security review:** a second pass in the role of a skeptical application-security engineer produced 19 findings (2 High, 10 Medium, 7 Low; none Critical). Most were reproduced with throwaway scripts before being fixed. Highlights: non-ASCII emails and dotted or newline-separated cards/SSNs bypassed redaction; `userId` could carry PII into plaintext storage; a torn audit line could swallow the next record; audit fields other than the ciphertext were not authenticated; compose leaked the key through `docker compose config` and published the port on all interfaces; empty env vars silently became `0`. Each fix has a regression test (the `review #n` blocks in the test files).

**Other corrections made during AI-assisted development** (found by running tests or reviewing): an SSN directly followed by a card was mis-redacted (fixed with SSN "barrier" groups); `@types/node` was not picked up under TypeScript 7; the Docker test stage initially lacked files that hygiene tests read; the container refused to start when failure simulation was combined with the production default (working as designed, now documented).

**Engineer sign-off checklist** (to be completed by the human before submission):

- [ ] Reviewed `src/redactor.ts` patterns and the Luhn / 9-digit trade-offs
- [ ] Reviewed `src/crypto.ts` and `src/auditStore.ts` (IV handling, AAD, framing, error messages)
- [ ] Reviewed `src/circuitBreaker.ts` state transitions, bulkhead and concurrency reasoning
- [ ] Reviewed error handling in `src/app.ts` for data leaks
- [ ] Reviewed `compose.yaml` / `Dockerfile` (secret handling, loopback binding)
- [ ] Ran `npm test` and the Docker demo themselves
- [ ] Confirmed no `.env`, `secrets/` or audit data is committed

## 11. Known limitations and production improvements

**Redaction**
- Pattern-based only: no names, addresses, phone numbers or obfuscated forms ("john at x dot com", spelled-out digits, text between digit groups). A real deployment would add an NER / DLP layer.
- Luhn means a mistyped card number (or a non-Luhn card-like number) is **not** redacted.
- Any standalone 9-digit number is redacted as an SSN (false positives such as order IDs), and with `.` `/` newline as separators more look-alikes match: an IPv4-like `1234.5678.9012.3456` or a date pair can be redacted as a card when it passes Luhn. Digit runs of 10–12 or 20+ digits, and 9 digits inside longer runs, are left alone.
- A card with an extra 4-digit group glued before it (`1111 4111 1111 1111 1111`) can be partially redacted when the wrong window passes Luhn (~1 in 10).
- `userId` values that look like PII (including a plain 9-digit id) are rejected rather than stored; clients must use non-numeric or shorter identifiers.

**Circuit breaker, provider and limits**
- Breaker state, the concurrency cap and the rate limiter are in memory and per process: with several instances each has its own. Production needs shared state or per-instance tuning. Behind a proxy, configure Express `trust proxy`, otherwise all clients share one rate-limit bucket.
- One global breaker for a single provider; no per-user isolation, no probe budget greater than one, no metrics export.
- The provider is a mock; retries, backoff and jitter are not implemented.

**Audit and keys**
- The audit "database" is an append-only local file: no rotation, retention policy, indexing or hash chain. Records are tamper-*evident* only to someone holding the key; an attacker with file access can still delete or truncate records. Production should use a real datastore with access controls.
- Multiple processes must not share one audit file.
- A single static key (`keyVersion: 1`): no rotation tooling, no KMS/HSM, the key is held in process memory. Random 96-bit IVs are safe for roughly 2^32 messages per key, so plan rotation for busy deployments. Losing the key makes old records unreadable.
- There is no decryption tooling or access-controlled review workflow.
- The audit write happens *after* the provider call, so a crash in between loses the record for that request. Failing closed also means a full or failing disk returns an error even when the breaker is open.

**Service and delivery**
- No authentication, authorization or TLS (expect a gateway or ingress in front); the compose port is loopback-only for that reason.
- Docker secret files keep the host file's permissions, which on Linux must be readable by uid 1000.
- Graceful shutdown stops accepting connections and force-exits after 10 s; there is no in-flight draining beyond that.
- The CI workflow has not been run; image vulnerability scanning and an SBOM are not set up. The base image is pinned by digest and must be updated deliberately.
