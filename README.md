# Guardian Integration Gateway

A small Express + TypeScript service that sits between clients and an (external) AI provider. It accepts a message, **redacts PII before anything leaves the service**, calls a mock AI provider behind a **circuit breaker**, and writes an **audit record** containing the *encrypted* original and the *plaintext redacted* message.

## 1. Overview and architecture

```
POST /secure-inquiry { userId, message }
        │
        ▼
 ┌───────────────┐   400/413/415 on bad input
 │ Zod validation │──────────────────────────► (never touches the breaker)
 └──────┬────────┘
        ▼
 ┌───────────────┐   emails, credit cards (Luhn), SSNs / 9-digit runs
 │   redactor    │
 └──────┬────────┘
        ▼
 ┌───────────────┐  OPEN ──► 503 "Service Busy" immediately (provider not called)
 │ circuit breaker│
 └──────┬────────┘
        ▼  redacted text ONLY
 ┌───────────────┐  2 s delay, "Generated Answer" (or simulated failure / timeout)
 │ mock AI        │
 └──────┬────────┘
        ▼
 ┌───────────────┐  AES-256-GCM(original) + redacted text + status → data/audit.jsonl
 │  audit log     │  (write failure ⇒ generic 500; no answer without an audit trail)
 └──────┬────────┘
        ▼
   JSON response { requestId, status, answer | error }
```

| Module | Responsibility |
|---|---|
| `src/redactor.ts` | Pure PII redaction (email > credit card > SSN priority, no overlapping redactions) |
| `src/crypto.ts` | AES-256-GCM encrypt/decrypt, key loading and validation |
| `src/auditStore.ts` | Serialized append-only audit log (JSON Lines) |
| `src/circuitBreaker.ts` | `CLOSED` / `OPEN` / `HALF_OPEN` state machine |
| `src/aiProvider.ts` | Mock provider, deterministic failure simulation, timeout wrapper |
| `src/config.ts` | Zod-validated environment, fails fast without echoing values |
| `src/routes/secureInquiry.ts`, `src/app.ts`, `src/server.ts` | HTTP layer, error handling, entry point |

Tech: Node.js, Express 5, TypeScript, Zod, built-in `crypto`, Vitest + Supertest, Docker.

## 2. Installation and Docker commands

### Docker (recommended)

```bash
# 1. Create your local, git-ignored .env and generate an encryption key
cp .env.example .env
sed -i.bak "s|^AUDIT_ENCRYPTION_KEY=.*|AUDIT_ENCRYPTION_KEY=$(openssl rand -base64 32)|" .env && rm .env.bak

# 2. Build and start (the container runs as a non-root user with a read-only filesystem)
docker compose up -d --build

# 3. Check health, logs, stop
curl -s localhost:3000/health
docker compose logs -f app
docker compose down          # keeps the audit volume
docker compose down -v       # also deletes the audit volume
```

Audit data lives in the named volume `audit-data` (mounted at `/app/data`), not in the image or the repo. To look at it:

```bash
docker compose exec app cat /app/data/audit.jsonl
```

### Local (no Docker)

Requires Node.js 20+ (verified on Node 24 in the container and Node 26 locally).

```bash
npm ci
cp .env.example .env     # then set AUDIT_ENCRYPTION_KEY as above
npm run dev              # watch mode, loads .env
# or
npm run build && npm start
```

## 3. Environment variables

Copy `.env.example` to `.env`. **Never commit `.env`** (it is in `.gitignore` and `.dockerignore`).

| Variable | Default | Description |
|---|---|---|
| `AUDIT_ENCRYPTION_KEY` | *(required)* | 32 random bytes, base64. Generate: `openssl rand -base64 32`. The service refuses to start if it is missing or malformed; the error never prints the value. |
| `AUDIT_FILE_PATH` | `data/audit.jsonl` | Audit file (fixed to `/app/data/audit.jsonl` in Docker). |
| `PORT` | `3000` | Listen port. |
| `NODE_ENV` | `development` | `production` disables failure simulation. |
| `PROVIDER_DELAY_MS` | `2000` | Mock AI latency. |
| `PROVIDER_TIMEOUT_MS` | `5000` | A provider call slower than this counts as a failure. |
| `BREAKER_FAILURE_THRESHOLD` | `3` | Consecutive provider failures that open the breaker. |
| `BREAKER_COOLDOWN_MS` | `10000` | Time the breaker stays `OPEN` before allowing one probe. |
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
| Body > 16 KB | 413 | `error: "Payload Too Large"` |
| Not `application/json` | 415 | `error: "Unsupported Media Type"` |
| Provider failed or timed out | 503 | `{ requestId, status: "failed", error: "Service Unavailable" }` |
| Breaker `OPEN` (or probe in flight) | 503 | `{ requestId, status: "breaker_open", error: "Service Busy" }` + `Retry-After` |
| Audit write / unexpected error | 500 | `{ requestId, status: "error", error: "Internal Server Error" }` |

Validation: `userId` matches `^[A-Za-z0-9_.:-]{1,64}$`; `message` is 1–4000 characters; unknown fields are rejected.

## 5. Trigger three consecutive failures

Failure simulation is controlled by the **server environment only**. There is deliberately no header or payload a client can use to trip it.

```bash
# in .env
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
# -> HTTP 503 in 0.00xs
```

Observed in the Docker run: failures took 2.07 s / 2.02 s / 2.02 s; the fourth and fifth requests returned in about 8 ms.
The server log shows `"breakerState":"OPEN"` and `"providerStatus":"breaker_open"` for these requests.

## 7. How HALF_OPEN recovery works

```
CLOSED --3 consecutive failures--> OPEN --cooldown elapsed--> HALF_OPEN
HALF_OPEN --probe succeeds--> CLOSED
HALF_OPEN --probe fails-----> OPEN (new cooldown)
```

1. **OPEN:** every request gets `503 Service Busy` instantly. The cooldown (`BREAKER_COOLDOWN_MS`, default 10 s) is measured from the moment the breaker opened.
2. **After the cooldown**, the *next* request becomes the single **probe** and is sent to the provider (state `HALF_OPEN`). While the probe is in flight, every other request still gets `Service Busy`. The "is a probe running?" check and claiming the probe slot happen in one synchronous step, so concurrent requests cannot start duplicate probes (covered by unit and integration tests).
3. **Probe succeeds** → `CLOSED`, counters reset, normal traffic resumes. **Probe fails** → `OPEN` again with a fresh cooldown.
4. Results from requests that started *before* the last state change are ignored, so a slow old request cannot close an open breaker or re-open a recovered one.
5. Only provider failures and timeouts count. Validation errors (400/413/415) never reach the breaker, and audit-write problems do not count either.

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

- Emails; credit cards of 13–19 digits (spaces or hyphens allowed) that pass the **Luhn** check; SSNs as `ddd-dd-dddd` or any standalone 9-digit run.
- Priority is email > card > SSN. A lower-priority candidate that overlaps a higher one is dropped, so nothing is half-redacted.
- Matching is done on an NFKC-normalized view (full-width digits, zero-width characters), but only the matched spans are replaced in the original string. Unrelated text is returned unchanged.

**Only the redacted text is sent to the AI provider.** The provider function has no access to the original.

**Encryption** (`src/crypto.ts`): AES-256-GCM, 32-byte key from `AUDIT_ENCRYPTION_KEY`, a fresh random 12-byte IV per message, 16-byte auth tag stored with the ciphertext. The `requestId` is bound in as AAD, so a ciphertext cannot be moved onto another record. Decryption errors are a single fixed message (no oracle).

**Audit log** (`src/auditStore.ts`): one JSON object per line in `AUDIT_FILE_PATH` (JSON Lines), file mode `0600`.

```json
{
  "requestId": "6c0f…",
  "userId": "user-123",
  "timestamp": "2026-11-25T21:47:31.070Z",
  "providerStatus": "success | failed | breaker_open",
  "redactedMessage": "Hello <REDACTED: EMAIL>, card <REDACTED: CREDIT_CARD>, ssn <REDACTED: SSN>",
  "encryptedOriginalMessage": { "alg": "aes-256-gcm", "keyVersion": 1, "iv": "…", "tag": "…", "ciphertext": "…" }
}
```

- **Concurrency:** all writes go through one promise queue, so at most one append is in flight and records land in call order. A failed write rejects only its own request; later writes still work.
- **Write errors** become a generic `500` (the error carries only an errno code, never a path or content). The service fails closed: no answer is returned without an audit record.
- **Logging:** structured JSON lines with request id, status, breaker state, redaction *counts* and timing. Message text, `userId`, keys and underlying error messages are never logged.
- **Decrypting** is intentionally not exposed by the API or any CLI. `decrypt()` exists for tests (`tests/crypto.test.ts`, `tests/auditStore.test.ts` show the round trip with the authorized key and that a wrong key, wrong `requestId` or any tampering fails).
- Audit files are git-ignored (`data/`) and excluded from the Docker build context.

## 9. Running the tests

```bash
npm test                              # 175 tests, ~1 s, no network, no real 2 s sleeps
npm run typecheck
docker build --target test .          # runs the suite inside the Node 24 image
```

Coverage by area: `tests/redactor.test.ts` (PII patterns, overlaps, Unicode evasion, adversarial performance), `crypto.test.ts` and `auditStore.test.ts` (encryption, tampering, persistence, concurrent writes, write failures), `circuitBreaker.test.ts` (all transitions, single probe, stale results), `aiProvider.test.ts`, `config.test.ts`, and `secureInquiry.test.ts` (Supertest: success, invalid input, redaction, provider failures, breaker fallback and recovery, audit failure, leak checks). Time is injected, so breaker tests are deterministic.

### Verification performed (2026-11-25)

- `npm test`: 175/175 passed locally (Node 26); `tsc --noEmit` clean.
- `docker build --target test .`: 175/175 passed in `node:24-alpine`.
- `docker compose up`: container reported `healthy`; ran as user `node`; writes outside the data volume failed (`Read-only file system`); audit file mode `-rw-------`.
- End-to-end through the container: 3 failures (~2 s each), instant `Service Busy` for requests 4–5 (~8 ms), `400` for invalid input, probe after the 10 s cooldown succeeded (`200`) and normal traffic resumed. The audit file had 7 records (`failed`×3, `breaker_open`×2, `success`×2) and **0** occurrences of the raw email, card number or SSN.
- Not verified: Linux-host volume permissions, multi-instance behaviour, load/latency testing.

## 10. AI tools used and human review

**AI tool:** Claude Code (Anthropic CLI, Claude Sonnet 5.5) worked as a pair-programming partner under the rules in `CLAUDE.md` (design first, approval before coding, one component at a time, tests with each component). Every prompt and its outcome is recorded in [`PROMPTS.md`](PROMPTS.md).

**Decisions made by the human engineer** (all in `PROMPTS.md`):

- Approved the architecture and assumptions: global breaker, audit written for failures too, fail-closed audit, JSON Lines format, env-driven failure simulation.
- Chose **HTTP 503 `Service Unavailable`** (not 502) for a single provider failure.
- Required **Luhn validation** for credit cards and that unrelated text stays unchanged (overriding the AI's initial "no Luhn" recommendation).
- Defined the audit record fields and the response schema, and the order in which components were built.

**Corrections made during AI-assisted development** (found by running tests or reviewing): an SSN directly followed by a card was mis-redacted (fixed with SSN "barrier" groups); `@types/node` was not picked up under TypeScript 7; the Docker test stage initially lacked `.gitignore` / `.env.example`, which two hygiene tests read.

**Engineer sign-off checklist** (to be completed by the human before submission):

- [ ] Reviewed `src/redactor.ts` patterns and the Luhn / 9-digit trade-offs
- [ ] Reviewed `src/crypto.ts` and `src/auditStore.ts` (IV handling, AAD, error messages)
- [ ] Reviewed `src/circuitBreaker.ts` state transitions and concurrency reasoning
- [ ] Reviewed error handling in `src/app.ts` for data leaks
- [ ] Ran `npm test` and the Docker demo themselves
- [ ] Confirmed no `.env` or audit data is committed

## 11. Known limitations and production improvements

**Redaction**
- Pattern-based only: no names, addresses, phone numbers or obfuscated forms ("john at x dot com", spelled-out digits). A real deployment would add an NER / DLP layer.
- Luhn means a mistyped card number (or a non-Luhn card-like number) is **not** redacted.
- Any standalone 9-digit number is redacted as an SSN (false positives such as order IDs). Digit runs of 10–12 or 20+ digits, and 9 digits inside longer runs, are left alone.
- A card with an extra 4-digit group glued before it (`1111 4111 1111 1111 1111`) can be partially redacted when the wrong window passes Luhn (~1 in 10).
- `userId` is stored in plaintext in the audit log and may itself be personal data.

**Circuit breaker and provider**
- State is in memory and per process: multiple instances each have their own breaker. Production needs shared state or per-instance tuning.
- One global breaker for a single provider; no per-user or per-model isolation, no half-open probe budget greater than one, no metrics export.
- The provider is a mock; retries, backoff, jitter and cancellation of timed-out calls are not implemented.

**Audit and keys**
- The audit "database" is an append-only local file: no rotation, size limit, retention policy, indexing or integrity chain. Production should use a real datastore with access controls.
- A single static key (`keyVersion: 1`): no rotation, no KMS/HSM, key is held in process memory. Losing or rotating the key makes old records unreadable.
- No decryption tooling or access-controlled review workflow.
- The audit write happens *after* the provider call, so a crash in between loses the record for that request; failing closed also means a disk problem returns `500` even when the breaker is open.

**Service**
- No authentication, authorization, rate limiting or TLS (expect a gateway or ingress in front). Without rate limiting, the open breaker still performs an audit write per request.
- Graceful shutdown only stops accepting connections; there is no in-flight draining deadline.
- No CI pipeline, image scanning or SBOM; the base image is pinned by major version, not by digest.
