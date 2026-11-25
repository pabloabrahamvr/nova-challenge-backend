# Prompt Log

A running record of the prompts given to the AI assistant (Claude Code) during the Guardian Integration Gateway assessment, and what each produced. New entries are appended in order.

---

## Prompt 1: Assessment requirements + design-first request

**Prompt (verbatim):**

> 1. The Endpoint:
> POST /secure-inquiry
> . Accepts a JSON body:
> { userId: string, message: string }
>
> 2. The Logic:
> ◦ Step 1 (Sanitization): Use AI to generate a robust sanitizer that strips emails, credit cards, and SSNs (Social security Numbers or 9 numeric digits) from
> message and replaces them with
> <REDACTED: TYPE>.
>
> ◦ Step 2 (Mock AI Call): Simulate an external AI call (use a setTimeout of 2 seconds) that returns a "Generated Answer."
>
> ◦ Step 3 (Audit Log): Write the original message (encrypted) and the redacted message (plaintext) to a mock database (a JSON file is fine).
>
> 3. The Twist: The system must include a "Circuit Breaker." If the Mock AI Call fails 3 times in a row, the API should instantly return a fallback message ("Service Busy") without waiting for the timeout.
>
> Review the complete assessment requirements.
>
> Before coding:
> 1. Propose the minimum architecture and modules.
> 2. Explain the request lifecycle.
> 3. Identify security risks and edge cases.
> 4. Define the circuit breaker state transitions.
> 5. Identify ambiguities and propose reasonable assumptions.
> 6. Outline the tests needed for each requirement.
>
> Keep the design simple enough to complete and demonstrate in 4–6 hours.
>
> Do not write implementation code yet.

**Outcome:** Design proposal only, with no code. It covered:
- module layout
- request lifecycle
- breaker state machine (CLOSED / OPEN / HALF_OPEN, single probe, epoch guard for stale results)
- env-driven failure simulation (`PROVIDER_FAIL_FIRST_N`)
- security risks and edge cases
- assumptions table
- per-requirement test plan
- a ~5h estimate

**Open decisions raised (awaiting human answer):**
1. Approve assumptions 1–5 (esp. #1 single-failure status code, #5 JSONL audit format).
2. NFKC normalization before redaction (recommended: yes).
3. Luhn validation on cards (recommended: no).
4. Start with the redactor component.

---

## Prompt 2: Keep a prompt log

**Prompt (verbatim):**

> keep a log for prompt

**Outcome:** Created this file. Each future prompt and its outcome will be appended here.

---

## Prompt 3: Answers to open decisions

**Prompt (verbatim):**

> 1. Assumptions are correct, 2. should return 503 Service Unavailable, 3. approve, 4. yes

**Interpretation applied (stated to the human for correction):**
- Assumptions 1–5 approved, **except** a single provider failure returns **503 Service Unavailable** (not 502). Breaker-open still returns 503 `Service Busy`; the two are told apart by body text.
- NFKC normalization: yes. Luhn: no (fail safe).
- Start with the redactor.

**Outcome:** Scaffolded project (package.json, tsconfig, .gitignore, deps) and implemented `src/redactor.ts` with `tests/redactor.test.ts`. Ran `vitest` and `tsc --noEmit`: tests pass, typecheck clean.

---

## Prompt 4: Encryption and audit logging modules

**Prompt (verbatim):**

> Implement the encryption and audit logging modules.
>
> Use AES-256-GCM with:
> - A 32-byte key provided through an environment variable
> - A new random 12-byte IV for every encryption
> - Authentication tag stored alongside ciphertext
> - A decrypt function used only in tests
>
> Audit records should include:
> - requestId
> - userId
> - encryptedOriginalMessage
> - redactedMessage
> - timestamp
> - providerStatus
>
> Persist to a JSON file for this assessment.
>
> Requirements:
> - Never log plaintext original messages.
> - Do not expose encryption keys.
> - Prevent accidentally committing audit files.
> - Handle JSON file write errors explicitly.
> - Define how concurrent writes are serialized.
> - Demonstrate that encrypted messages can be decrypted correctly with the authorized key.
>
> Write tests for encryption, decryption, tampering, and audit persistence.
>
> Do not implement the circuit breaker yet.

**Outcome:** Added `src/crypto.ts`, `src/auditStore.ts`, `.env.example`, `tests/crypto.test.ts`, `tests/auditStore.test.ts`. Fixed `tsconfig.json` (`"types": ["node"]`, required by TypeScript 7). Ran `vitest` (71 tests pass across 3 files) and `tsc --noEmit` (clean).
