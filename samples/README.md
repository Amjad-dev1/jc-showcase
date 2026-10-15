# Code Samples

Real files from the private production codebase, kept at their original paths.
Comments that referenced internal specification documents have been trimmed; the
code itself is unchanged. Imports point to modules that are not included here, so
these files are meant to be read, not built.

## Suggested reading order

**1. The request boundary**
- [`src/proxy.ts`](src/proxy.ts): every request passes through here first. Admin
  subtree guard and CSRF `Origin` check.
- [`src/lib/server/http.ts`](src/lib/server/http.ts): the wrapper every route handler
  uses, which guarantees only the error envelope ever leaves the server.
- [`src/lib/shared/errors.ts`](src/lib/shared/errors.ts): the fixed error contract.

**2. Authentication and authorization**
- [`src/lib/server/auth/password.ts`](src/lib/server/auth/password.ts): Argon2id,
  legacy hash compatibility, timing equalisation.
- [`src/lib/server/auth/config.ts`](src/lib/server/auth/config.ts): Auth.js
  credentials provider and session callbacks.
- [`src/lib/server/auth/guards.ts`](src/lib/server/auth/guards.ts): `requireAdmin()`.
- [`src/app/api/admin/auth/change-password/route.ts`](src/app/api/admin/auth/change-password/route.ts):
  what a guarded admin route looks like.

**3. The payment flow**
- [`src/lib/server/services/payment-service.ts`](src/lib/server/services/payment-service.ts):
  session creation, verification, idempotent finalization.
- [`src/lib/server/integrations/checkout-token.ts`](src/lib/server/integrations/checkout-token.ts):
  HMAC signed, expiring callback token with constant time comparison.
- [`src/lib/server/integrations/mpgs.ts`](src/lib/server/integrations/mpgs.ts):
  gateway client and the `SUCCESS` + `CAPTURED` state mapping.

**4. Abuse prevention**
- [`src/lib/server/ratelimit.ts`](src/lib/server/ratelimit.ts): sliding window limits
  with explicit failure modes.
- [`src/lib/server/integrations/turnstile.ts`](src/lib/server/integrations/turnstile.ts):
  fail closed bot verification with hostname binding.
- [`src/app/api/public/registrations/check-email/route.ts`](src/app/api/public/registrations/check-email/route.ts):
  an enumeration oracle, and how it is throttled.
- [`src/lib/shared/schemas/public.ts`](src/lib/shared/schemas/public.ts): shared Zod
  schemas and why `orderId` is absent.

**5. Data protection**
- [`src/lib/server/logger.ts`](src/lib/server/logger.ts): structural PII redaction.
- [`src/lib/server/repositories/errors.ts`](src/lib/server/repositories/errors.ts):
  PostgreSQL errors mapped by constraint name.
- [`next.config.ts`](next.config.ts): CSP and security headers.

**6. Proof**
- [`tests/unit/security.test.ts`](tests/unit/security.test.ts)
- [`tests/unit/password.test.ts`](tests/unit/password.test.ts)
- [`tests/integration/payments.test.ts`](tests/integration/payments.test.ts)
