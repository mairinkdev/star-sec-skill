# Secure Review Playbooks

Step-by-step playbooks for reviewing the highest-risk areas. Each playbook lists where to look, what to verify, the
common failure modes, and how to confirm safely. Use them in Phase 4; pair with
`references/stack-specific-checklists.md` and `references/vulnerability-taxonomy.md`.

## Table of contents
- [1. Authentication](#1-authentication)
- [2. Authorization](#2-authorization)
- [3. Payments & Webhooks](#3-payments--webhooks)
- [4. File Upload](#4-file-upload)
- [5. Admin Panels](#5-admin-panels)
- [6. APIs](#6-apis)
- [7. Frontend Security](#7-frontend-security)
- [8. Docker & CI/CD](#8-docker--cicd)
- [9. Secrets & Environment Variables](#9-secrets--environment-variables)
- [10. Multi-Tenant Apps](#10-multi-tenant-apps)
- [11. Realtime (WebSocket / SSE)](#11-realtime-websocket--sse)
- [12. AI / LLM Features](#12-ai--llm-features)
- [13. Background Jobs / Workers](#13-background-jobs--workers)

---

## 1. Authentication

**Where:** login, signup, logout, password reset, session/token issuance, OAuth/OIDC callbacks, MFA.

**Verify:**
- Passwords hashed with bcrypt/scrypt/argon2 (never MD5/SHA-1/plain). Per-user salt automatic.
- Login is rate-limited and protected against credential stuffing; no user enumeration (uniform responses + timing).
- Sessions: strong random IDs, rotated on login/privilege change, expiry + idle timeout, server-side invalidation on
  logout.
- Cookies: `HttpOnly`, `Secure`, `SameSite` appropriate; scoped path/domain.
- **JWT:** signature verified, algorithm pinned (no `none`, no HS/RS confusion), `exp`/`nbf`/`aud`/`iss` checked, secret
  strong and server-side only.
- **Refresh tokens:** short-lived access tokens, refresh rotation, reuse detection, server-side revocation.
- **Password reset:** single-use, time-limited, unpredictable tokens; reset link host not derived from a spoofable
  `Host` header; no token leakage via Referer.
- **OAuth/OIDC:** `state` + PKCE present; redirect URIs allowlisted; tokens validated; scopes minimal.
- **MFA/TOTP:** enforced where claimed; OTP single-use with replay protection; backup codes hashed.

**Common failures:** plaintext/weak hashing, missing lockout, JWT `alg:none`, long-lived non-revocable tokens,
reset-link host poisoning, MFA bypass by skipping the second step.

**Confirm safely:** read the verification code path; with test accounts on staging, try a wrong-then-right sequence to
observe lockout, or inspect a decoded (non-secret) JWT header for `alg`.

---

## 2. Authorization

**Where:** every route/handler that reads or changes data; middleware/guards; admin/privileged functions.

**Verify (the core question: "whose data, and who's asking?"):**
- Every object access is **scoped to the caller** (ownership/tenant), not just "is logged in". This catches IDOR/BOLA.
- Function-level checks exist for privileged actions (BFLA) — not just hidden in the UI.
- Authorization is enforced **server-side at the data layer**, not only in client routing or by obscurity.
- Role/permission checks are centralized and consistently applied (look for handlers that forgot the guard).
- No reliance on client-supplied role/tenant/user IDs for the decision.

**Common failures:** `findById(req.params.id)` with no ownership check; admin action gated only by a hidden UI button;
trusting `X-User-Id`/JWT claims that aren't verified; inconsistent guards across similar endpoints.

**Confirm safely:** as test user A, request user B's object by ID on staging; expect denial. Read the handler to see if
the `where` clause includes the caller's scope.

---

## 3. Payments & Webhooks

**Where:** checkout/payment intent creation, webhook receivers (Stripe/PayPal/etc.), order fulfillment, refunds.

**Verify:**
- **Webhook signature verification** is present and uses the raw body (not parsed/re-serialized) with the provider's
  secret. Not commented out, not behind a disabled flag.
- **Replay protection:** timestamp tolerance and/or event-ID dedup; old events rejected.
- **Idempotency:** fulfillment keyed by event/order ID so duplicates don't double-ship or double-credit.
- **Server-side truth:** amounts, currency, and payment status come from the provider/server, never trusted from the
  client. Prices computed server-side.
- Refund/credit flows authorize the actor and amount.

**Common failures:** trusting a client "paid=true" callback; missing/disabled signature check; no idempotency →
double fulfillment; price/amount taken from request body; success redirect treated as payment proof.

**Confirm safely:** read the webhook handler for signature verification and idempotency keys. Use provider **test
keys** and test events on staging; never trigger real charges.

---

## 4. File Upload

**Where:** upload endpoints, storage writes, file serving/download, image processing.

**Verify:**
- Type validation by content (magic bytes) not just extension/`Content-Type`; allowlist, not denylist.
- Size limits enforced; resource limits on processing (image bombs, zip bombs).
- Stored outside the web root or in object storage; filenames sanitized/randomized (no path traversal via `../` or
  null bytes).
- Served with safe `Content-Type`, `Content-Disposition: attachment` where appropriate, and not executed by the
  server.
- No SSRF via "import from URL" features; no overwrite of existing files; access-controlled retrieval.
- Image/doc parsers up to date (avoid known RCE in libraries).

**Common failures:** trusting client MIME, executable upload into a served dir, path traversal in filename, missing
size limits (DoS), SVG/HTML upload leading to stored XSS, URL-import SSRF.

**Confirm safely:** read the handler; on staging, upload a benign `.txt` renamed to a disallowed type to test
content-based validation; attempt a traversal filename and confirm rejection.

---

## 5. Admin Panels

**Where:** `/admin`, internal dashboards, impersonation, bulk actions, feature toggles.

**Verify:**
- Strong authentication + ideally MFA; not reachable by normal users; authorization enforced per action.
- Not exposed publicly without need (network/SSO/IP allowlist where appropriate).
- Impersonation is audited and tightly controlled; dangerous bulk actions require confirmation + logging.
- No debug/diagnostic features that leak data or allow arbitrary queries.
- Admin APIs have the same authz rigor as the UI.

**Common failures:** admin endpoints protected only by an unlinked URL; missing per-action checks; impersonation
without audit; verbose internal data exposed.

---

## 6. APIs

**Where:** REST/GraphQL/RPC endpoints, versioned routes, public vs internal APIs.

**Verify:**
- AuthN + per-object/per-function authorization on every endpoint (BOLA/BFLA).
- Input validation and output shaping (no excessive data exposure / over-posting / mass assignment).
- Rate limiting and resource limits (pagination caps, query cost limits for GraphQL).
- Consistent error handling (no stack traces, no internal IDs leaking inadvertently).
- API inventory: deprecated/old versions don't bypass new authz; no forgotten debug endpoints.
- GraphQL: introspection appropriate for environment; depth/complexity limits; field-level authz.

**Common failures:** BOLA on `/resource/:id`, returning full DB objects, no rate limits, shadow `/v1` endpoints lacking
fixes, GraphQL query bombs.

---

## 7. Frontend Security

**Where:** rendering of user content, navigation, storage, third-party scripts, build config.

**Verify:**
- No unsanitized raw-HTML sinks (`dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `bypassSecurityTrust*`).
- CSP meaningful; SRI on external scripts; no inline event handlers if CSP forbids.
- No secrets in the bundle; only public env vars exposed.
- No open redirects; `target=_blank` hardened; `postMessage` origins validated.
- Token storage decision deliberate (XSS → token theft risk understood).
- Client-side validation is UX-only; server enforces all rules.

**Common failures:** stored XSS via rich text, secret keys in `NEXT_PUBLIC_*`, open redirect via `?next=`, DOM XSS via
`location`/`hash` into `innerHTML`.

**Confirm safely:** search for the sinks above; on staging, inject a benign marker (`xss-probe-7f3`) and check whether
it executes or renders inert.

---

## 8. Docker & CI/CD

**Where:** `Dockerfile`, Compose/K8s manifests, CI workflow files, build scripts.

**Verify (Docker):** non-root user, pinned minimal base, multi-stage, no secrets in layers/`ENV`/args,
`.dockerignore` excludes secrets, resource limits, read-only FS where feasible.

**Verify (CI/CD):** action/image pinning (SHA, not `latest`), minimal token `permissions`, secrets never echoed,
untrusted PR code never runs with secrets (`pull_request_target` caution), no secrets in artifacts/logs, dependency &
image scanning in the pipeline.

**Common failures:** root containers, secrets baked into images, `pull_request_target` running fork code with secrets,
unpinned third-party actions, plaintext secrets in CI variables printed to logs.

**Confirm safely:** read the files; lint with `hadolint`/`checkov` if available (record `not available` otherwise).

---

## 9. Secrets & Environment Variables

**Where:** code, config, `.env`/examples, git history, client bundles, logs, CI config.

**Verify:**
- No hardcoded secrets/keys/passwords in code or committed config.
- `.env` not committed; only `.env.example` with placeholder values.
- Secrets sourced from a secret manager/platform store at runtime.
- No secrets in client bundles, logs, error messages, or URLs.
- Rotation possible; long-lived static credentials flagged.

**Common failures:** committed `.env`, API keys in source, secrets in git history, tokens logged on error, service
keys shipped to the browser.

**Confirm safely:** run `scripts/secret_scan_helper.py` (masked output) and `gitleaks` if available. Report
**location + type**, never the value; recommend rotation for any real exposure.

---

## 10. Multi-Tenant Apps

**Where:** tenant resolution, every data query, caches, queues, background jobs, per-tenant config.

**Verify:**
- Tenant identity derived from the authenticated session/token server-side — never from a client-supplied field
  used directly for scoping.
- Every query filters by tenant; no global queries that can cross tenants.
- Cache keys, rate-limit keys, and queue messages are tenant-scoped.
- Background jobs carry and enforce tenant context.
- Per-tenant secrets/config isolated; no bleed across tenants.

**Common failures:** cross-tenant IDOR via shared IDs, cache leakage from unscoped keys, jobs running without tenant
context, trusting `X-Tenant-Id` header.

**Confirm safely:** as tenant A on staging, attempt to access tenant B's object by ID; expect denial.

---

## 11. Realtime (WebSocket / SSE)

**Where:** WS/SSE handshake, message handlers, rooms/channels, broadcast logic.

**Verify:**
- Authentication on the WS/SSE connection itself (not just the page that opened it).
- **Origin validation** on the WebSocket upgrade (prevents Cross-Site WebSocket Hijacking).
- Per-message authorization; users only receive their own/authorized rooms; no cross-tenant broadcast.
- Rate/size limits on inbound messages; backpressure handling.

**Common failures:** unauthenticated sockets, missing origin check (CSWSH), broadcasting to wrong room/tenant, no
message limits (DoS).

---

## 12. AI / LLM Features

**Where:** prompt construction, tool/function calling, RAG/data ingestion, rendering of model output.

**Verify:**
- Untrusted content (user input, fetched pages, stored docs) can't override system instructions — treat it as data,
  not instructions (indirect prompt injection).
- Tools/agents that take privileged actions require independent authorization — model output alone never authorizes a
  sensitive action.
- No secrets/PII placed in prompts or logged; system prompts contain no credentials.
- Model output rendered safely (escaped; not injected as raw HTML → XSS).
- Cost/DoS limits on generation; SSRF guards on any URL-fetching tools.

**Common failures:** indirect prompt injection via retrieved content, model output triggering unguarded actions,
secrets in prompts/logs, rendering model HTML unsanitized.

---

## 13. Background Jobs / Workers

**Where:** queue producers/consumers, scheduled jobs, message payloads, retries.

**Verify:**
- Job payloads are validated and not blindly trusted (treat the queue as a trust boundary).
- Jobs enforce authorization/tenant context just like request handlers.
- Idempotency/retry-safety so re-delivery doesn't double-apply effects.
- No secrets in payloads/logs; dead-letter handling doesn't leak data.
- Resource limits so a poisoned/huge job can't exhaust workers.

**Common failures:** trusting queue messages as authenticated, jobs ignoring tenant scope, non-idempotent handlers
double-charging on retry, secrets serialized into payloads.
