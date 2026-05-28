# Stack-Specific Checklists

Targeted checks per technology. Jump to the sections matching the audited stack. These complement (not replace) the
playbooks in `references/secure-review-playbooks.md` and the taxonomy in `references/vulnerability-taxonomy.md`.

## Table of contents
- [Frontend](#frontend)
  - [React](#react) · [Next.js](#nextjs) · [Vue / Nuxt](#vue--nuxt) · [Angular](#angular) · [Static sites](#static-sites) · [SPA auth](#spa-auth) · [SSR / ISR / Server Actions](#ssr--isr--server-actions) · [Cross-cutting frontend](#cross-cutting-frontend)
- [Backend](#backend)
  - [Node.js (Express/Fastify/NestJS)](#nodejs-expressfastifynestjs) · [Python (FastAPI/Django/Flask)](#python-fastapidjangoflask) · [Rust (Axum/Actix/Rocket)](#rust-axumactixrocket) · [Go (Gin/Fiber/Chi)](#go-ginfiberchi) · [PHP (Laravel/Symfony)](#php-laravelsymfony) · [Ruby on Rails](#ruby-on-rails) · [Java (Spring)](#java-spring) · [.NET](#net)
- [Database & ORM](#database--orm)
- [Infrastructure & Platforms](#infrastructure--platforms)

---

## Frontend

### Cross-cutting frontend
- [ ] No secrets/API keys/tokens in client code or bundles. Only intentionally public keys are exposed.
- [ ] Build-time env vars: only public-prefixed vars reach the client (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`,
      `PUBLIC_`). No private keys leak through bundling.
- [ ] Output encoding everywhere; raw-HTML sinks audited (see framework specifics).
- [ ] CSP present and meaningful (no blanket `unsafe-inline`/`unsafe-eval`/`*`); SRI on third-party scripts.
- [ ] No open redirects from user-controlled `next`/`returnUrl`/`redirect` params.
- [ ] `target="_blank"` links use `rel="noopener noreferrer"`.
- [ ] `postMessage` handlers validate `event.origin` and message shape.
- [ ] Auth tokens stored safely (prefer HttpOnly cookies over `localStorage`; understand the tradeoffs).
- [ ] Dependency risk: lockfile committed, no abandoned/typosquatted packages, audit clean.

### React
- [ ] `dangerouslySetInnerHTML` only with sanitized input (DOMPurify or equivalent).
- [ ] No user input flowing into `href`/`src` as `javascript:` URLs.
- [ ] No secrets in client state, context, or env vars exposed to the bundle.
- [ ] `ref`-based direct DOM writes (`innerHTML`) avoided or sanitized.

### Next.js
- [ ] **Server Actions / Route Handlers re-authorize every call** — never trust that the client only renders for
      authorized users. Each action checks auth + ownership server-side.
- [ ] `NEXT_PUBLIC_*` only for non-secret values; service keys stay server-only.
- [ ] No secret usage in components that can run on the client; data fetching that uses secrets stays server-side.
- [ ] `next.config` headers/redirects reviewed; no SSRF via `next/image` remote patterns or unvalidated image URLs.
- [ ] Middleware auth checks aren't the *only* control (they can be bypassed for some routes) — enforce in the
      handler/data layer too.
- [ ] API routes validate input and apply rate limiting where relevant.

### Vue / Nuxt
- [ ] `v-html` only with sanitized content.
- [ ] Nuxt `runtimeConfig`: `public` vs private split correct; secrets not in `public`.
- [ ] Server routes (`server/api`) re-authorize and validate input.

### Angular
- [ ] Avoid `bypassSecurityTrust*` unless input is fully trusted; document why if used.
- [ ] No direct DOM manipulation bypassing Angular's sanitizer.
- [ ] HttpInterceptors don't attach tokens to third-party/cross-origin requests inadvertently.

### Static sites
- [ ] No secrets in repo or built assets.
- [ ] Forms post to a trusted, validated backend; no client-only "validation as security".
- [ ] Security headers set at the host/CDN layer; `_headers`/config reviewed.

### SPA auth
- [ ] Token storage decision is deliberate; XSS impact understood (a stored token + XSS = account takeover).
- [ ] Silent refresh handled securely; refresh tokens rotated and revocable.
- [ ] Route guards are UX only — **all** authorization is enforced by the API.
- [ ] Logout clears tokens and invalidates server-side session where applicable.

### SSR / ISR / Server Actions
- [ ] Per-request authorization in server-rendered data fetches (no leaking another user's cached page).
- [ ] ISR/edge caches don't cache authenticated/personalized responses publicly.
- [ ] Server Actions validate input and check authorization (they are public endpoints).

---

## Backend

> Universal backend checks (apply to all): input validation at boundaries; authorization on every state change and
> object access; parameterized queries; rate limiting on sensitive endpoints; secrets from env/secret manager (not
> code); safe error handling (no stack traces to clients); secure logging (no secrets/PII); HTTPS/TLS assumptions
> documented.

### Node.js (Express/Fastify/NestJS)
- [ ] No `child_process` exec with user input; if unavoidable, use `execFile`/args arrays, never string concat.
- [ ] No `eval`/`Function`/`vm` on user input; no unsafe deserialization (`node-serialize`).
- [ ] Prototype pollution: safe object merge/clone; guard `__proto__`/`constructor`/`prototype` keys.
- [ ] ReDoS: review regexes applied to user input for catastrophic backtracking.
- [ ] Express: `helmet` (or explicit headers), CORS configured narrowly, body size limits, cookie flags
      (`HttpOnly`, `Secure`, `SameSite`).
- [ ] NestJS: Guards applied (not forgotten) on controllers; `ValidationPipe` with `whitelist`/`forbidNonWhitelisted`
      to prevent mass assignment; DTOs enforce types.
- [ ] Fastify: schema validation present; `@fastify/helmet`, rate-limit plugin.
- [ ] JWT verified with correct algorithm + secret; no `algorithms` left open to `none`.

### Python (FastAPI/Django/Flask)
- [ ] No `subprocess` with `shell=True` on user input; no `eval`/`exec`/`pickle.loads` on untrusted data.
- [ ] No `yaml.load` (use `safe_load`); no `jinja2` autoescape disabled for user content.
- [ ] SQL via ORM/parameterized; no f-string/`%`-built SQL.
- [ ] **Django:** `DEBUG=False` in prod, `ALLOWED_HOSTS` set, `SECRET_KEY` from env, CSRF middleware on, secure cookie
      settings, `SECURE_*` headers, admin not at default path/exposed, `@login_required`/permission mixins present,
      querysets scoped to the user (no `.objects.get(pk=...)` without ownership check).
- [ ] **FastAPI:** dependencies enforce auth on each route; Pydantic models prevent over-posting; CORS not wildcard
      with credentials.
- [ ] **Flask:** `SECRET_KEY` strong + from env; CSRF protection for forms; `debug=False` in prod; secure session
      cookie config.

### Rust (Axum/Actix/Rocket)
- [ ] `unsafe` blocks reviewed and justified; no memory-safety footguns introduced.
- [ ] SQLx/Diesel queries parameterized; no string-built SQL; `query!`/typed queries preferred.
- [ ] Extractors validate/limit body size; auth middleware/guards applied to protected routes.
- [ ] No secrets via `format!` into logs; error responses don't leak internals (`anyhow` chains to clients).
- [ ] CORS/headers configured (e.g., `tower-http` layers); panics don't expose stack info to clients.

### Go (Gin/Fiber/Chi)
- [ ] `database/sql`/`sqlx`/`gorm` use parameterized queries (`?`/named), never `fmt.Sprintf` into SQL.
- [ ] No `os/exec` with user input via shell; pass args explicitly.
- [ ] `html/template` (auto-escaping) for HTML, not `text/template`.
- [ ] Auth middleware applied to protected groups; context carries authenticated identity; ownership checks present.
- [ ] Request size limits; timeouts set on servers/clients (DoS hardening); `govulncheck` clean.

### PHP (Laravel/Symfony)
- [ ] No raw `DB::raw`/string-built SQL with user input; use query builder/Eloquent bindings.
- [ ] Mass assignment guarded (`$fillable`/`$guarded`); no `Model::unguard()`.
- [ ] Blade `{{ }}` (escaped) vs `{!! !!}` (raw) — raw only for trusted content.
- [ ] CSRF middleware enabled; `APP_DEBUG=false` in prod; `APP_KEY` set; storage/symlink and upload dirs not
      web-executable.
- [ ] No `unserialize` on user input; file upload validated (type, size, stored outside webroot).
- [ ] Symfony: security voters/firewall configured; `dev` front controller not deployed.

### Ruby on Rails
- [ ] Strong Parameters used everywhere (`params.require(...).permit(...)`) — no `permit!`.
- [ ] No string-interpolated SQL; use parameterized `where`/placeholders.
- [ ] `html_safe`/`raw` only on trusted content; ERB auto-escapes by default.
- [ ] CSRF protection on (`protect_from_forgery`); `force_ssl` where applicable; credentials in encrypted credentials,
      not code.
- [ ] No `Marshal.load`/unsafe YAML on user input; mass-assignment via nested attributes reviewed.
- [ ] Authorization (Pundit/CanCanCan) applied on actions and scoped queries.

### Java (Spring)
- [ ] Spring Security config reviewed: endpoints secured by default, method security (`@PreAuthorize`) present, CSRF
      handling appropriate for the app type.
- [ ] JPA/JDBC parameterized; no string-built JPQL/SQL.
- [ ] No unsafe deserialization (Java native, vulnerable Jackson polymorphic typing); SnakeYAML safe loading.
- [ ] Actuator endpoints secured/limited; no sensitive actuators exposed publicly.
- [ ] SSRF guards on URL fetchers; XXE disabled on XML parsers.

### .NET
- [ ] EF Core / parameterized ADO.NET; no string-built SQL.
- [ ] `[Authorize]` on controllers/actions; anti-forgery tokens for cookie-auth forms.
- [ ] No `BinaryFormatter`/insecure deserialization; safe JSON settings.
- [ ] Data Protection keys persisted securely; secrets in user-secrets/Key Vault, not `appsettings` in repo.
- [ ] Detailed errors disabled in prod; security headers configured.

---

## Database & ORM
- [ ] **PostgreSQL/MySQL:** least-privilege app user (not superuser/root); no broad `GRANT ALL`; TLS to DB; backups
      access-controlled; no secrets in connection strings committed to repo.
- [ ] **MongoDB:** auth enabled; not bound to `0.0.0.0` publicly; query operators from user input sanitized (NoSQL
      injection via `$where`/`$ne`); schema validation where possible.
- [ ] **Redis:** auth/`requirepass` set; not internet-exposed; dangerous commands restricted; used as cache/queue with
      tenant-scoped keys.
- [ ] **Prisma:** avoid `$queryRawUnsafe`/string-built raw SQL; use `$queryRaw` tagged templates; `select` to avoid
      over-exposure; ownership filters in `where`.
- [ ] **Drizzle:** use `sql` template parameterization; avoid manual string concatenation; scope queries by tenant/user.
- [ ] **TypeORM:** parameterized `QueryBuilder` (`:param`), not string concat; `find` conditions scoped; no
      `query(rawString)` with user input.
- [ ] **Sequelize:** use replacements/bind params; avoid `literal()` with user input; validate attributes (mass
      assignment).
- [ ] **SQLx (Rust):** compile-time `query!` or bound params; never format user input into SQL.
- [ ] **Diesel (Rust):** typed DSL / bound params; `sql_query` reviewed for injection.
- [ ] General: migrations don't embed secrets; no destructive migration auto-run in prod paths during audit.

---

## Infrastructure & Platforms
- [ ] **Docker:** non-root `USER`; minimal/pinned base image; multi-stage build; no secrets in layers/`ENV`/build
      args; `.dockerignore` excludes `.env`/keys; healthcheck; read-only FS where feasible. (Lint with `hadolint`.)
- [ ] **Docker Compose:** secrets via env files not committed; no host network unless required; ports bound to
      `127.0.0.1` for internal services; volumes scoped.
- [ ] **Kubernetes (basics):** no privileged/`hostPath` unless justified; `securityContext` (runAsNonRoot,
      drop capabilities, readOnlyRootFilesystem); resource limits; secrets via Secrets (not env in manifests committed);
      NetworkPolicies; RBAC least-privilege; no `:latest` images.
- [ ] **GitHub Actions:** pinned action SHAs; minimal `permissions:`; secrets not echoed; careful with
      `pull_request_target` + checkout of untrusted code; no secrets in artifacts/logs.
- [ ] **Vercel:** server-only env vars not exposed to client; functions enforce auth; preview deployments don't leak
      prod secrets; headers/redirects config reviewed; serverless functions validate input.
- [ ] **Railway / Render / Fly.io:** services not unintentionally public; env/secrets via platform store; internal
      services bound privately; healthchecks don't leak internals.
- [ ] **AWS/GCP/Azure (generic):** least-privilege IAM; no public buckets/blobs with sensitive data; SSRF protections
      (block metadata endpoint); secrets in secret manager; security groups/firewalls scoped; logging/audit enabled.
- [ ] **Cloudflare:** WAF/rate limiting where relevant; origin not directly reachable (bypassing WAF); secrets in
      Workers via bindings not code; access policies for admin tools.
- [ ] **Nginx / reverse proxies:** TLS config sane; security headers added; no path traversal via misconfig; upstream
      trust headers (`X-Forwarded-*`) handled correctly; no info leakage in error pages; request size/timeout limits.
