---
name: star-sec
description: >-
  Star Sec Auditor performs authorized, defensive application security audits and secure code reviews of full-stack
  web apps, APIs, and services. Use this skill whenever the user asks for a security audit, AppSec review, secure code
  review, web app pentest (defensive), vulnerability assessment, threat model, hardening review, OWASP Top 10 / API
  Security Top 10 check, dependency/supply-chain audit, secret scanning, Docker/CI/CD/cloud config review, or a final
  security report with prioritized findings. Trigger it for prompts like "audit this app", "review auth/payments/
  webhooks/uploads for vulnerabilities", "find security issues in frontend and backend", "is this code secure",
  "harden this repo", or "produce an AppSec report". It works across React/Next/Vue/Angular frontends and Node/Python/
  Go/Rust/PHP/Ruby/Java/.NET backends with SQL/NoSQL/ORM databases, Docker, and CI/CD. Defensive only: it never
  exploits third-party systems, never exfiltrates secrets, and runs dynamic tests only against authorized localhost/
  staging targets. Do NOT trigger for purely legal/privacy compliance (LGPD/GDPR), general non-security coding, or
  feature development with no security framing.
---

# Star Sec Auditor

A reusable, international **defensive** application-security skill. It drives a complete, authorized audit of a
codebase — frontend, backend, APIs, database, infrastructure, Docker, and CI/CD — and produces evidence-backed,
prioritized findings plus executive and technical reports.

This skill is an **orchestrator**. Keep this file in context; load the detailed `references/` only when a phase
needs them. Run the `scripts/` to automate repetitive recon, inventory, dependency, secret, and reporting work.

> **Scope of guarantees.** No audit proves the absence of vulnerabilities. Always state limitations, assumptions, and
> coverage gaps. Never claim a system is "100% secure". Prioritize *exploitable* risk and *real* business impact.

---

## When to use this skill

Use it when the user wants any of:

- A security audit / AppSec review / secure code review of a repo or full-stack app.
- A defensive web-app pentest or vulnerability assessment of code they are authorized to test.
- A threat model, attack-surface map, or architecture security review.
- An auth / authorization / session / token / payment / webhook / upload / multi-tenant / realtime review.
- A dependency / supply-chain / secrets / Docker / CI/CD / cloud-config security review.
- A prioritized, evidence-backed security report (executive + technical).

## When NOT to use this skill

- Legal/privacy **compliance** work (LGPD, GDPR, contracts, DPA, ROPA) — this skill is technical security only.
- General coding, refactors, or feature work with no security framing.
- Any request to attack, scan, or exploit systems the user is **not authorized** to test.
- Offensive tradecraft: weaponized exploits, malware, C2, DoS, mass scanning, or detection-evasion for misuse.

---

## Operating principles (read first)

1. **Authorized & defensive only.** Assume the user owns or is contracted to test the target. If anything implies an
   unauthorized third-party target, stop and ask. Never produce destructive or weaponized PoCs.
2. **Do no harm.** Read code freely. Do not modify the project by default. Do not delete data, run migrations, or
   mutate state. Dynamic tests run only against authorized `localhost`/staging.
3. **Protect secrets.** Never print full secrets/tokens/keys/PII in output or reports. Mask them
   (`AKIA…REDACTED`, `sk_live_…1234`). Never exfiltrate anything over the network.
4. **No global installs without consent.** Prefer `npx`, `uvx`, `pipx run`, Docker, or already-installed tools. If a
   tool is missing, record it as `not available` and continue with manual review — never block the audit.
5. **Evidence over alarm.** Every finding cites file:line / route / function and explains *real* impact and
   preconditions. Separate Confirmed vs Probable vs Suspected vs Informational. Avoid hype.
6. **Best-effort under uncertainty.** If scope is incomplete, proceed with what the repos reveal and document gaps.

---

## Standard audit workflow

Work through the phases in order. Track them as todos. Each phase says which `references/` and `scripts/` to use.
Save all machine output under `reports/` (create it if missing) — never inside the project's source tree.

### Phase 0 — Authorization & Scope Guard
- Confirm the user is authorized to audit the target. If a remote/production/third-party target is implied for
  dynamic testing, get explicit confirmation of scope before any runtime action.
- Capture scope: repos + branch, app type, stack, environments (localhost/staging), authorized URLs, and critical
  areas (auth, payments, admin, multi-tenant, integrations). Missing details → proceed best-effort and note gaps.
- Record an **out-of-scope** list. Never touch anything on it.

### Phase 1 — Repository Recon
- Map repo structure, languages, frameworks, package managers, entrypoints, routes/controllers, middleware, models,
  migrations, auth, payments, webhooks, workers, Docker, CI/CD, and infra.
- Run `scripts/repo_recon.py <path> --out reports/recon.json` for a deterministic stack/file inventory.
- Produce an **attack-surface inventory**.

### Phase 2 — Architecture & Data-Flow Review
- Identify trust boundaries, critical assets, and sensitive flows: login, session, refresh tokens, permissions,
  payment confirmation, file upload, webhooks, financial data, admin, external integrations, queues, callbacks,
  exports.
- Write a concise threat model (assets → entry points → trust boundaries → threats → existing mitigations).
- See `references/methodology.md` (Architecture & Threat Modeling).

### Phase 3 — Automated Baseline Checks
- Run available tooling **non-destructively**; record missing tools as `not available`.
  - Dependencies: `npm/pnpm/yarn audit`, `pip-audit`, `safety`, `cargo audit`, `bundler-audit`, `osv-scanner`,
    `govulncheck`.
  - SAST: `semgrep`, `bandit`, `gosec`, ESLint security plugins.
  - Secrets: `gitleaks`, `trufflehog`.
  - Containers/IaC: `trivy`, `hadolint`, `checkov`, `docker scout`.
  - DAST (only if authorized, Phase 5): `zap-baseline`.
- Helpers: `scripts/dependency_audit_helper.py` (suggests/runs only safe, available commands) and
  `scripts/secret_scan_helper.py` (local, masked secret patterns). Both write to `reports/raw/`.

### Phase 4 — Manual Secure Code Review
The core phase. Use `references/secure-review-playbooks.md` for step-by-step playbooks and
`references/stack-specific-checklists.md` for your stack. Run `scripts/security_inventory.py <path>
--out reports/inventory.json` to locate routes, middleware, auth/admin/webhook/upload/payment handlers first.

Cover at minimum:
- **Identity:** authentication, authorization (RBAC/ABAC), session management, token handling (JWT/refresh),
  password reset, OAuth/OIDC, MFA/TOTP.
- **Web/browser:** CSRF, CORS, XSS, CSP, security headers, unsafe redirects, clickjacking.
- **Injection:** SQL/NoSQL/ORM injection, command injection, SSRF, path traversal, template/LDAP injection.
- **Data handling:** file upload, insecure deserialization, prototype pollution, ReDoS, mass assignment.
- **Access control:** IDOR/BOLA, function-level authz, admin routes, internal/diagnostics endpoints.
- **Abuse resistance:** rate limiting, brute-force protection, replay attacks, race conditions.
- **Money & integrations:** webhook signature verification, payment confirmation, **idempotency**, replay safety.
- **Secrets & config:** secrets exposure, env vars, error handling/stack traces, debug modes, feature flags.
- **Platform:** Docker hardening, CI/CD secrets, supply-chain & dependency-confusion risks, TLS assumptions.
- **Topology:** multi-tenant isolation, cache isolation, queue/worker trust boundaries, realtime/SSE/WebSocket
  security, API versioning/deprecation, backup/export/import security, observability endpoints.
- **AI/LLM features (if present):** prompt injection, tool/agent abuse, data leakage, output handling.

Taxonomy and CWE/OWASP mapping: `references/vulnerability-taxonomy.md`.

### Phase 5 — DAST / Runtime Testing (only if authorized)
- Only against authorized `localhost`/staging. Never production without explicit scope.
- Boot the app locally if feasible; exercise routes with **non-destructive** requests. Use ZAP baseline or careful
  manual tests. No aggressive fuzzing, no DoS, no data destruction.
- Capture relevant request/response evidence with secrets/tokens masked.

### Phase 6 — Risk Validation
For each candidate finding: confirm file/line/function/route, explain real impact + preconditions + a defensive
exploitation scenario, classify severity, and de-duplicate. Bucket as **Confirmed / Probable / Suspected /
Informational**. Drop false positives or mark them `Needs Validation`. See `references/severity-model.md` and
`references/evidence-guidelines.md`.

### Phase 7 — Remediation Planning
For each issue: recommended fix, likely files to change, suggested tests + a security regression test, and priority
(**P0/P1/P2/P3**). Separate **quick wins** from **structural hardening**. See
`references/reporting-guide.md` and `templates/remediation-plan-template.md`.

### Phase 8 — Final Report
Assemble the report from `templates/`:
- `templates/executive-report-template.md` — for founders/CTOs/stakeholders.
- `templates/technical-report-template.md` — for engineers (detailed findings + evidence + fixes + tests).
- `templates/finding-template.md` — one block per finding.
- `templates/remediation-plan-template.md` — 24h / 7d / 30d / 90d roadmap + CI/CD gates + monitoring.

Use `scripts/report_builder.py --findings reports/findings/ --out reports/final-security-report.md` to assemble a
severity-ordered report (works with partial data). Report sections: Executive Summary, Scope, Methodology, Security
Posture, Attack Surface, Findings by Severity, Confirmed Vulnerabilities, Suspected Risks, Dependency/Tooling
Results, Secrets/Config Review, Architecture Risks, Remediation Roadmap, Quick Wins, Evidence Appendix, Suggested
Security Backlog, and Suggested CI/CD Security Gates.

---

## Working with multiple repositories

- Audit each repo with Phases 1–4, then reconcile a **cross-repo threat model** (e.g., frontend trust assumptions vs
  backend enforcement, shared auth, webhook producers/consumers).
- Watch the seams: token issuance vs validation, CORS vs cookie scope, client-trusted values the server must re-check,
  and shared secrets/queues. Many real bugs live *between* services, not inside one.
- Keep one consolidated `reports/` with a per-repo prefix on finding IDs (e.g., `WEB-001`, `API-014`).

## Prioritizing findings

Order by **exploitability × impact × exposure**, adjusted for existing mitigations and confidence. A Confirmed,
unauthenticated, internet-exposed RCE outranks a theoretical, authenticated, low-impact issue. Lead the report with
what an attacker would actually do first. Severity and priority rubric: `references/severity-model.md`.

## Producing evidence (and avoiding false positives)

- Cite `path:line`, function, and route. Prefer minimal static snippets; mask secrets/PII.
- Distinguish **static** (code), **dynamic** (observed at runtime), and **inferred** evidence — label which.
- Before reporting, check for compensating controls (a global middleware, a validation layer, a WAF assumption) that
  may neutralize the issue. If unsure, mark **Suspected / Needs Validation** rather than overstating.
- Full guidance: `references/evidence-guidelines.md`.

---

## Reference & asset map

| File | Use it for |
|---|---|
| `references/methodology.md` | End-to-end methodology, threat modeling, audit checklist per phase. |
| `references/vulnerability-taxonomy.md` | OWASP Web/API Top 10, CWE mapping, full category catalog. |
| `references/stack-specific-checklists.md` | Per-framework/DB/infra checklists (frontend, backend, DB, infra). |
| `references/secure-review-playbooks.md` | Step-by-step review playbooks (auth, payments, uploads, etc.). |
| `references/severity-model.md` | Severity, priority (P0–P3), confidence, and status definitions. |
| `references/evidence-guidelines.md` | Collecting evidence, masking secrets, safe PoCs, reducing FPs. |
| `references/reporting-guide.md` | How to assemble the final report and write good findings. |
| `templates/*` | Executive, technical, finding, and remediation-plan templates. |
| `scripts/repo_recon.py` | Detect stack, package managers, Docker/CI, entrypoints → JSON inventory. |
| `scripts/security_inventory.py` | Locate routes/middleware/auth/admin/webhook/upload/payment handlers → JSON. |
| `scripts/dependency_audit_helper.py` | Detect package managers, run only safe available audit commands. |
| `scripts/secret_scan_helper.py` | Local masked secret detection with confidence scoring. |
| `scripts/report_builder.py` | Merge finding files into a severity-ordered final report. |
| `examples/` | A sample finding and a sample final report to model tone and depth. |

All scripts are Python 3, support `--help`, are network-free, and do not modify the target project by default.
