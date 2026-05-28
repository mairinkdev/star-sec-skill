# Methodology

The end-to-end methodology behind Star Sec Auditor. The `SKILL.md` summarizes the phases; this file expands each one
with concrete steps, what to look for, and how to keep the audit defensive and evidence-driven.

## Table of contents
- [Principles](#principles)
- [Phase 0 — Authorization & Scope Guard](#phase-0--authorization--scope-guard)
- [Phase 1 — Repository Recon](#phase-1--repository-recon)
- [Phase 2 — Architecture & Threat Modeling](#phase-2--architecture--threat-modeling)
- [Phase 3 — Automated Baseline Checks](#phase-3--automated-baseline-checks)
- [Phase 4 — Manual Secure Code Review](#phase-4--manual-secure-code-review)
- [Phase 5 — DAST / Runtime Testing](#phase-5--dast--runtime-testing)
- [Phase 6 — Risk Validation](#phase-6--risk-validation)
- [Phase 7 — Remediation Planning](#phase-7--remediation-planning)
- [Phase 8 — Final Report](#phase-8--final-report)
- [Audit limitations to always disclose](#audit-limitations-to-always-disclose)

---

## Principles

- **Authorized, defensive, non-destructive.** The goal is to find and explain risk so it can be fixed — not to break
  anything or to demonstrate offense against third parties.
- **Map before you dig.** Recon and architecture come before line-by-line review so effort lands on the real
  attack surface, not random files.
- **Trace data, not just code.** Most serious bugs are data-flow bugs: untrusted input reaching a dangerous sink, or
  a trust boundary where the server trusts a client-supplied value.
- **Confidence is a first-class attribute.** A guess and a proven bug are not the same; label them differently.
- **Coverage honesty.** Record what you reviewed, what you skipped, and why. An audit is a snapshot in time.

---

## Phase 0 — Authorization & Scope Guard

**Goal:** establish that the work is authorized and bound to a clear scope.

Steps:
1. Confirm authorization. The default assumption is that the user owns or is contracted to test the target. If the
   request implies a third-party/production target for *dynamic* testing, confirm scope explicitly before acting.
2. Capture scope into notes:
   - Repositories and branch/commit.
   - Application type (SaaS, API, mobile backend, admin panel, marketplace, etc.).
   - Stack (languages, frameworks, datastores, infra/hosting).
   - Environments available for dynamic testing (`localhost`, staging) and authorized URLs.
   - Critical areas the user cares about (auth, payments, multi-tenant, admin, integrations).
3. Write an explicit **out-of-scope** list (third-party APIs, production hosts, other tenants). Never touch it.
4. If details are missing, proceed best-effort from the code and **document the gaps** in the report.

Output: a short scope statement reused verbatim in the report's *Scope* section.

---

## Phase 1 — Repository Recon

**Goal:** build an accurate map of the codebase and an attack-surface inventory.

Steps:
1. Run `scripts/repo_recon.py <path> --out reports/recon.json` for a deterministic inventory of languages, package
   managers, frameworks, Docker/CI files, env examples, and likely entrypoints.
2. Read the top-level layout, build/run config, and the dependency manifests.
3. Locate and list:
   - Entrypoints (servers, CLIs, serverless handlers, workers, cron).
   - Routes/controllers, middleware, and route guards.
   - Data models, ORM schemas, migrations.
   - Auth code, session/token logic, permission checks.
   - Payment, webhook, upload, export/import, and integration handlers.
   - Background jobs/queues and realtime (WebSocket/SSE) endpoints.
   - Docker/Compose/K8s, CI/CD workflows, IaC, reverse-proxy config.
4. Run `scripts/security_inventory.py <path> --out reports/inventory.json` to find security-relevant handlers fast.

Output: an attack-surface inventory (entry points × trust level × sensitivity).

---

## Phase 2 — Architecture & Threat Modeling

**Goal:** understand trust boundaries and sensitive flows so review is targeted.

Steps:
1. **Identify assets:** credentials, sessions, PII, financial data, API keys, tenant data, admin capabilities,
   internal services.
2. **Map trust boundaries:** client↔server, service↔service, app↔datastore, app↔third party, public↔internal.
3. **Trace sensitive flows** end to end:
   - Login → session issuance → refresh → logout.
   - Authorization decisions (where is the check, what does it trust?).
   - Payment intent → confirmation → fulfillment (idempotency? replay?).
   - File upload → storage → retrieval/serving.
   - Webhook receipt → signature verification → state change.
   - Multi-tenant request → tenant resolution → data scoping.
4. **Lightweight threat model.** For each asset/flow note: entry points, threats (STRIDE is a fine lens), and existing
   mitigations. Mark where the server trusts client-supplied data — those are prime bug locations.

Output: a concise threat model and a ranked list of flows to review deeply in Phase 4.

---

## Phase 3 — Automated Baseline Checks

**Goal:** cheap, broad signal from tools — without breaking anything or installing globally.

Guidance:
- Prefer ephemeral runners: `npx <tool>`, `uvx <tool>`, `pipx run <tool>`, or Docker images. Use already-installed
  tools if present. **Never** install globally without consent.
- If a tool is missing, record it as `not available` in `reports/raw/` and continue. Tools augment manual review;
  they never gate the audit.
- Run everything read-only. No autofix, no writes to the project tree.

Tool families:
- **Dependencies / vulns:** `npm audit`, `pnpm audit`, `yarn audit`, `pip-audit`, `safety`, `cargo audit`,
  `bundler-audit`, `govulncheck`, `osv-scanner`.
- **SAST:** `semgrep` (with `p/owasp-top-ten`, `p/secrets`, language packs), `bandit` (Python), `gosec` (Go),
  ESLint security plugins (JS/TS).
- **Secrets:** `gitleaks`, `trufflehog` — plus `scripts/secret_scan_helper.py` for a local masked pass.
- **Containers / IaC:** `trivy`, `hadolint`, `checkov`, `docker scout`.
- **DAST (Phase 5 only, if authorized):** `zap-baseline`.

Helpers: `scripts/dependency_audit_helper.py` detects the package manager(s) and runs only safe, available audit
commands, saving raw output to `reports/raw/`.

Output: raw tool results plus a triaged shortlist (tools over-report; you confirm in Phase 4/6).

---

## Phase 4 — Manual Secure Code Review

**Goal:** the substance of the audit — confirm real issues by reading the code along the data flow.

Approach:
- Start from the ranked flows (Phase 2) and the security inventory (Phase 1).
- For each, trace untrusted input → transformations → dangerous sink, and verify the authorization decision at every
  state change.
- Use `references/secure-review-playbooks.md` for per-area steps and `references/stack-specific-checklists.md` for
  framework/DB/infra specifics. Map each issue to `references/vulnerability-taxonomy.md`.

Mandatory coverage (see the SKILL.md list): identity, web/browser, injection, data handling, access control, abuse
resistance, money & integrations, secrets & config, platform, topology, and AI/LLM features when present.

For each candidate issue, capture: location (`path:line`/route/function), the untrusted source, the sink, the missing
or weak control, and a first impact hypothesis. Defer final severity to Phase 6.

Output: a list of candidate findings with locations and evidence stubs.

---

## Phase 5 — DAST / Runtime Testing

**Goal:** confirm select findings dynamically — only where authorized and safe.

Rules:
- Authorized `localhost`/staging only. No production without explicit written scope.
- Non-destructive only: no data deletion, no aggressive fuzzing, no DoS, no spam to real third parties.
- Prefer a local boot of the app. Use ZAP baseline (passive) or targeted manual requests.
- Mask secrets/tokens in captured traffic. Use throwaway/test accounts and test payment keys.

Use it to validate things like access-control bypass (request another tenant's object with your own session),
missing rate limits (a small, bounded burst — not a flood), or reflected XSS (a benign marker payload). Record
request/response evidence with sensitive values masked.

Output: dynamic evidence that upgrades findings from Probable/Suspected to Confirmed.

---

## Phase 6 — Risk Validation

**Goal:** turn candidates into trustworthy findings.

For each candidate:
1. Re-confirm the location and that no compensating control neutralizes it (global middleware, validation layer,
   framework default, infra control).
2. Write the **real impact**, **preconditions**, and a **defensive exploitation scenario** (what an attacker achieves,
   not a weaponized payload).
3. Assign severity, priority, and confidence per `references/severity-model.md`.
4. De-duplicate (same root cause across many files = one finding with multiple locations).
5. Bucket: **Confirmed / Probable / Suspected / Informational**. Demote or drop false positives.

Output: validated, de-duplicated findings ready for remediation planning.

---

## Phase 7 — Remediation Planning

**Goal:** make every finding actionable.

For each finding provide:
- The recommended fix (concept + concrete approach for this stack).
- Likely files/functions to change.
- Suggested tests, including a **security regression test** that would fail on the vulnerable code and pass once fixed.
- Priority (P0–P3) and whether it's a **quick win** or **structural hardening**.

Then assemble a roadmap (24h / 7d / 30d / 90d) and proposed CI/CD security gates. See
`templates/remediation-plan-template.md`.

Output: a remediation plan mapped 1:1 to findings.

---

## Phase 8 — Final Report

**Goal:** deliver clear, prioritized, evidence-backed reports.

- Build the executive report (`templates/executive-report-template.md`) and technical report
  (`templates/technical-report-template.md`).
- Each finding follows `templates/finding-template.md`.
- Use `scripts/report_builder.py` to merge per-finding files into a severity-ordered `reports/final-security-report.md`
  (works with partial data).
- See `references/reporting-guide.md` for tone, structure, and quality bar.

Output: `reports/final-security-report.md` plus the executive summary.

---

## Audit limitations to always disclose

Include a short *Limitations* note in every report:
- Time-boxed, snapshot-in-time review of the provided code/commit; later changes are not covered.
- Coverage is best-effort; some paths, generated code, vendored code, or binaries may be unreviewed.
- Static review infers runtime behavior; dynamic confirmation was limited to the authorized environment (or not
  performed).
- Absence of a finding is not proof of absence of vulnerabilities.
- Tool results depend on tool availability and rule coverage; missing tools are noted as `not available`.
