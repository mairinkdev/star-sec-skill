<div align="center">

# Star Sec Auditor

### A defensive AppSec auditor for [Claude Code](https://claude.com/claude-code) — secure code review, web app security audits, and prioritized reporting for full-stack apps.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Claude Code Skill](https://img.shields.io/badge/Claude%20Code-Skill-8A2BE2.svg)](https://docs.claude.com/en/docs/claude-code/skills)
[![Scope: Defensive](https://img.shields.io/badge/scope-defensive%20only-2ea44f.svg)](#-ethics--authorized-scope)
[![OWASP](https://img.shields.io/badge/aligned-OWASP%20Top%2010%20%2F%20API%20Top%2010-000000.svg)](https://owasp.org/)
[![Status](https://img.shields.io/badge/status-stable-success.svg)](#)

**Authorized · Defensive · Non-destructive · Stack-agnostic**

</div>

---

> **Star Sec Auditor** is a [Claude Code](https://claude.com/claude-code) skill that turns Claude into a senior
> application-security auditor. Point it at your repositories and it runs a structured, **defensive** security
> review — frontend, backend, APIs, database, infrastructure, Docker, and CI/CD — then delivers evidence-backed,
> prioritized findings and professional executive + technical reports.
>
> It is built for **authorized** work: auditing code you own or are contracted to assess. It is *not* an offensive
> tool, and it never promises that any system is "100% secure" — it finds and explains real, exploitable risk so you
> can fix it.

## Table of contents

- [Why Star Sec Auditor](#-why-star-sec-auditor)
- [What it does](#-what-it-does)
- [What it does not do](#-what-it-does-not-do)
- [How it works](#-how-it-works)
- [Example output](#-example-output)
- [Installation](#-installation)
- [Usage & example prompts](#-usage--example-prompts)
- [Reports & deliverables](#-reports--deliverables)
- [How to interpret results](#-how-to-interpret-results)
- [Repository structure](#-repository-structure)
- [Bundled scripts](#-bundled-scripts)
- [Ethics & authorized scope](#-ethics--authorized-scope)
- [Limitations](#-limitations)
- [Contributing](#-contributing)
- [Security](#-security)
- [Changelog](#-changelog)
- [License](#-license)

## ✨ Why Star Sec Auditor

Most "security" prompts produce a shallow checklist. Star Sec Auditor instead gives Claude a **methodology**: it maps
your attack surface, builds a lightweight threat model, runs available tooling, reads the code along the data flow,
validates findings to cut false positives, and writes reports that engineers and stakeholders can actually act on.

- 🛡️ **Defensive by design** — read code, find risk, recommend fixes. No exploitation of third parties, no data
  exfiltration, no destructive testing.
- 🌐 **Stack-agnostic** — React/Next/Vue/Angular on the frontend; Node/Python/Go/Rust/PHP/Ruby/Java/.NET on the
  backend; PostgreSQL/MySQL/MongoDB/Redis with Prisma/Drizzle/TypeORM/Sequelize/SQLx/Diesel.
- 🧭 **OWASP-aligned** — Web Top 10 and API Security Top 10, mapped to CWE.
- 🔁 **Reusable** — works on any web project, even with only source-code access.
- 🧰 **Tooling-aware, never tooling-blocked** — uses `semgrep`, `gitleaks`, `npm/pip/cargo audit`, `trivy`, ZAP and
  more when present; falls back to manual review and records anything missing as *not available*.
- 📋 **Report-ready** — executive summary, technical findings, remediation roadmap, and suggested CI/CD security gates.

## 🔍 What it does

| Area | Coverage |
|---|---|
| **Identity** | Authentication, authorization (RBAC/ABAC), sessions, JWT/refresh tokens, password reset, OAuth/OIDC, MFA/TOTP |
| **Access control** | IDOR/BOLA, function-level authz, admin routes, multi-tenant isolation |
| **Injection** | SQL/NoSQL/ORM, command, SSRF, path traversal, template/LDAP injection |
| **Web/browser** | XSS, CSRF, CORS, CSP, security headers, open redirects, clickjacking |
| **Data handling** | File upload, insecure deserialization, prototype pollution, ReDoS, mass assignment |
| **Money & integrations** | Webhook signature verification, payment confirmation, **idempotency**, replay safety |
| **Abuse resistance** | Rate limiting, brute-force protection, race conditions |
| **Secrets & config** | Hardcoded secrets, env exposure, error handling, debug modes, feature flags |
| **Platform** | Docker hardening, CI/CD secrets, supply-chain & dependency-confusion risk, TLS assumptions |
| **Topology** | Cache isolation, queue/worker trust boundaries, realtime/WebSocket/SSE security, API versioning |
| **AI/LLM features** | Prompt injection, tool/agent abuse, data leakage, unsafe output rendering |

## 🚫 What it does *not* do

- ❌ No attacks, scanning, or exploitation of systems you are **not authorized** to test.
- ❌ No destructive testing, DoS, aggressive fuzzing, or mass targeting.
- ❌ No weaponized exploits, malware, C2, or detection-evasion tradecraft.
- ❌ No secret exfiltration; secrets/PII are always **masked** in output and reports.
- ❌ No legal/privacy **compliance** work (LGPD, GDPR, DPAs). This skill is **technical security only**.
- ❌ No "100% secure" guarantees — every report states its limitations.

## ⚙️ How it works

Star Sec Auditor follows an eight-phase workflow. `SKILL.md` orchestrates; deep guidance lives in `references/`.

```
Phase 0  Authorization & Scope Guard   confirm authorization, capture scope, set out-of-scope
Phase 1  Repository Recon              map stack, entrypoints, routes → attack-surface inventory
Phase 2  Architecture & Threat Model   trust boundaries, critical assets, sensitive flows
Phase 3  Automated Baseline Checks     deps / SAST / secrets / containers (non-destructive)
Phase 4  Manual Secure Code Review     the core — trace untrusted input to dangerous sinks
Phase 5  DAST / Runtime Testing        only if authorized; localhost/staging; non-destructive
Phase 6  Risk Validation               confirm, de-duplicate, classify, cut false positives
Phase 7  Remediation Planning          fixes, tests, priorities (P0–P3), quick wins
Phase 8  Final Report                  executive + technical reports, roadmap, CI/CD gates
```

Findings are rated with a transparent model — **Severity** (Critical→Informational), **Priority** (P0–P3),
**Confidence** (Confirmed/High/Medium/Low), and **Status** — so you know what to fix first and how sure we are. See
[`star-sec/references/severity-model.md`](./star-sec/references/severity-model.md).

## 🧾 Example output

A quick look at what the skill produces. These are trimmed from the fictional, sanitized samples in
[`star-sec/examples/`](./star-sec/examples) — see the full
[finding](./star-sec/examples/example-finding.md) and [report](./star-sec/examples/example-final-report.md).

**A single finding** (standardized header → evidence → impact → fix → tests):

> #### [API-007] Any authenticated user can read other users' invoices via `GET /api/invoices/:id`
> **Severity:** High · **Priority:** P1 · **Confidence:** Confirmed · **Status:** Open
> **Category:** Broken Object Level Authorization (IDOR/BOLA) — CWE-639 / API1:2023
>
> Invoice lookup loads a record by the primary key in the URL and returns it without checking ownership. The route
> has authentication but no **object-level** authorization, and sequential IDs make enumeration trivial.

```text
File: src/modules/billing/invoice.controller.ts:88

  @UseGuards(AuthGuard)                       // authentication only
  async getInvoiceById(@Param('id') id: string) {
    return this.invoiceService.findById(id);  // <-- no check that invoice.userId === request.user.id
  }
```

> **Fix:** scope the query to the caller (`where: { id, userId }`) and return `404`; centralize the check in a
> reusable policy. **Test:** user A requesting user B's invoice returns `404`.

<details>
<summary><strong>Final report excerpt</strong> — severity summary + executive snippet</summary>

```markdown
## Executive summary
Acme App is a multi-tenant SaaS… authorization is enforced inconsistently, which produced the most serious
findings. The headline risks are a cross-tenant data exposure on the billing API and a payment webhook that does
not verify signatures.

We recorded 8 findings: 1 Critical, 2 High, 3 Medium, 1 Low, 1 Informational.

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 2 |
| Medium | 3 |
| Low | 1 |
| Informational | 1 |

## Remediation roadmap
| Timeframe | Focus |
|---|---|
| Now (24h)        | Enable Stripe webhook signature verification + idempotency (P0). |
| This week (7d)   | Invoice ownership scoping + sibling-endpoint audit; redirect allowlist (P1). |
| This month (30d) | Security headers/CSP, login rate limiting, non-root container (P2). |
| This quarter     | Centralize authorization policy; audit logging; CI/CD security gates (P3). |
```

</details>

## 📦 Installation

Star Sec Auditor is a standard Claude Code skill. Install it at **user** scope (available everywhere) or **project**
scope (committed with a specific repo).

> Requires [Claude Code](https://docs.claude.com/en/docs/claude-code). The bundled scripts need **Python 3.9+** (the
> skill works fine without them — they just automate repetitive steps).

**1. Clone the repository**

```bash
git clone https://github.com/mairinkdev/star-sec-skill.git
```

**2a. Install for your user (recommended — available in every project)**

```bash
# macOS / Linux
mkdir -p ~/.claude/skills
cp -r star-sec-skill/star-sec ~/.claude/skills/star-sec
```

```powershell
# Windows (PowerShell)
New-Item -ItemType Directory -Force "$env:USERPROFILE\.claude\skills" | Out-Null
Copy-Item -Recurse "star-sec-skill\star-sec" "$env:USERPROFILE\.claude\skills\star-sec"
```

**2b. Or install for a single project (committed to that repo)**

```bash
mkdir -p your-project/.claude/skills
cp -r star-sec-skill/star-sec your-project/.claude/skills/star-sec
```

**3. Verify** — start Claude Code and run `/skills` (or just ask for a security audit). The skill activates
automatically when your request involves a security audit, secure code review, or AppSec assessment.

The final folder must contain `SKILL.md` at its root, e.g. `~/.claude/skills/star-sec/SKILL.md`.

## 💬 Usage & example prompts

Just describe what you want — the skill triggers on intent. Examples that activate Star Sec Auditor:

```text
Use Star Sec Auditor to audit this full-stack app.
Run a complete authorized security review of the frontend and backend.
Perform a defensive pentest of this repository and produce a report.
Audit auth, payments, webhooks, secrets, Docker and CI/CD.
Review this API for IDOR/BOLA and broken access control.
Generate a final AppSec report with prioritized findings.
Harden this Next.js + NestJS app and suggest CI/CD security gates.
```

Helpful context to include (optional — the skill proceeds best-effort without it):

- Which repos/branches are in scope, and the app type and stack.
- Whether a `localhost`/staging environment exists and is **authorized** for dynamic testing.
- The areas you care about most (e.g., payments, multi-tenant isolation, admin panel).

> **Authorization first.** The skill assumes you own or are contracted to test the target. If anything implies an
> unauthorized or third-party target, it will pause and ask before doing any dynamic testing.

## 📑 Reports & deliverables

Star Sec Auditor produces a consistent set of artifacts (templates in
[`star-sec/templates/`](./star-sec/templates)):

- **Executive report** — posture, top risks in business terms, and a phased roadmap for non-engineers.
- **Technical report** — detailed findings with evidence (`file:line`), impact, safe reproduction, fixes, and tests.
- **Per-finding blocks** — standardized fields, ready for your issue tracker.
- **Remediation plan** — 24h / 7-day / 30-day / 90-day actions, CI/CD gates, and monitoring recommendations.

The bundled `report_builder.py` merges per-finding files into a single severity-ordered
`reports/final-security-report.md`. See a fictional, sanitized sample in
[`star-sec/examples/example-final-report.md`](./star-sec/examples/example-final-report.md).

## 🧭 How to interpret results

- **Start with Severity + Priority.** P0/Critical items are realistically exploitable with serious impact — act first.
- **Check Confidence.** *Confirmed* means verified in code and/or reproduced safely; *Suspected / Needs Validation*
  means do the stated check before acting.
- **Read the "Confirmed" vs "Suspected" sections** — they keep proven issues separate from leads.
- **Use the Quick Wins list** for high-value, low-effort fixes you can ship immediately.
- **Remember the Limitations section** — an audit is a snapshot in time and does not prove the absence of bugs.

## 🗂️ Repository structure

```
star-sec-skill/
├── README.md                  ← you are here
├── LICENSE                    ← MIT
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── .gitignore
└── star-sec/                  ← the Claude Code skill (install this folder)
    ├── SKILL.md               ← orchestrator: workflow, guardrails, triggers
    ├── references/            ← methodology, taxonomy, checklists, playbooks, models
    │   ├── methodology.md
    │   ├── vulnerability-taxonomy.md
    │   ├── stack-specific-checklists.md
    │   ├── evidence-guidelines.md
    │   ├── severity-model.md
    │   ├── secure-review-playbooks.md
    │   └── reporting-guide.md
    ├── templates/             ← executive, technical, finding, remediation templates
    ├── scripts/               ← safe Python helpers (recon, inventory, deps, secrets, report)
    └── examples/              ← sample finding + sample final report
```

## 🐍 Bundled scripts

All scripts are Python 3, support `--help`, are **network-free**, and **do not modify** the target project by default.
Output goes to `reports/`.

| Script | Purpose |
|---|---|
| `repo_recon.py` | Detect stack, package managers, frameworks, Docker/CI, env examples, entrypoints → JSON. |
| `security_inventory.py` | Locate routes, middleware, and auth/admin/webhook/upload/payment handlers → JSON. |
| `dependency_audit_helper.py` | Detect package managers and run only **safe, available** audit commands (opt-in `--run`). |
| `secret_scan_helper.py` | Local, **masked** secret detection with confidence scoring (never prints full secrets). |
| `report_builder.py` | Merge per-finding files into a severity-ordered final report (works with partial data). |

```bash
# Example: recon + attack-surface inventory of a project
python star-sec/scripts/repo_recon.py ./your-project --out reports/recon.json
python star-sec/scripts/security_inventory.py ./your-project --out reports/inventory.json
```

## ⚖️ Ethics & authorized scope

This project exists to help teams **find and fix** vulnerabilities in software they are responsible for. Use it only
where you have explicit authorization. Star Sec Auditor:

- operates **defensively** — it identifies and explains risk and recommends remediation;
- keeps dynamic testing to **authorized** `localhost`/staging environments and avoids anything destructive;
- writes **minimal, non-destructive** proofs of concept and **masks** secrets and PII;
- declines to attack third-party systems or to produce offensive tradecraft.

By using this skill you agree to act within the law and your authorization. See
[`SECURITY.md`](./SECURITY.md) and [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

## 🧱 Limitations

No audit proves the absence of vulnerabilities, and **no result here should be read as a guarantee of security**.

- **Point-in-time & best-effort.** Findings reflect the code reviewed at a specific commit; later changes are not
  covered, and some paths, generated code, vendored code, or binaries may go unreviewed.
- **Scope- and access-bound.** Depth depends on what you grant — repositories, branches, and whether an authorized
  `localhost`/staging environment exists for dynamic checks.
- **Tooling-dependent.** When scanners (`semgrep`, `trivy`, `gitleaks`, ZAP…) are unavailable, the skill falls back to
  manual review and records the gap; coverage of those checks is reduced accordingly.
- **Not a substitute for a full human-led penetration test.** It accelerates and structures expert review and catches
  a wide class of issues, but it does not replace adversarial testing, business-logic deep dives, or a formal
  engagement by a qualified security team.

Treat every report as a prioritized starting point for remediation — not a certificate of security.

## 🤝 Contributing

Contributions are welcome — new checklists, playbooks, taxonomy entries, and safe tooling integrations especially.
Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md) first. Keep everything **defensive** and within scope: no offensive
payloads, no compliance/legal scope creep.

## 🔐 Security

Found a security issue in this project (not in something you're auditing with it)? Please follow the responsible
disclosure process in [`SECURITY.md`](./SECURITY.md).

## 🗒️ Changelog

Release history is tracked in [`CHANGELOG.md`](./CHANGELOG.md), following
[Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).

## 📄 License

Released under the [MIT License](./LICENSE).

<div align="center">

Built by [**@mairinkdev**](https://github.com/mairinkdev) · for the Claude Code community

*Find risk. Explain it clearly. Help teams fix it.*

</div>
