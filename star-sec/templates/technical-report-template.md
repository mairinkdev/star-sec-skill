<!--
Technical report template for Star Sec Auditor.
Audience: engineers. Detailed, evidence-backed, actionable. Replace <placeholders>. Mask all secrets/PII.
Findings use templates/finding-template.md. Order by severity, then priority, then confidence.
-->

# Security Audit — Technical Report

**Project:** <App / company name>
**Prepared by:** <Auditor / team>
**Date:** <YYYY-MM-DD>
**Commit / branch:** <hash / branch>

---

## 1. Executive summary

<5–10 sentences: overall posture, counts by severity, and the most important issues. (Mirror the executive report's
headline, but you may use technical terms here.)>

| Severity | Count |
|---|---|
| Critical | <n> |
| High | <n> |
| Medium | <n> |
| Low | <n> |
| Informational | <n> |

## 2. Scope

- **Repositories:** <repo(s) + branch/commit>
- **Application type:** <SaaS / API / admin / marketplace / mobile backend / ...>
- **Stack:** <languages, frameworks, datastores, infra/hosting>
- **Environments tested:** <code-only / localhost / staging URL(s)>
- **Authorized URLs:** <list, or "none — static review only">
- **Out of scope:** <production hosts, third-party APIs, other tenants, ...>
- **Authorization:** Confirmed — the requester is authorized to audit the above.

## 3. Methodology

<Phases performed (Star Sec Auditor 0–8). Manual secure code review plus automated baseline checks<, and
non-destructive dynamic testing on staging if performed>.>

**Tools used:**

| Tool | Purpose | Status |
|---|---|---|
| semgrep | SAST | run / not available |
| npm/pnpm/yarn audit | dependency vulns | run / not available |
| gitleaks | secret scan | run / not available |
| trivy / hadolint / checkov | container & IaC | run / not available |
| OWASP ZAP (baseline) | DAST (authorized env) | run / not performed |

## 4. Security posture

<Narrative assessment: maturity, recurring themes (e.g., authorization enforced inconsistently), and where risk
concentrates.>

## 5. Attack surface

<Entry points, trust boundaries, and sensitive flows (from recon + threat modeling). A short table or list of
exposed endpoints/handlers and their trust level is helpful.>

## 6. Findings by severity

> Each finding uses the finding template. Insert finding blocks here, ordered Critical → Informational.

### Critical
<finding blocks or "None identified.">

### High
<finding blocks or "None identified.">

### Medium
<finding blocks or "None identified.">

### Low
<finding blocks or "None identified.">

### Informational
<finding blocks or "None identified.">

## 7. Confirmed vulnerabilities
<Subset proven via verified code path and/or safe dynamic reproduction. Reference finding IDs.>

## 8. Suspected risks (need validation)
<Probable/Suspected items with the exact validation step for each. Reference finding IDs.>

## 9. Dependency & security tooling results
<Summary of dependency/SAST/secret/container scans. Counts and notable items; raw output in the appendix. Note any
tools that were `not available`.>

## 10. Secrets & configuration review
<Secret exposure findings (location + type, masked — never the value) and configuration hardening items. Recommend
rotation for any real exposure.>

## 11. Architecture risks
<Design-level issues and cross-repo/seam risks (token issuance vs validation, CORS vs cookie scope, shared
secrets/queues, multi-tenant isolation).>

## 12. Remediation roadmap
<Insert from templates/remediation-plan-template.md: 24h / 7d / 30d / 90d.>

## 13. Quick wins
<High-value, low-effort fixes pulled out for momentum.>

## 14. Evidence appendix
<Supporting snippets/captures (masked) and references to raw tool output stored under reports/raw/.>

## 15. Suggested security backlog
<Prioritized, trackable list of issues (IDs + titles + priority) for the team's tracker.>

## 16. Suggested CI/CD security gates
<Pipeline checks to prevent regressions: dependency audit, SAST, secret scan, container/IaC scan, and which should
block vs warn.>

## 17. Limitations
<Snapshot-in-time, best-effort coverage; what was not reviewed; dynamic-testing scope; tool availability. No audit
proves the absence of vulnerabilities.>
