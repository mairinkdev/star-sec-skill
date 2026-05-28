# Reporting Guide

How to assemble the final deliverables and write findings that engineers and stakeholders trust and act on.

## Table of contents
- [Deliverables](#deliverables)
- [Report structure](#report-structure)
- [How to write a great finding](#how-to-write-a-great-finding)
- [Ordering & grouping](#ordering--grouping)
- [Tone & language](#tone--language)
- [Using the report builder](#using-the-report-builder)
- [Quality bar (pre-delivery checklist)](#quality-bar-pre-delivery-checklist)

---

## Deliverables

Produce two views of the same audit plus supporting artifacts:

1. **Executive report** (`templates/executive-report-template.md`) — for founders/CTOs/stakeholders. Posture,
   top risks, business impact, roadmap. Minimal jargon.
2. **Technical report** (`templates/technical-report-template.md`) — for engineers. Detailed findings with evidence,
   file/line, impact, defensive exploitation scenario, fix, and tests.
3. **Findings** (`templates/finding-template.md`) — one block per finding, reused in the technical report and tracker.
4. **Remediation plan** (`templates/remediation-plan-template.md`) — 24h / 7d / 30d / 90d roadmap + CI/CD gates +
   monitoring.

The combined `reports/final-security-report.md` (built by `scripts/report_builder.py`) is the master document.

---

## Report structure

The master technical report should contain these sections in order:

1. **Executive Summary** — 5–10 sentences: overall posture, count by severity, the few things that matter most.
2. **Scope** — repos/branch/commit, app type, stack, environments, authorized URLs, out-of-scope, and the date.
3. **Methodology** — phases performed, tools used (and `not available`), manual vs dynamic coverage.
4. **Security Posture** — narrative assessment + a severity summary table.
5. **Attack Surface** — entry points, trust boundaries, sensitive flows (from Phase 1–2).
6. **Findings by Severity** — Critical → Informational, each using the finding template.
7. **Confirmed Vulnerabilities** — the subset proven (static path verified and/or dynamically reproduced).
8. **Suspected Risks** — Probable/Suspected items with a clear validation step.
9. **Dependency / Security Tooling Results** — summarized audit/SAST/secret/container results; raw output in appendix.
10. **Secrets / Configuration Review** — exposure findings (locations + types, masked), config hardening.
11. **Architecture Risks** — design-level issues and cross-repo/seam risks.
12. **Remediation Roadmap** — from the remediation plan template.
13. **Quick Wins** — high-value, low-effort fixes called out for momentum.
14. **Evidence Appendix** — supporting snippets/captures (masked), raw tool output references.
15. **Suggested Security Backlog** — prioritized issues to track.
16. **Suggested CI/CD Security Gates** — checks to add to the pipeline to prevent regressions.
17. **Limitations** — the standing caveats (see `references/methodology.md`).

---

## How to write a great finding

Each finding (see `templates/finding-template.md`) must answer: *what's wrong, where, why it matters, how sure are
we, and how to fix it.*

- **Title:** specific and outcome-focused — "Unauthenticated access to other users' orders via `/api/orders/:id`",
  not "IDOR".
- **Severity/Priority/Confidence/Status:** per `references/severity-model.md`.
- **Category:** from `references/vulnerability-taxonomy.md` with CWE + OWASP IDs.
- **Affected asset/files/routes:** exact `path:line`, function, endpoint.
- **Description:** the flaw and the data flow (untrusted source → missing control → sink).
- **Evidence:** minimal snippet/capture, labeled static/dynamic/inferred, secrets masked
  (`references/evidence-guidelines.md`).
- **Impact:** concrete consequence (what an attacker gains; data/financial/availability).
- **Preconditions:** what must be true to exploit (auth level, configuration, timing).
- **Safe reproduction steps:** minimal, non-destructive, authorized-env only.
- **Recommended fix:** concept + concrete approach for this stack; likely files to change.
- **Suggested tests:** including a security regression test that fails on the vuln and passes once fixed.
- **References:** OWASP/CWE links and relevant framework docs.
- **Notes:** assumptions, compensating controls, validation needed.

---

## Ordering & grouping

- Order findings by **severity**, then **priority**, then **confidence**.
- **Group by root cause:** if the same flaw appears in many handlers, write one finding listing all locations rather
  than many near-duplicates. This makes the fix and its tracking clearer.
- Use stable IDs (`WEB-001`, `API-014`) so findings can be referenced in tickets; keep them consistent across the
  executive and technical reports.

---

## Tone & language

- Professional, direct, defensive, international English. No fear-mongering, no absolute claims like "100% secure".
- Lead with exploitable, high-impact risk; be explicit about what is proven vs suspected.
- Be constructive: pair every problem with a path to a fix and acknowledge good practices you observed.
- Respect the team: assume competent engineers under constraints, not negligence.

---

## Using the report builder

`scripts/report_builder.py` merges per-finding Markdown files into a severity-ordered report. It tolerates partial
data, so you can generate a draft early and regenerate as findings firm up.

```bash
# 1. Write each finding as its own markdown file under reports/findings/ using the finding template.
#    Include a metadata header the builder can parse (see the script's --help and the template).
# 2. Build the master report:
python star-sec/scripts/report_builder.py --findings reports/findings/ --out reports/final-security-report.md

# Optional: prepend an executive summary file and set a title.
python star-sec/scripts/report_builder.py \
  --findings reports/findings/ \
  --summary reports/executive-summary.md \
  --title "Security Audit — Acme App" \
  --out reports/final-security-report.md
```

---

## Quality bar (pre-delivery checklist)

- [ ] Executive summary readable by a non-engineer; technical report actionable by engineers.
- [ ] Every finding has location, evidence (labeled + masked), impact, fix, and a regression test idea.
- [ ] Severity/priority/confidence/status set and consistent with the model.
- [ ] No real secrets, tokens, or PII anywhere in the report.
- [ ] Confirmed vs Suspected clearly separated; validation steps given for Suspected.
- [ ] Quick wins and a phased roadmap (24h/7d/30d/90d) included.
- [ ] CI/CD security gates and monitoring recommendations included.
- [ ] Scope, methodology, tool availability, and limitations stated.
- [ ] No unauthorized targets referenced; dynamic evidence only from the authorized environment.
