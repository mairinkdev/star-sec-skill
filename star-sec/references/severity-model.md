# Severity, Priority, Confidence & Status Model

A consistent rubric for rating findings. Apply it in Phase 6 and carry the labels into every finding block.

## Table of contents
- [Severity](#severity)
- [Scoring inputs](#scoring-inputs)
- [Priority (P0–P3)](#priority-p0p3)
- [Confidence](#confidence)
- [Status](#status)
- [Putting it together](#putting-it-together)

---

## Severity

Severity reflects the worst realistic outcome given how exploitable and exposed the issue is. Use five levels.

| Severity | Meaning | Typical examples |
|---|---|---|
| **Critical** | Trivially or remotely exploitable with severe impact; often unauthenticated or full compromise. | Unauthenticated RCE, SQL injection dumping the DB, auth bypass to admin, secret-key leak enabling account takeover, payment bypass with direct financial loss. |
| **High** | Serious impact, exploitable with realistic preconditions (e.g., any authenticated user). | IDOR/BOLA exposing other users' data, stored XSS in an authenticated app, SSRF reaching internal services, missing webhook signature verification enabling forged events. |
| **Medium** | Real but constrained impact, or needs notable preconditions/user interaction. | Reflected XSS requiring a crafted link, CSRF on a sensitive action, weak rate limiting enabling slow brute force, verbose errors leaking stack traces. |
| **Low** | Limited impact or hard to exploit; mostly hardening. | Missing security headers with low exploitability, minor info disclosure, outdated dependency with no reachable sink. |
| **Informational** | No direct vulnerability; best-practice or defense-in-depth. | Missing CSP report-only, suggestion to rotate keys, logging improvements, code-quality risks. |

When two levels seem to fit, let **exploitability** and **exposure** break the tie. Document the reasoning briefly.

---

## Scoring inputs

Weigh these factors. They are qualitative — explain your rating rather than computing a false-precision number. (If a
client requires CVSS, you can map to it, but lead with business-relevant reasoning.)

- **Exploitability** — how hard is it? (skill, tooling, timing, special conditions)
- **Impact** — confidentiality / integrity / availability consequence.
- **Exposure** — internet-facing vs internal vs local; reachable by anonymous users?
- **Authentication requirement** — none / any user / privileged.
- **Data sensitivity** — credentials, PII, financial, tenant data, secrets.
- **Privilege escalation** — can it raise privileges (user→admin, tenant→tenant)?
- **Lateral movement** — does it open a path to other systems/services?
- **Financial impact** — direct loss, fraud, or chargeback exposure.
- **Availability impact** — can it degrade or take down the service?
- **Existing mitigations** — WAF, framework defaults, network controls, monitoring.
- **Confidence** — how sure are you it's real and reachable? (tracked separately, below)

Rule of thumb: **Severity ≈ Exploitability × Impact × Exposure**, then nudge down for strong existing mitigations or
up for sensitive data / escalation / financial loss.

---

## Priority (P0–P3)

Priority is the *fix-urgency* recommendation. It usually tracks severity but also considers exposure, ease of fix, and
business context (a Medium on the payment path may be prioritized above a High in an internal tool).

| Priority | Act within | Guidance |
|---|---|---|
| **P0** | Immediately (hours) | Active or trivial exploitation risk with severe impact. Consider mitigating in production now (feature flag, block route, rotate secret). |
| **P1** | This week | High-impact issues that are realistically exploitable; schedule a fix and a regression test. |
| **P2** | This month | Medium issues and meaningful hardening. |
| **P3** | This quarter / backlog | Low and Informational items; batch into maintenance. |

Note **quick wins** (high value, low effort — e.g., add a header, enable signature verification) separately so teams
can knock them out fast regardless of priority bucket.

---

## Confidence

State how sure you are. This protects credibility and tells the team how much to validate before acting.

| Confidence | Meaning |
|---|---|
| **Confirmed** | Verified by reading the exact code path and/or reproduced dynamically in the authorized environment. |
| **High** | Strong static evidence; the vulnerable pattern is clear and no compensating control was found, but not dynamically reproduced. |
| **Medium** | Plausible based on code, but a control may exist elsewhere or reachability is uncertain. Recommend validation. |
| **Low** | Heuristic/tool-flagged or inferred; needs investigation before action. |

Pair confidence with evidence type (static / dynamic / inferred) from `references/evidence-guidelines.md`.

---

## Status

Track the lifecycle of each finding.

| Status | Meaning |
|---|---|
| **Open** | Reported, not yet addressed. |
| **Needs Validation** | Requires the team or a dynamic test to confirm before fixing. |
| **False Positive** | Investigated and determined not to be a real issue (keep a short rationale). |
| **Fixed** | Remediated and ideally covered by a regression test. |

---

## Putting it together

Every finding block should carry: **Severity**, **Priority**, **Confidence**, and **Status**, plus the category
(`references/vulnerability-taxonomy.md`). Example header:

```
Severity: High | Priority: P1 | Confidence: Confirmed | Status: Open
Category: Broken Access Control (IDOR / BOLA) — CWE-639 / OWASP A01
```

Be honest and proportionate: inflating severity erodes trust and buries the issues that truly matter.
