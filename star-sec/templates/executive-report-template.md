<!--
Executive report template for Star Sec Auditor.
Audience: founders, CTOs, product/security stakeholders. Keep it clear and business-oriented; minimal jargon.
Replace <placeholders>. Mask all secrets/PII. Do not claim "100% secure".
-->

# Security Audit — Executive Summary

**Project:** <App / company name>
**Prepared by:** <Auditor / team>
**Date:** <YYYY-MM-DD>
**Scope:** <Repos / app / environments reviewed at a high level>
**Type:** Authorized, defensive application security audit (secure code review<, plus dynamic testing on staging if performed>)

---

## 1. Overall security posture

<3–6 sentences in plain language: how the application is doing security-wise, the general maturity, and the headline
message. Be honest and proportionate — acknowledge strengths as well as gaps. Avoid absolute claims.>

**Posture rating:** <e.g., Needs Attention / Fair / Good> — <one-line justification>

## 2. Findings at a glance

| Severity | Count |
|---|---|
| Critical | <n> |
| High | <n> |
| Medium | <n> |
| Low | <n> |
| Informational | <n> |

<One sentence interpreting the table — e.g., "The criticals concentrate in access control on the payments path.">

## 3. Top risks (business impact)

List the few risks that matter most, framed by business consequence, not jargon.

1. **<Risk title>** — <what could happen in business terms: data exposure, financial loss, account takeover, downtime>.
   *Severity: <level>. Priority: <P0–P3>.*
2. **<Risk title>** — <business impact>. *Severity / Priority.*
3. **<Risk title>** — <business impact>. *Severity / Priority.*

## 4. What's going well

<Briefly note good practices observed (e.g., parameterized queries, framework auth used correctly, secrets in a
manager). This builds trust and shows the audit is balanced.>

## 5. Recommended roadmap

| Timeframe | Focus |
|---|---|
| **Now (24h)** | <Emergency mitigations for P0 items — e.g., rotate exposed key, disable risky route.> |
| **This week (7d)** | <High-priority fixes (P1).> |
| **This month (30d)** | <Medium fixes and key hardening (P2).> |
| **This quarter (90d)** | <Structural hardening, security maturity, CI/CD gates (P3).> |

## 6. Quick wins

<3–6 high-value, low-effort actions the team can complete fast — e.g., enable webhook signature verification, add
security headers, set cookie flags.>

## 7. Investment & maturity recommendations

<Optional: lightweight suggestions to raise security maturity — CI/CD security gates, dependency monitoring, periodic
reviews, secret management, logging/alerting. Keep it practical and scaled to the team's size.>

## 8. Limitations

<Snapshot-in-time, best-effort coverage; dynamic testing scope; tool availability. No audit proves the absence of
vulnerabilities. See the technical report for full detail.>

---

*This is a summary. Engineering detail, evidence, and remediation steps are in the accompanying technical report.*
