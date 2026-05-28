# Evidence Guidelines

How to collect evidence that is convincing, reproducible, and safe — without leaking secrets or overstating risk.
Good evidence is what separates a credible audit from a noisy scanner dump.

## Table of contents
- [Goals](#goals)
- [Citing code precisely](#citing-code-precisely)
- [Evidence types](#evidence-types)
- [Masking secrets and PII](#masking-secrets-and-pii)
- [Writing safe PoCs](#writing-safe-pocs)
- [Reducing false positives](#reducing-false-positives)
- [Recording audit limitations](#recording-audit-limitations)
- [Evidence checklist](#evidence-checklist)

---

## Goals

- Make each finding **independently verifiable** by the team.
- Keep evidence **minimal** — just enough to prove the issue and locate the fix.
- Never let evidence become a liability: **no real secrets, no destructive steps, no third-party attacks.**

---

## Citing code precisely

- Always reference `relative/path.ext:line` (a single line or a tight range), the **function/method**, and the
  **route/endpoint** when applicable.
- Quote the smallest snippet that shows the problem. Add a one-line caret/comment indicating the exact issue.
- Prefer a permalink-style reference (path + line + commit/branch) so it survives file movement.

Example:
```text
File: src/api/orders.controller.ts:142  (function getOrder, route GET /api/orders/:id)

  const order = await db.order.findUnique({ where: { id: req.params.id } });
  return res.json(order);   // <-- no check that order.userId === req.user.id  (IDOR)
```

---

## Evidence types

Always label which kind of evidence supports a finding — it sets the right expectation and pairs with confidence.

| Type | What it is | Confidence it supports |
|---|---|---|
| **Static** | Read directly from source/config. | High when the path is clear and no compensating control exists. |
| **Dynamic** | Observed at runtime in the authorized environment (request/response, logs). | Confirmed when reproduced safely. |
| **Inferred** | Deduced from patterns, naming, or tool output without seeing the exact path. | Medium/Low — recommend validation. |

If a finding is only tool-flagged, say so and treat it as Inferred until you confirm reachability by reading the code.

---

## Masking secrets and PII

Never print full secrets, tokens, keys, passwords, or personal data — in terminal output, raw files, or the report.

Masking rules:
- Show only enough to identify *type/location*, never the usable value.
- Keep a short prefix/suffix at most: `AKIA…REDACTED`, `sk_live_…(redacted)`, `eyJ….<jwt redacted>`.
- Redact PII: emails `j***@example.com`, names, phone numbers, full card numbers (`411111******1111` at most), national
  IDs, addresses.
- For leaked-secret findings, report the **location** (file:line, commit) and **type**, not the value. Recommend
  immediate rotation.
- The bundled `scripts/secret_scan_helper.py` masks by default — keep it that way.

Never paste a real secret into a PoC, an issue tracker, a chat, or any networked tool.

---

## Writing safe PoCs

A proof of concept should **demonstrate** the flaw with the least power necessary, and must be reproducible by a
defender.

Do:
- Use benign markers (e.g., an XSS probe like `"><b>xss-probe-7f3</b>` that only proves injection, not a weaponized
  payload).
- Use test/throwaway accounts and provider **test keys**; target only authorized `localhost`/staging.
- Show the minimal request + the observable effect (status, reflected marker, another tenant's object ID returned).
- Keep it idempotent and non-destructive. Read, don't delete or corrupt.

Don't:
- Provide weaponized exploit chains, malware, shellcode, data-exfiltration scripts, or DoS payloads.
- Run aggressive fuzzing, password sprays against real users, or anything that mass-targets.
- Exploit beyond what's needed to prove the point (no lateral movement, no pulling real data dumps).

Example (safe, illustrative) IDOR PoC:
```text
Preconditions: logged in as user A (test account). Order 1001 belongs to user B (test account).
Request:  GET /api/orders/1001   (with user A's session cookie)
Observed: 200 OK, body contains user B's order — confirms missing ownership check.
Impact:   any authenticated user can read any order by ID.
```

---

## Reducing false positives

Before promoting a candidate to Confirmed/High, rule out compensating controls:
- Is there a **global middleware** / guard / interceptor enforcing auth or validation upstream?
- Does the **framework default** already mitigate it (e.g., ORM parameterization, template auto-escaping, CSRF tokens
  enabled by default)?
- Is the dangerous code **reachable** from an exposed entry point with attacker-controlled input?
- Is the input actually **untrusted**, or is it server-generated/constrained?
- Is there an **infra control** (WAF, network policy) the team relies on? Note the dependency rather than assuming.

If you can't rule these out, mark the finding **Suspected / Needs Validation** and say exactly what to check. It's far
better to under-claim with a clear validation step than to cry wolf.

---

## Recording audit limitations

State limitations honestly so results aren't over-read:
- Scope and commit/branch reviewed; what was out of scope.
- Areas not fully covered (generated code, vendored libs, binaries, time-boxed paths).
- Whether dynamic testing was performed and where (authorized env only) or not at all.
- Tool availability (`not available` tools noted) and that tools can miss issues.
- The standing caveat: no audit proves the absence of vulnerabilities.

---

## Evidence checklist

- [ ] File path + line + function + route cited.
- [ ] Smallest convincing snippet included; the exact issue highlighted.
- [ ] Evidence type labeled (static / dynamic / inferred).
- [ ] All secrets/tokens/PII masked.
- [ ] PoC (if any) is minimal, non-destructive, and targets only the authorized environment.
- [ ] Compensating controls considered; confidence set accordingly.
- [ ] Impact and preconditions stated in real terms.
