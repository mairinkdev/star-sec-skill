<!--
Finding template for Star Sec Auditor.
Copy this block for each finding. Keep the HTML-comment metadata header at the top so scripts/report_builder.py can
parse and order findings. Remove guidance comments in the final report. Mask all secrets/PII.
-->

<!--
id: WEB-001
severity: High            # Critical | High | Medium | Low | Informational
priority: P1              # P0 | P1 | P2 | P3
confidence: Confirmed     # Confirmed | High | Medium | Low
status: Open              # Open | Needs Validation | False Positive | Fixed
category: Broken Access Control (IDOR / BOLA)
cwe: CWE-639
owasp: A01:2021 / API1:2023
-->

## [WEB-001] <Concise, outcome-focused title>

| Field | Value |
|---|---|
| **Severity** | High |
| **Priority** | P1 |
| **Confidence** | Confirmed |
| **Status** | Open |
| **Category** | Broken Access Control (IDOR / BOLA) |
| **CWE / OWASP** | CWE-639 / A01:2021 / API1:2023 |

### Affected asset
<Service/app component, e.g., "Orders API (backend repo)">

### Affected files
- `relative/path/to/file.ext:LINE` — `functionName()`

### Affected routes / endpoints
- `GET /api/orders/:id`

### Description
<What the flaw is and the data flow: untrusted source → missing/weak control → sink. Be specific and technical.>

### Evidence
<Evidence type: static | dynamic | inferred. Minimal snippet with the issue highlighted; secrets/PII masked.>

```text
File: relative/path/to/file.ext:LINE  (functionName, route GET /api/orders/:id)

  const order = await db.order.findUnique({ where: { id: req.params.id } });
  return res.json(order);   // <-- no ownership check (order.userId !== req.user.id)
```

### Impact
<Concrete consequence: what an attacker gains; data/financial/availability/privilege impact.>

### Preconditions
<What must be true to exploit: auth level, configuration, timing, special access.>

### Safe reproduction steps
<Minimal, non-destructive, authorized-environment only. Use test accounts/keys. Mask sensitive values.>

1. Authenticate as test user A (staging).
2. Request `GET /api/orders/1001` where order 1001 belongs to test user B.
3. Observe `200 OK` returning user B's order → confirms missing ownership check.

### Recommended fix
<Concept + concrete approach for this stack. Likely files to change.>

- Scope the query to the caller: `where: { id, userId: req.user.id }`, or load then assert ownership and return 404/403.
- Apply the same pattern to sibling endpoints (list affected routes).

### Suggested tests
- Security regression test: as user A, requesting user B's object returns 403/404 (fails on vulnerable code, passes
  after fix).
- Positive test: a user can still access their own object.

### References
- OWASP A01:2021 Broken Access Control; OWASP API1:2023 BOLA.
- CWE-639: Authorization Bypass Through User-Controlled Key.
- <Framework-specific authorization docs.>

### Notes
<Assumptions, compensating controls considered, validation still needed, related findings (IDs).>
