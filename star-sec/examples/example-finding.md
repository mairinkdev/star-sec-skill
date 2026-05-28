<!--
Example finding (generic, safe). Demonstrates the finding-template structure and tone.
Values are illustrative; no real system, secret, or weaponized payload is referenced.

id: API-007
severity: High
priority: P1
confidence: Confirmed
status: Open
category: Broken Object Level Authorization (IDOR / BOLA)
cwe: CWE-639
owasp: A01:2021 / API1:2023
-->

## [API-007] Any authenticated user can read other users' invoices via `GET /api/invoices/:id`

| Field | Value |
|---|---|
| **Severity** | High |
| **Priority** | P1 |
| **Confidence** | Confirmed |
| **Status** | Open |
| **Category** | Broken Object Level Authorization (IDOR / BOLA) |
| **CWE / OWASP** | CWE-639 / A01:2021 / API1:2023 |

### Affected asset
Billing API (backend service).

### Affected files
- `src/modules/billing/invoice.controller.ts:88` — `getInvoiceById()`
- `src/modules/billing/invoice.service.ts:42` — `findById()`

### Affected routes / endpoints
- `GET /api/invoices/:id`

### Description
The invoice lookup loads a record by its primary key taken directly from the URL and returns it without verifying that
the invoice belongs to the authenticated caller. The route is protected by an authentication guard (any logged-in user
can reach it) but has no **object-level** authorization. Because invoice IDs are sequential integers, an authenticated
user can enumerate and read other tenants' invoices.

Data flow: `req.params.id` (untrusted) → `invoiceService.findById(id)` → record returned to the client. No ownership
or tenant scoping is applied at any step.

### Evidence
Evidence type: **static** (verified code path) and **dynamic** (reproduced on staging with test accounts).

```text
File: src/modules/billing/invoice.controller.ts:88  (getInvoiceById, GET /api/invoices/:id)

  @UseGuards(AuthGuard)                       // authentication only
  async getInvoiceById(@Param('id') id: string) {
    return this.invoiceService.findById(id);  // <-- no check that invoice.userId === request.user.id
  }
```

```text
File: src/modules/billing/invoice.service.ts:42

  findById(id: string) {
    return this.repo.findOne({ where: { id } });   // <-- not scoped to the caller / tenant
  }
```

### Impact
Any authenticated user can read any invoice by ID, exposing other customers' billing data (amounts, line items, and
associated personal/business details). This is a confidentiality breach across tenants and a likely trigger for
customer-trust and contractual fallout.

### Preconditions
- A valid authenticated session (any role; no special privileges needed).
- Knowledge or guessing of a target invoice ID (sequential IDs make this trivial).

### Safe reproduction steps
1. Authenticate as test user A on staging.
2. Note that invoice `1042` belongs to test user B.
3. Send `GET /api/invoices/1042` with user A's session.
4. Observe `200 OK` returning user B's invoice → confirms missing object-level authorization.

(No data was modified; only a read was performed with test accounts in the authorized environment.)

### Recommended fix
Enforce ownership/tenant scoping at the data layer so the object can only be retrieved by an authorized caller:

```ts
// invoice.service.ts
findForUser(id: string, userId: string) {
  return this.repo.findOne({ where: { id, userId } }); // scope to the caller
}
```
Return `404 Not Found` (not `403`) to avoid confirming the existence of other users' resources. Audit sibling
endpoints (`/api/invoices`, `/api/payments/:id`, `/api/subscriptions/:id`) for the same pattern and centralize the
ownership check in a reusable guard/policy so it cannot be forgotten.

### Suggested tests
- Security regression test: user A requesting user B's invoice returns `404` (fails on current code, passes after fix).
- Positive test: user A can still retrieve their own invoice.
- Add a shared test helper asserting object-level authz for all `/:id` billing routes.

### References
- OWASP API1:2023 — Broken Object Level Authorization.
- OWASP A01:2021 — Broken Access Control.
- CWE-639 — Authorization Bypass Through User-Controlled Key.

### Notes
Confidence is Confirmed: the missing check is visible in code and was reproduced safely on staging. No compensating
control (global ownership middleware, row-level security) was found. Likely systemic — recommend reviewing all
object-by-ID endpoints, not just billing.
