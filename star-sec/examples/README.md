# Examples

Reference outputs that show the **depth, tone, and structure** Star Sec Auditor aims for. Everything here is
fictional and sanitized — illustrative format, not a real assessment. There are no live secrets, real targets, or
weaponized payloads.

| File | What it shows |
|---|---|
| [`example-finding.md`](./example-finding.md) | A single, fully written finding (IDOR/BOLA) using the finding template — metadata header, evidence, impact, safe reproduction, fix, and tests. |
| [`example-final-report.md`](./example-final-report.md) | A complete sample security report for a fictional SaaS, covering all report sections from executive summary to CI/CD gates. |

## How to use these

- **As a quality bar.** When producing real findings/reports, match this level of specificity: cite `file:line`,
  state real impact and preconditions, give a concrete fix and a regression test, and label confidence honestly.
- **As input to the report builder.** `example-finding.md` follows the same metadata format the builder parses, so
  you can drop finding files into `reports/findings/` and run:
  ```bash
  python ../scripts/report_builder.py --findings reports/findings/ --out reports/final-security-report.md
  ```
- **As a template starter.** Copy the structure, then replace every placeholder with audited facts.

## Safety reminder

These samples intentionally avoid offensive payloads. Real findings must follow
[`../references/evidence-guidelines.md`](../references/evidence-guidelines.md): mask all secrets/PII, keep PoCs minimal
and non-destructive, and only run dynamic tests against authorized `localhost`/staging environments.
