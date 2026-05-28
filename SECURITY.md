# Security Policy

Star-Sec-Skill is a **defensive** security-auditing skill. This policy explains how to report a problem with the
skill itself, and how to use it responsibly.

## Reporting a vulnerability in this project

If you find a security issue **in this repository** (for example, a script that behaves unsafely, leaks data, or could
be abused), please report it privately first:

- **Email:** af.mairink@gmail.com
- Use a subject line starting with `[SECURITY] star-sec-skill`.
- Include a description, affected file(s), reproduction steps, and impact. Mask any real secrets in your report.

Please do **not** open a public issue for an unfixed vulnerability. We aim to acknowledge reports within a few days
and will coordinate a fix and disclosure timeline with you.

## Scope

In scope:

- The Python helper scripts in `star-sec/scripts/`.
- The skill instructions, templates, and references that could cause unsafe behavior if followed.

Out of scope:

- Findings produced *by* the skill about *your own* applications — those belong in your project's own process.
- Vulnerabilities in third-party tools the skill can invoke (`semgrep`, `trivy`, `gitleaks`, etc.). Report those
  upstream.

## Responsible use

This skill is built for **authorized, defensive** work only. By using it you agree to:

- Audit only systems you **own** or are **explicitly authorized** to assess.
- Run dynamic tests only against `localhost`, authorized staging, or an environment the owner has designated.
- Keep proof-of-concepts minimal and **non-destructive** — demonstrate, don't damage.
- Never exfiltrate secrets or personal data, and **mask** sensitive values in reports.
- Never use the skill to attack third-party systems without written permission.

The skill does not guarantee that an application is free of vulnerabilities. See the Limitations section of any
generated report and the project README.

## Handling generated reports

Audit reports can contain sensitive details about real systems. Treat `reports/` output as confidential: it is
git-ignored by default — keep it that way, store it securely, and share it only with authorized stakeholders.
