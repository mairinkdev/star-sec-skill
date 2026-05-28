# Contributing to Star-Sec-Skill

Thanks for your interest in improving Star-Sec-Skill. This project is a **defensive** Claude Code skill for authorized
application-security audits. Contributions that make audits more accurate, safer, or clearer are very welcome.

## Ground rules

This is a defensive-only project. We will **not** accept contributions that:

- Add offensive tooling, weaponized exploits, or destructive payloads.
- Help attack third-party systems without authorization.
- Exfiltrate secrets or personal data, or print full secrets to output.
- Promise that an application is "100% secure" or otherwise overstate assurance.

Everything here should help someone audit a system they own or are authorized to assess, and report findings honestly.

## Ways to contribute

- **References & checklists** (`star-sec/references/`) — new stack coverage, sharper review playbooks, better CWE/OWASP
  mapping.
- **Templates** (`star-sec/templates/`) — clearer finding/report structures.
- **Scripts** (`star-sec/scripts/`) — improved detection, fewer false positives, better cross-platform behavior.
- **Examples** (`star-sec/examples/`) — additional sanitized, fictional samples.
- **Docs** — README, fixes, clarifications.

## Script requirements

Helper scripts must stay safe by default. A script contribution should:

- Target **Python 3** and use only the standard library where possible (no mandatory third-party installs).
- Provide `argparse` with a useful `--help`.
- Be **network-free** — never send project data anywhere.
- **Not modify** the audited project by default; write output only under `reports/`.
- Handle errors gracefully so a single failure doesn't abort an audit.
- **Mask** any secret-like values — never print a usable secret.

Before opening a PR, verify each script compiles and its help works:

```bash
python -m py_compile star-sec/scripts/*.py
python star-sec/scripts/repo_recon.py --help
python star-sec/scripts/security_inventory.py --help
python star-sec/scripts/dependency_audit_helper.py --help
python star-sec/scripts/secret_scan_helper.py --help
python star-sec/scripts/report_builder.py --help
```

## Editing the skill

- Keep `SKILL.md` lean — it is the orchestrator. Detailed guidance belongs in `references/`.
- Keep the `description` in the frontmatter accurate for auto-triggering: it should match real audit requests without
  over-triggering on unrelated tasks.
- Prefer explaining **why** a check matters over rigid "ALWAYS/NEVER" rules, so the model can reason about edge cases.

## Pull request process

1. Fork the repo and create a topic branch.
2. Make focused changes with clear commit messages.
3. Run the script checks above; sanitize any example data (no real secrets, hosts, or PII).
4. Open a PR describing **what** changed and **why**, and how you verified it.
5. Be responsive to review feedback. By contributing, you agree your work is licensed under the project's
   [MIT License](./LICENSE).

## Reporting issues

- For **bugs / feature ideas**, open a GitHub issue with steps to reproduce or a clear use case.
- For a **security problem in this project**, follow [SECURITY.md](./SECURITY.md) and report privately first.

All participation is governed by our [Code of Conduct](./CODE_OF_CONDUCT.md).
