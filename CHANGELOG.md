# Changelog

All notable changes to Star-Sec-Skill are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-05-28

### Added
- Initial release of **Star Sec Auditor**, a defensive Claude Code skill for authorized application-security audits.
- `SKILL.md` orchestrator driving an eight-phase workflow (scope guard → recon → threat model → automated baseline →
  manual secure code review → DAST → risk validation → remediation planning → final report).
- Seven reference documents: methodology, severity model, vulnerability taxonomy, evidence guidelines, stack-specific
  checklists, secure-review playbooks, and reporting guide.
- Four report templates: finding, executive report, technical report, and remediation plan.
- Five network-free, non-destructive Python helper scripts: `repo_recon.py`, `security_inventory.py`,
  `dependency_audit_helper.py`, `secret_scan_helper.py` (masked output), and `report_builder.py`.
- Sanitized, fictional examples: a single finding and a full final report.
- Repository files: `README.md`, `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`,
  `.gitignore`, and `examples/README.md`.

[Unreleased]: https://github.com/mairinkdev/star-sec-skill/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/mairinkdev/star-sec-skill/releases/tag/v1.0.0
