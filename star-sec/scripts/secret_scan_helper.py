#!/usr/bin/env python3
"""secret_scan_helper.py — Star Sec Auditor / Phase 3 & 9 (Secret detection).

Scan a repository for likely hardcoded secrets using local regex patterns. Every
reported value is MASKED — the script never prints or stores a usable secret. It
reports the location (file:line), the secret type, a masked preview, and a
confidence level so triage is fast.

This is a helper, not a replacement for gitleaks/trufflehog (run those too if
available). It complements them with a safe, dependency-free local pass.

Safety:
  * Read-only and network-free. Does not modify the target project.
  * Masks all detected values; full secrets are never emitted.
  * Skips node_modules/.git/dist/build/target/vendor and binary files.

Usage:
  python secret_scan_helper.py <path> [--out reports/raw/secrets.json]
                               [--max-bytes N] [--include-examples] [--quiet]
  python secret_scan_helper.py --help
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit",
    "target", "vendor", "venv", ".venv", "env", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".gradle", ".idea", ".vscode", "coverage", ".turbo", ".cache",
    "bin", "obj", "Pods", ".terraform", "site-packages",
}

# Binary-ish extensions to skip outright.
SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz",
    ".tar", ".rar", ".7z", ".mp4", ".mp3", ".wav", ".mov", ".woff", ".woff2", ".ttf",
    ".eot", ".otf", ".class", ".jar", ".so", ".dll", ".dylib", ".bin", ".exe", ".wasm",
    ".lock",  # lockfiles are huge and rarely hold secrets; gitleaks covers edge cases
}

# Files whose names suggest placeholders (lower the confidence, unless --include-examples raises focus).
EXAMPLE_HINTS = ("example", "sample", "template", "dist", "test", "spec", "fixture", "mock")

# Each rule: (name, compiled regex, base_confidence, group_with_value)
# group_with_value = index of the capture group holding the secret to mask (0 = whole match).
RULES = [
    ("AWS Access Key ID",      re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),                              "High",   0),
    ("AWS Secret Access Key",  re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"), "High", 1),
    ("Stripe Secret Key",      re.compile(r"\b(sk_live|rk_live)_[0-9a-zA-Z]{16,}\b"),                    "High",   0),
    ("Stripe Test Key",        re.compile(r"\b(sk_test|rk_test)_[0-9a-zA-Z]{16,}\b"),                    "Medium", 0),
    ("GitHub Token",           re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b"),               "High",   0),
    ("GitHub Fine-grained",    re.compile(r"\bgithub_pat_[0-9A-Za-z_]{60,}\b"),                          "High",   0),
    ("Google API Key",         re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),                                "High",   0),
    ("Google OAuth Client",    re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"), "Medium", 0),
    ("Slack Token",            re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),                          "High",   0),
    ("Slack Webhook",          re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),          "Medium", 0),
    ("Twilio Account SID",     re.compile(r"\bAC[0-9a-fA-F]{32}\b"),                                     "Medium", 0),
    ("SendGrid Key",           re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"),            "High",   0),
    ("OpenAI Key",             re.compile(r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b"),           "High",   0),
    ("Anthropic Key",          re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),                            "High",   0),
    ("JWT",                    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "Low", 0),
    ("Private Key Block",      re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "High",   0),
    ("Database URL w/ creds",  re.compile(r"\b(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:@/'\"]+:([^\s:@/'\"]+)@"), "High", 3),
    ("Generic Secret Assign",  re.compile(r"(?i)\b(api[_-]?key|secret|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"), "Medium", 2),
    ("Bearer Token",           re.compile(r"(?i)bearer\s+([A-Za-z0-9_\-\.=]{20,})"),                     "Low",    1),
]

# Obvious placeholder values that should never be flagged as real secrets.
PLACEHOLDER_VALUES = re.compile(
    r"(?i)^(?:x{3,}|y{3,}|\.{3,}|<[^>]+>|your[_-]?|changeme|placeholder|example|dummy|test|fake|"
    r"redacted|none|null|true|false|todo|xxxxx|\*+|\$\{?[a-z_]+\}?|process\.env|os\.environ).*"
)


def shannon_entropy(s: str) -> float:
    """Bits-per-char Shannon entropy — used to downrank low-entropy false hits."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def mask(value: str) -> str:
    """Return a non-recoverable masked preview of a secret value."""
    if value is None:
        return ""
    v = value.strip()
    if len(v) <= 8:
        return (v[:1] + "…<redacted>") if v else "<redacted>"
    return f"{v[:4]}…{v[-2:]} <redacted, len={len(v)}>"


def looks_like_placeholder(value: str) -> bool:
    v = (value or "").strip()
    if not v:
        return True
    if PLACEHOLDER_VALUES.match(v):
        return True
    # Repeated single char or clearly non-random short token.
    if len(set(v)) <= 2:
        return True
    return False


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if Path(name).suffix.lower() in SKIP_EXTS:
                continue
            yield Path(dirpath) / name


def is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(1024)
    except OSError:
        return True


def adjust_confidence(base: str, value: str, is_example_file: bool) -> str:
    order = ["Low", "Medium", "High"]
    idx = order.index(base)
    ent = shannon_entropy(value or "")
    if ent and ent < 3.0:        # very low entropy -> likely not a real secret
        idx = max(0, idx - 1)
    if is_example_file:          # placeholder-ish file -> downrank
        idx = max(0, idx - 1)
    return order[idx]


def scan_file(path: Path, root: Path, max_bytes: int, include_examples: bool) -> list[dict]:
    try:
        if path.stat().st_size > max_bytes:
            return []
    except OSError:
        return []
    if is_binary(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    rel = os.path.relpath(path, root).replace(os.sep, "/")
    low_name = path.name.lower()
    is_example_file = any(h in low_name for h in EXAMPLE_HINTS)
    findings: list[dict] = []

    for idx, line in enumerate(lines, start=1):
        if len(line) > 4000:  # skip minified blobs
            continue
        for name, pat, base_conf, grp in RULES:
            m = pat.search(line)
            if not m:
                continue
            try:
                value = m.group(grp) if grp else m.group(0)
            except (IndexError, re.error):
                value = m.group(0)
            if value and looks_like_placeholder(value):
                continue
            # Skip example files unless explicitly included.
            if is_example_file and not include_examples:
                continue
            findings.append({
                "file": rel,
                "line": idx,
                "type": name,
                "masked": mask(value),
                "confidence": adjust_confidence(base_conf, value or "", is_example_file),
                "is_example_file": is_example_file,
            })
            break  # one finding per line is enough for triage
    return findings


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="secret_scan_helper.py",
        description="Star Sec Auditor — local, masked secret detection with confidence scoring.",
        epilog="Read-only, network-free. Never prints full secrets. Report location+type; recommend rotation.",
    )
    p.add_argument("path", nargs="?", default=".", help="Repository root (default: current dir).")
    p.add_argument("--out", default="reports/raw/secrets.json", help="Output JSON (default: reports/raw/secrets.json).")
    p.add_argument("--max-bytes", type=int, default=1_000_000, help="Skip files larger than this (default: 1MB).")
    p.add_argument("--include-examples", action="store_true",
                   help="Also scan example/sample/template/test files (downranked by default; skipped without this).")
    p.add_argument("--quiet", action="store_true", help="Suppress the summary on stderr.")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"[secret_scan_helper] Error: '{root}' is not a directory.", file=sys.stderr)
        return 2

    findings: list[dict] = []
    files_scanned = 0
    try:
        for path in iter_files(root):
            files_scanned += 1
            findings.extend(scan_file(path, root, args.max_bytes, args.include_examples))
    except Exception as exc:
        print(f"[secret_scan_helper] Unexpected error: {exc}", file=sys.stderr)
        return 1

    by_conf = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        by_conf[f["confidence"]] = by_conf.get(f["confidence"], 0) + 1

    report = {
        "tool": "secret_scan_helper",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "note": "All values masked. Confirm by reading the cited line. Treat any real exposure as rotate-now.",
        "summary": {"files_scanned": files_scanned, "findings": len(findings), "by_confidence": by_conf},
        "findings": findings,
    }

    out_path = Path(args.out)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    except OSError as exc:
        print(f"[secret_scan_helper] Error writing '{out_path}': {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"[secret_scan_helper] Scanned {files_scanned} files; {len(findings)} candidate secret(s).")
        print(f"[secret_scan_helper] Confidence — High: {by_conf['High']}  Medium: {by_conf['Medium']}  Low: {by_conf['Low']}")
        for f in findings[:15]:
            print(f"    [{f['confidence']:6s}] {f['type']:24s} {f['file']}:{f['line']}  {f['masked']}")
        if len(findings) > 15:
            print(f"    ... and {len(findings) - 15} more (see {out_path}).")
        print(f"[secret_scan_helper] Wrote: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
