#!/usr/bin/env python3
"""dependency_audit_helper.py — Star Sec Auditor / Phase 3 (Dependency audit).

Detect which package managers a project uses and map them to the appropriate
*read-only* vulnerability-audit command. By default it only PRINTS a plan (which
commands it would run and whether each tool is installed). Pass --run to execute
the available commands and save their raw output under reports/raw/.

Safety:
  * Never installs anything. Only runs allowlisted audit subcommands.
  * The script makes no network calls itself. The underlying audit tools may
    consult their advisory databases — only run them in an environment where you
    are authorized to do so. Execution is opt-in (--run).
  * Missing tools are recorded as "not available"; the audit continues.
  * Commands are invoked as argument lists (no shell), so there is no shell
    injection surface.

Usage:
  python dependency_audit_helper.py <path>                 # plan only (safe default)
  python dependency_audit_helper.py <path> --run           # execute available audits
  python dependency_audit_helper.py <path> --out-dir reports/raw --timeout 180
  python dependency_audit_helper.py --help
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Manifest/lockfile -> audit plan.
#   detect:  file whose presence enables this plan
#   tool:    executable that must exist on PATH
#   argv:    argument list to run (read-only audit command)
#   note:    guidance shown in the plan
AUDIT_PLANS = [
    {"id": "pnpm",      "detect": "pnpm-lock.yaml",     "tool": "pnpm",        "argv": ["pnpm", "audit", "--json"],          "note": "pnpm dependency audit"},
    {"id": "yarn",      "detect": "yarn.lock",          "tool": "yarn",        "argv": ["yarn", "npm", "audit", "--json"],    "note": "yarn (berry) audit; for classic yarn use 'yarn audit --json'"},
    {"id": "npm",       "detect": "package-lock.json",  "tool": "npm",         "argv": ["npm", "audit", "--json"],            "note": "npm dependency audit"},
    {"id": "npm-nolock","detect": "package.json",       "tool": "npm",         "argv": ["npm", "audit", "--json"],            "note": "npm audit (no lockfile present; may be limited)"},
    {"id": "pip-audit", "detect": "requirements.txt",   "tool": "pip-audit",   "argv": ["pip-audit", "-r", "requirements.txt", "-f", "json"], "note": "pip-audit on requirements.txt"},
    {"id": "pip-proj",  "detect": "pyproject.toml",     "tool": "pip-audit",   "argv": ["pip-audit", "-f", "json"],           "note": "pip-audit on the current environment/project"},
    {"id": "safety",    "detect": "requirements.txt",   "tool": "safety",      "argv": ["safety", "check", "-r", "requirements.txt", "--json"], "note": "safety check (alternative to pip-audit)"},
    {"id": "cargo",     "detect": "Cargo.toml",         "tool": "cargo-audit", "argv": ["cargo", "audit", "--json"],          "note": "cargo audit (requires cargo-audit)"},
    {"id": "go",        "detect": "go.mod",             "tool": "govulncheck", "argv": ["govulncheck", "-json", "./..."],     "note": "govulncheck on Go modules"},
    {"id": "composer",  "detect": "composer.lock",      "tool": "composer",    "argv": ["composer", "audit", "--format=json"],"note": "composer audit"},
    {"id": "bundler",   "detect": "Gemfile.lock",       "tool": "bundle-audit","argv": ["bundle-audit", "check"],             "note": "bundler-audit (gem install bundler-audit)"},
    {"id": "osv",       "detect": "*",                  "tool": "osv-scanner", "argv": ["osv-scanner", "--format", "json", "--recursive", "."], "note": "osv-scanner across all lockfiles (if installed)"},
]


def manifest_present(root: Path, detect: str) -> bool:
    if detect == "*":
        return True
    return (root / detect).exists()


def build_plans(root: Path) -> list[dict]:
    """Return the applicable audit plans for this repo, deduped by tool+argv."""
    plans: list[dict] = []
    seen: set[str] = set()
    for plan in AUDIT_PLANS:
        if not manifest_present(root, plan["detect"]):
            continue
        # Avoid running both npm and npm-nolock when a lockfile exists.
        if plan["id"] == "npm-nolock" and (root / "package-lock.json").exists():
            continue
        key = plan["tool"] + " ".join(plan["argv"])
        if key in seen:
            continue
        seen.add(key)
        tool_path = shutil.which(plan["tool"])
        plans.append({
            **plan,
            "available": tool_path is not None,
            "tool_path": tool_path or "not available",
            "command": " ".join(plan["argv"]),
        })
    return plans


def run_plan(plan: dict, root: Path, out_dir: Path, timeout: int) -> dict:
    """Execute one audit plan and persist raw output. Never raises."""
    result = {"id": plan["id"], "command": plan["command"], "status": "skipped",
              "exit_code": None, "output_file": None, "error": None}
    if not plan["available"]:
        result["status"] = "not available"
        return result
    try:
        proc = subprocess.run(
            plan["argv"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,           # audit tools exit non-zero when vulns are found
            shell=False,           # no shell — argv list only
        )
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"dep_audit_{plan['id']}.txt"
        with open(out_file, "w", encoding="utf-8", errors="ignore") as fh:
            fh.write(f"$ {plan['command']}\n(exit code: {proc.returncode})\n\n")
            fh.write("===== STDOUT =====\n")
            fh.write(proc.stdout or "")
            fh.write("\n\n===== STDERR =====\n")
            fh.write(proc.stderr or "")
        result["status"] = "ran"
        result["exit_code"] = proc.returncode
        result["output_file"] = str(out_file)
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = f"exceeded {timeout}s"
    except Exception as exc:  # keep the audit alive no matter what
        result["status"] = "error"
        result["error"] = str(exc)
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="dependency_audit_helper.py",
        description="Star Sec Auditor — detect package managers and run safe, available dependency audits.",
        epilog="Safe by default: prints a plan. Use --run to execute. Never installs anything.",
    )
    p.add_argument("path", nargs="?", default=".", help="Repository root (default: current dir).")
    p.add_argument("--run", action="store_true", help="Execute available audit commands (default: plan only).")
    p.add_argument("--out-dir", default="reports/raw", help="Where to save raw output (default: reports/raw).")
    p.add_argument("--timeout", type=int, default=300, help="Per-command timeout in seconds (default: 300).")
    p.add_argument("--quiet", action="store_true", help="Suppress the human-readable summary.")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"[dependency_audit_helper] Error: '{root}' is not a directory.", file=sys.stderr)
        return 2

    plans = build_plans(root)
    report = {
        "tool": "dependency_audit_helper",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "executed": bool(args.run),
        "plans": plans,
        "results": [],
    }

    if not args.quiet:
        print(f"[dependency_audit_helper] Detected {len(plans)} applicable audit plan(s) under {root}")
        for plan in plans:
            avail = "available" if plan["available"] else "NOT available"
            print(f"    [{plan['id']:10s}] {plan['command']}  ({avail})")

    if args.run:
        out_dir = Path(args.out_dir)
        for plan in plans:
            res = run_plan(plan, root, out_dir, args.timeout)
            report["results"].append(res)
            if not args.quiet:
                print(f"[dependency_audit_helper] {plan['id']}: {res['status']}"
                      + (f" -> {res['output_file']}" if res.get("output_file") else ""))
        # Persist the run manifest alongside raw outputs.
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            with open(out_dir / "dep_audit_manifest.json", "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
        except OSError as exc:
            print(f"[dependency_audit_helper] Warning: could not write manifest: {exc}", file=sys.stderr)
    else:
        if not args.quiet:
            print("[dependency_audit_helper] Plan only. Re-run with --run to execute available audits.")
        # Still emit the plan as JSON for the report.
        try:
            out_dir = Path(args.out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            with open(out_dir / "dep_audit_plan.json", "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2)
        except OSError:
            pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
