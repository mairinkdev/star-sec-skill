#!/usr/bin/env python3
"""security_inventory.py — Star Sec Auditor / Phase 1 (Attack-surface inventory).

Scan source files for security-relevant surfaces — routes/endpoints, middleware,
and auth / admin / webhook / upload / payment handlers — and emit a JSON map so
manual review (Phase 4) can start at the highest-risk code first.

This is a heuristic locator, not a vulnerability scanner: it points you at code
worth reading. Expect false positives; confirm by reading the cited lines.

Safety:
  * Read-only and network-free. Does not modify the target project.
  * Skips heavy/irrelevant dirs and binary files.

Usage:
  python security_inventory.py <path> [--out reports/inventory.json]
                               [--max-bytes N] [--context N] [--quiet]
  python security_inventory.py --help
"""

from __future__ import annotations

import argparse
import json
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

# Only scan source-like files.
CODE_EXTS = {
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rb", ".php", ".go",
    ".rs", ".java", ".kt", ".cs", ".vue", ".svelte", ".scala",
}

# Each category maps to a list of compiled regexes. Patterns are intentionally
# broad across frameworks; the goal is recall (find candidates), then a human
# confirms. Case-insensitive where helpful.
RAW_PATTERNS: dict[str, list[str]] = {
    "routes": [
        r"\b(app|router|api|route|r)\.(get|post|put|patch|delete|all|head|options)\s*\(",  # express/koa/fastify
        r"@(Get|Post|Put|Patch|Delete|All|RequestMapping|GetMapping|PostMapping)\s*\(",     # nest/spring
        r"@app\.(route|get|post|put|patch|delete)\s*\(",                                     # flask/fastapi
        r"@(router|app)\.(get|post|put|patch|delete)\s*\(",                                  # fastapi router
        r"\bpath\s*\(\s*['\"]",                                                               # django urls
        r"\b(HandleFunc|GET|POST|PUT|PATCH|DELETE)\s*\(\s*['\"]",                             # go routers
        r"Route::(get|post|put|patch|delete|any|match)\s*\(",                                # laravel
        r"\b(get|post|put|patch|delete)\s+['\"]/",                                            # rails/sinatra-ish
        r"\b(routes\.MapControllerRoute|MapGet|MapPost|MapPut|MapDelete)\s*\(",               # .net minimal
    ],
    "middleware": [
        r"\b(app|router)\.use\s*\(",
        r"\buse[A-Z]\w*Middleware\b",
        r"@UseGuards\s*\(", r"@UseInterceptors\s*\(",
        r"\bbefore_action\b", r"\bbefore_request\b",
        r"\bDepends\s*\(",                       # fastapi dependency injection (often auth)
        r"\bmiddleware\b\s*[:=]",
    ],
    "auth": [
        r"\b(authenticate|authorize|requireAuth|isAuthenticated|ensureAuth|checkAuth)\b",
        r"\b(login|signin|sign_in|logout|signout|sign_out)\b",
        r"\b(jwt|jsonwebtoken|verifyToken|signToken|decodeToken)\b",
        r"\b(bcrypt|argon2|scrypt|pbkdf2|hashPassword|comparePassword)\b",
        r"\b(passport|next-auth|@auth|lucia|clerk|supabase\.auth|firebase\.auth)\b",
        r"\b(session|refreshToken|refresh_token|accessToken|access_token)\b",
        r"@login_required\b", r"@PreAuthorize\s*\(", r"\[Authorize\]",
        r"\b(oauth|oidc|openid|saml|mfa|totp|otp)\b",
        r"\bpassword[_-]?reset\b|\bforgot[_-]?password\b|\breset[_-]?token\b",
    ],
    "admin": [
        r"['\"/]admin\b", r"\bisAdmin\b|\bis_admin\b|\brequireAdmin\b",
        r"\brole\s*===?\s*['\"]admin['\"]", r"\bROLE_ADMIN\b",
        r"\b(superuser|is_staff|hasRole\s*\(\s*['\"]admin)", r"\bimpersonat",
    ],
    "webhook": [
        r"\bwebhook[s]?\b", r"\b(stripe|paypal|razorpay|paddle|lemonsqueezy)\b.*\b(webhook|event)\b",
        r"\bconstructEvent\b", r"\bverify(Webhook|Signature)\b", r"\bX-Hub-Signature\b",
        r"\bsignature\b.*\b(header|verify|hmac)\b", r"\bwebhookSecret|WEBHOOK_SECRET\b",
    ],
    "upload": [
        r"\b(multer|formidable|busboy|multipart)\b",
        r"\bupload[s]?\b", r"\bsaveFile|writeFile|createWriteStream\b.*\breq\b",
        r"\bFile(s)?\s*=\s*request|request\.files\b", r"\b@FileInterceptor\b",
        r"\bMultipartFile\b", r"\bActiveStorage\b", r"\bIFormFile\b",
        r"\b(s3|putObject|bucket)\b.*\bupload\b",
    ],
    "payment": [
        r"\b(stripe|paypal|braintree|razorpay|paddle|lemonsqueezy|adyen|square)\b",
        r"\b(charge|paymentIntent|payment_intent|checkout|createOrder|capturePayment)\b",
        r"\b(refund|payout|invoice|subscription|price|amount|currency)\b.*\b(create|update|confirm)\b",
        r"\bidempotency[_-]?key\b",
    ],
    "dangerous_sinks": [
        r"\b(eval|exec|execSync|execFile|spawnSync|child_process|system|popen|shell_exec|Runtime\.getRuntime)\b",
        r"\bdangerouslySetInnerHTML\b|\bv-html\b|\.innerHTML\s*=", r"\bbypassSecurityTrust",
        r"\b(pickle\.loads|yaml\.load\b|unserialize|Marshal\.load|BinaryFormatter)\b",
        r"\b(query|raw|queryRawUnsafe|\$queryRawUnsafe|literal)\s*\(",  # potential raw SQL
        r"\brequests?\.(get|post)\s*\(\s*[^'\")]*\b(url|req|input|param)",  # potential SSRF
    ],
    "secrets_inline_hint": [
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|private[_-]?key)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]",
    ],
}

COMPILED: dict[str, list[re.Pattern]] = {
    cat: [re.compile(p, re.IGNORECASE) for p in pats] for cat, pats in RAW_PATTERNS.items()
}


def iter_code_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if Path(name).suffix.lower() in CODE_EXTS:
                yield Path(dirpath) / name


def scan_file(path: Path, root: Path, max_bytes: int) -> list[dict]:
    """Return a list of hits for one file. Never raises."""
    try:
        if path.stat().st_size > max_bytes:
            return []
    except OSError:
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    rel = os.path.relpath(path, root).replace(os.sep, "/")
    hits: list[dict] = []
    for idx, line in enumerate(lines, start=1):
        if len(line) > 2000:  # skip minified/giant lines
            continue
        for category, patterns in COMPILED.items():
            for pat in patterns:
                if pat.search(line):
                    snippet = line.strip()
                    # For the inline-secret hint, mask the quoted value so we never echo it.
                    if category == "secrets_inline_hint":
                        snippet = re.sub(r"(['\"])[^'\"]{6,}(['\"])", r"\1<redacted>\2", snippet)
                    hits.append({
                        "file": rel,
                        "line": idx,
                        "category": category,
                        "match": snippet[:240],
                    })
                    break  # one hit per category per line is enough
    return hits


def build_inventory(root: Path, max_bytes: int, quiet: bool) -> dict:
    by_category: dict[str, list[dict]] = {cat: [] for cat in RAW_PATTERNS}
    files_scanned = 0
    for path in iter_code_files(root):
        files_scanned += 1
        for hit in scan_file(path, root, max_bytes):
            by_category[hit["category"]].append(hit)

    counts = {cat: len(items) for cat, items in by_category.items()}
    # Files that touch the most sensitive categories — good places to start.
    sensitive = ("auth", "admin", "webhook", "upload", "payment", "dangerous_sinks")
    hot_files: dict[str, int] = {}
    for cat in sensitive:
        for hit in by_category[cat]:
            hot_files[hit["file"]] = hot_files.get(hit["file"], 0) + 1
    hotspots = sorted(hot_files.items(), key=lambda kv: kv[1], reverse=True)[:25]

    if not quiet:
        print(f"[security_inventory] Scanned {files_scanned} source files under {root}", file=sys.stderr)

    return {
        "tool": "security_inventory",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "note": "Heuristic locator. Confirm each hit by reading the cited line. Expect false positives.",
        "summary": {"files_scanned": files_scanned, "counts": counts},
        "hotspot_files": [{"file": f, "sensitive_hits": n} for f, n in hotspots],
        "surfaces": by_category,
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="security_inventory.py",
        description="Star Sec Auditor — locate routes/middleware/auth/admin/webhook/upload/payment handlers.",
        epilog="Heuristic, read-only, network-free. Confirm hits by reading the code.",
    )
    p.add_argument("path", nargs="?", default=".", help="Repository root (default: current dir).")
    p.add_argument("--out", default="reports/inventory.json", help="Output JSON path (default: reports/inventory.json).")
    p.add_argument("--max-bytes", type=int, default=1_500_000, help="Skip files larger than this (default: 1.5MB).")
    p.add_argument("--quiet", action="store_true", help="Suppress the summary on stderr.")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"[security_inventory] Error: '{root}' is not a directory.", file=sys.stderr)
        return 2

    try:
        inventory = build_inventory(root, args.max_bytes, args.quiet)
    except Exception as exc:
        print(f"[security_inventory] Unexpected error: {exc}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(inventory, fh, indent=2)
    except OSError as exc:
        print(f"[security_inventory] Error writing '{out_path}': {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        counts = inventory["summary"]["counts"]
        print("[security_inventory] Candidate surfaces by category:")
        for cat, n in counts.items():
            print(f"    {cat:20s} {n}")
        print(f"[security_inventory] Top hotspot files: {len(inventory['hotspot_files'])}")
        print(f"[security_inventory] Wrote inventory: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
