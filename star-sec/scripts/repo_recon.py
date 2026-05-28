#!/usr/bin/env python3
"""repo_recon.py — Star Sec Auditor / Phase 1 (Repository Recon).

Build a deterministic, read-only inventory of a codebase: languages, package
managers, frameworks (best-effort), Docker/CI files, env examples, and likely
entrypoints. Output is JSON for downstream phases.

Safety:
  * Read-only. Never modifies the target project.
  * Network-free. Performs no outbound connections.
  * Skips heavy/irrelevant dirs (node_modules, .git, dist, build, target, ...).

Usage:
  python repo_recon.py <path> [--out reports/recon.json] [--max-files N] [--quiet]
  python repo_recon.py --help
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Directories we never descend into — noise or huge, and not the audit target.
SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit",
    "target", "vendor", "venv", ".venv", "env", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".gradle", ".idea", ".vscode", "coverage", ".turbo", ".cache",
    "bin", "obj", "Pods", ".terraform", "site-packages",
}

# Extension -> language label (best-effort; covers common web stacks).
EXT_LANG = {
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".py": "Python", ".rb": "Ruby", ".php": "PHP", ".go": "Go", ".rs": "Rust",
    ".java": "Java", ".kt": "Kotlin", ".cs": "C#", ".scala": "Scala",
    ".vue": "Vue", ".svelte": "Svelte",
    ".sql": "SQL", ".sh": "Shell", ".ps1": "PowerShell",
    ".yml": "YAML", ".yaml": "YAML", ".tf": "Terraform", ".dockerfile": "Docker",
}

# Manifest filename -> (package manager, ecosystem).
PACKAGE_MANIFESTS = {
    "package.json": ("npm/yarn/pnpm", "node"),
    "pnpm-lock.yaml": ("pnpm", "node"),
    "yarn.lock": ("yarn", "node"),
    "package-lock.json": ("npm", "node"),
    "requirements.txt": ("pip", "python"),
    "pyproject.toml": ("pip/poetry/uv", "python"),
    "Pipfile": ("pipenv", "python"),
    "poetry.lock": ("poetry", "python"),
    "Cargo.toml": ("cargo", "rust"),
    "go.mod": ("go modules", "go"),
    "composer.json": ("composer", "php"),
    "Gemfile": ("bundler", "ruby"),
    "pom.xml": ("maven", "java"),
    "build.gradle": ("gradle", "java"),
    "build.gradle.kts": ("gradle", "java"),
    "*.csproj": ("dotnet", "dotnet"),
}

# Substrings in dependency manifests that hint at a framework.
FRAMEWORK_HINTS = {
    "node": [
        ("next", "Next.js"), ("react", "React"), ("vue", "Vue"), ("nuxt", "Nuxt"),
        ("@angular/core", "Angular"), ("svelte", "Svelte"), ("express", "Express"),
        ("fastify", "Fastify"), ("@nestjs/core", "NestJS"), ("koa", "Koa"),
        ("hapi", "hapi"), ("hono", "Hono"),
    ],
    "python": [
        ("fastapi", "FastAPI"), ("django", "Django"), ("flask", "Flask"),
        ("starlette", "Starlette"), ("tornado", "Tornado"),
    ],
    "rust": [
        ("axum", "Axum"), ("actix-web", "Actix"), ("rocket", "Rocket"),
        ("warp", "warp"), ("sqlx", "SQLx"), ("diesel", "Diesel"),
    ],
    "go": [
        ("gin-gonic/gin", "Gin"), ("gofiber/fiber", "Fiber"), ("go-chi/chi", "Chi"),
        ("labstack/echo", "Echo"), ("gorilla/mux", "gorilla/mux"),
    ],
    "php": [("laravel/framework", "Laravel"), ("symfony/symfony", "Symfony")],
    "ruby": [("rails", "Rails"), ("sinatra", "Sinatra")],
    "java": [("spring-boot", "Spring Boot"), ("spring-web", "Spring")],
    "dotnet": [("Microsoft.AspNetCore", "ASP.NET Core")],
}

CI_MARKERS = {
    ".github/workflows": "GitHub Actions",
    ".gitlab-ci.yml": "GitLab CI",
    "azure-pipelines.yml": "Azure Pipelines",
    "Jenkinsfile": "Jenkins",
    ".circleci": "CircleCI",
    "bitbucket-pipelines.yml": "Bitbucket Pipelines",
    ".drone.yml": "Drone",
}

DOCKER_MARKERS = ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")

# Filenames that frequently hold server/CLI/worker entrypoints (best-effort).
ENTRYPOINT_HINTS = (
    "main.py", "app.py", "wsgi.py", "asgi.py", "manage.py", "server.py",
    "index.js", "index.ts", "server.js", "server.ts", "app.js", "app.ts", "main.ts", "main.js",
    "main.go", "main.rs", "Program.cs", "artisan", "config.ru",
)


def is_probably_binary(path: Path) -> bool:
    """Cheap binary sniff: a NUL byte in the first 1KB means skip text reads."""
    try:
        with open(path, "rb") as fh:
            return b"\x00" in fh.read(1024)
    except OSError:
        return True


def read_text_safe(path: Path, limit: int = 200_000) -> str:
    """Read a text file defensively; never raise, never block the audit."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def manifest_matches(name: str) -> tuple[str, str] | None:
    """Return (package_manager, ecosystem) for a manifest filename, or None."""
    if name in PACKAGE_MANIFESTS:
        return PACKAGE_MANIFESTS[name]
    if name.endswith(".csproj"):
        return PACKAGE_MANIFESTS["*.csproj"]
    return None


def scan(root: Path, max_files: int, quiet: bool) -> dict:
    """Walk the tree once and collect every signal we care about."""
    languages: Counter[str] = Counter()
    package_managers: set[str] = set()
    ecosystems: set[str] = set()
    frameworks: set[str] = set()
    docker_files: list[str] = []
    ci_systems: set[str] = set()
    env_examples: list[str] = []
    entrypoints: list[str] = []
    manifests: list[str] = []
    notable_configs: list[str] = []
    file_count = 0
    truncated = False

    config_names = {
        "tsconfig.json", "next.config.js", "next.config.mjs", "next.config.ts",
        "vite.config.ts", "vite.config.js", "webpack.config.js", "nginx.conf",
        ".env.example", ".env.sample", ".env.template", "vercel.json", "vercel.ts",
        "serverless.yml", "Procfile", "fly.toml", "railway.json", "render.yaml",
    }

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in place so os.walk does not descend into them.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = os.path.relpath(dirpath, root)

        # CI directories (matched on the directory portion of the path).
        norm = rel_dir.replace(os.sep, "/")
        for marker, label in CI_MARKERS.items():
            if marker.endswith((".yml", ".yaml")) or "." in os.path.basename(marker):
                continue  # file markers handled below
            if norm.endswith(marker) or f"/{marker}" in f"/{norm}":
                ci_systems.add(label)

        for name in filenames:
            file_count += 1
            if file_count > max_files:
                truncated = True
                break
            full = Path(dirpath) / name
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            ext = full.suffix.lower()

            if ext in EXT_LANG:
                languages[EXT_LANG[ext]] += 1
            if name == "Dockerfile" or name.endswith(".dockerfile"):
                languages["Docker"] += 1

            # Package manifests + framework hints from their contents.
            mm = manifest_matches(name)
            if mm:
                pm, eco = mm
                package_managers.add(pm)
                ecosystems.add(eco)
                manifests.append(rel)
                if not is_probably_binary(full):
                    content = read_text_safe(full).lower()
                    for needle, label in FRAMEWORK_HINTS.get(eco, []):
                        if needle.lower() in content:
                            frameworks.add(label)

            # Docker.
            if name in DOCKER_MARKERS or name.endswith(".dockerfile"):
                docker_files.append(rel)

            # CI file markers.
            for marker, label in CI_MARKERS.items():
                if "/" not in marker and name == marker:
                    ci_systems.add(label)

            # Env examples (never read their values — names only).
            low = name.lower()
            if low.startswith(".env") and any(
                k in low for k in ("example", "sample", "template", "dist")
            ):
                env_examples.append(rel)

            # Likely entrypoints.
            if name in ENTRYPOINT_HINTS:
                entrypoints.append(rel)

            # Notable config files.
            if name in config_names:
                notable_configs.append(rel)

        if truncated:
            if not quiet:
                print(f"[repo_recon] Reached --max-files limit ({max_files}); inventory truncated.", file=sys.stderr)
            break

    primary_language = languages.most_common(1)[0][0] if languages else "unknown"

    return {
        "tool": "repo_recon",
        "version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root),
        "summary": {
            "files_scanned": file_count,
            "truncated": truncated,
            "primary_language": primary_language,
            "ecosystems": sorted(ecosystems),
        },
        "languages": dict(languages.most_common()),
        "package_managers": sorted(package_managers),
        "manifests": sorted(set(manifests)),
        "frameworks": sorted(frameworks),
        "docker_files": sorted(set(docker_files)),
        "ci_systems": sorted(ci_systems),
        "env_examples": sorted(set(env_examples)),
        "likely_entrypoints": sorted(set(entrypoints)),
        "notable_configs": sorted(set(notable_configs)),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="repo_recon.py",
        description="Star Sec Auditor — read-only repository recon (stack/file inventory) to JSON.",
        epilog="Read-only and network-free. Does not modify the target project.",
    )
    p.add_argument("path", nargs="?", default=".", help="Path to the repository root (default: current dir).")
    p.add_argument("--out", default="reports/recon.json", help="Output JSON path (default: reports/recon.json).")
    p.add_argument("--max-files", type=int, default=200_000, help="Safety cap on files scanned (default: 200000).")
    p.add_argument("--quiet", action="store_true", help="Suppress the human-readable summary on stderr.")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"[repo_recon] Error: '{root}' is not a directory.", file=sys.stderr)
        return 2

    try:
        inventory = scan(root, args.max_files, args.quiet)
    except Exception as exc:  # never crash the audit — report and exit cleanly
        print(f"[repo_recon] Unexpected error during scan: {exc}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(inventory, fh, indent=2)
    except OSError as exc:
        print(f"[repo_recon] Error writing '{out_path}': {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        s = inventory["summary"]
        print(f"[repo_recon] Scanned {s['files_scanned']} files under {root}")
        print(f"[repo_recon] Primary language : {s['primary_language']}")
        print(f"[repo_recon] Ecosystems       : {', '.join(s['ecosystems']) or 'none detected'}")
        print(f"[repo_recon] Frameworks       : {', '.join(inventory['frameworks']) or 'none detected'}")
        print(f"[repo_recon] Package managers : {', '.join(inventory['package_managers']) or 'none detected'}")
        print(f"[repo_recon] Docker files     : {len(inventory['docker_files'])}")
        print(f"[repo_recon] CI systems       : {', '.join(inventory['ci_systems']) or 'none detected'}")
        print(f"[repo_recon] Entrypoints      : {len(inventory['likely_entrypoints'])}")
        print(f"[repo_recon] Wrote inventory  : {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
