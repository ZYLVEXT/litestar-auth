"""Read-only inventory of authentication constructs removed in version 7."""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path

TEXT_SUFFIXES = frozenset({
    ".cfg",
    ".conf",
    ".csv",
    ".env",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".sql",
    ".toml",
    ".yaml",
    ".yml",
})
PATTERNS = (
    ("removed import", re.compile(r"\b(?:JWTStrategy|BearerTransport|ApiKeyConfig|ApiKeyTransport)\b")),
    (
        "removed module",
        re.compile(
            r"litestar_auth\.(?:authentication\.(?:strategy\.jwt|strategy\.api_key|transport\.(?:bearer|api_key))"
            r"|controllers\.api_keys|models\.api_key)",
        ),
    ),
    ("removed configuration", re.compile(r"\b(?:api_keys|api_key_hash_secret|allow_inmemory_denylist)\s*[:=]")),
    ("removed request signing", re.compile(r"\bLSA1-HMAC-SHA256\b")),
    (
        "removed credential record",
        re.compile(
            r"(?i)(?:insert\s+into\s+api_key\b|credential_(?:type|scheme)[\"'\s:=]+(?:api[_-]?key|hmac|bearer[_-]?jwt))",
        ),
    ),
)
IGNORED_DIRECTORIES = frozenset({".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".venv", "__pycache__"})


@dataclass(frozen=True, slots=True)
class Finding:
    """One source, configuration, or exported-record finding."""

    path: Path
    line: int
    category: str
    excerpt: str


def audit(paths: list[Path]) -> list[Finding]:
    """Return deterministic findings without modifying input files."""
    findings: list[Finding] = []
    for path in _files(paths):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(lines, 1):
            for category, pattern in PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(path, line_number, category, line.strip()[:240]))
    return sorted(findings, key=lambda item: (str(item.path), item.line, item.category))


def _files(paths: list[Path]) -> list[Path]:
    files: set[Path] = set()
    for path in paths:
        if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES:
            files.add(path)
        elif path.is_dir():
            files.update(
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file()
                and candidate.suffix.lower() in TEXT_SUFFIXES
                and not IGNORED_DIRECTORIES.intersection(candidate.parts)
            )
    return sorted(files)


def main() -> int:
    """Print findings and return a CI-friendly status.

    Returns:
        Zero when no removed construct is found, otherwise one.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="source/config/export paths to inspect")
    arguments = parser.parse_args()
    findings = audit(arguments.paths)
    for finding in findings:
        print(f"{finding.path}:{finding.line}: {finding.category}: {finding.excerpt}")  # ruff: ignore[print]
    if findings:
        print(f"{len(findings)} removed v7 construct(s) require manual migration")  # ruff: ignore[print]
        return 1
    print("no removed v7 constructs found")  # ruff: ignore[print]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
