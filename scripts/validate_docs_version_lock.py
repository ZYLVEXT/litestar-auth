"""Fail when user-facing docs advertise a different AuthWeave major than pyproject.toml."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

# Paths checked for stale “current product is v7” branding.
CHECKED_PATHS = (
    REPOSITORY_ROOT / "README.md",
    REPOSITORY_ROOT / "zensical.toml",
    REPOSITORY_ROOT / "docs" / "index.md",
    REPOSITORY_ROOT / "docs" / "quickstart.md",
    REPOSITORY_ROOT / "docs" / "architecture.md",
    REPOSITORY_ROOT / "docs" / "security.md",
    REPOSITORY_ROOT / "docs" / "roadmap.md",
    REPOSITORY_ROOT / "packages" / "authweave-workload" / "README.md",
)

# Phrases that mean “the current product major is still 7”.
STALE_CURRENT_PRODUCT = re.compile(
    r"(?:"
    r"`?litestar-auth`?\s+7\b|"
    r"AuthWeave\s+7\b|"
    r"site_name\s*=\s*\"litestar-auth 7\"|"
    r"#\s*Version 7 architecture contract|"
    r"#\s*Authentication stack version 7|"
    r"#\s*Tech stack — AuthWeave 7|"
    r"#\s*Product requirements — AuthWeave 7|"
    r"Version 7 supports registered X\.509"
    r")",
    re.IGNORECASE,
)


def _package_major() -> int:
    pyproject = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    major_text, _, _ = version.partition(".")
    return int(major_text)


def _site_name_major(site_name: str) -> int | None:
    match = re.search(r"litestar-auth\s+(\d+)\b", site_name)
    if match is None:
        return None
    return int(match.group(1))


def main() -> int:
    """Validate documentation major branding.

    Returns:
        Process exit status.
    """
    package_major = _package_major()
    errors: list[str] = []

    zensical = tomllib.loads((REPOSITORY_ROOT / "zensical.toml").read_text(encoding="utf-8"))
    site_name = zensical["project"]["site_name"]
    site_major = _site_name_major(site_name)
    if site_major is None:
        errors.append(f"zensical.toml site_name={site_name!r} has no litestar-auth major")
    elif site_major != package_major:
        errors.append(
            f"zensical.toml site_name major {site_major} != pyproject.toml major {package_major}",
        )

    for path in CHECKED_PATHS:
        text = path.read_text(encoding="utf-8")
        if STALE_CURRENT_PRODUCT.search(text):
            errors.append(
                f"{path.relative_to(REPOSITORY_ROOT)}: stale AuthWeave/litestar-auth 7 product branding",
            )

    if errors:
        sys.stderr.write("Documentation version lock failed:\n")
        sys.stderr.write("\n".join(f"  - {error}" for error in errors) + "\n")
        return 1

    sys.stdout.write(f"Documentation version lock OK (major={package_major})\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
