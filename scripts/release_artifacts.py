"""Build and verify the complete lockstep AuthWeave workspace release."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - release orchestration requires uv subprocesses
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class ReleasePackage:
    """One independently installable workspace distribution."""

    distribution: str
    module: str
    project_file: Path


_PACKAGES = (
    ReleasePackage("authweave-core", "authweave_core", _REPOSITORY_ROOT / "packages/authweave-core/pyproject.toml"),
    ReleasePackage("litestar-auth", "litestar_auth", _REPOSITORY_ROOT / "pyproject.toml"),
    ReleasePackage(
        "authweave-workload",
        "authweave_workload",
        _REPOSITORY_ROOT / "packages/authweave-workload/pyproject.toml",
    ),
    ReleasePackage("authweave-otel", "authweave_otel", _REPOSITORY_ROOT / "packages/authweave-otel/pyproject.toml"),
    ReleasePackage(
        "authweave-webhooks",
        "authweave_webhooks",
        _REPOSITORY_ROOT / "packages/authweave-webhooks/pyproject.toml",
    ),
    ReleasePackage(
        "authweave-http-signatures",
        "authweave_http_signatures",
        _REPOSITORY_ROOT / "packages/authweave-http-signatures/pyproject.toml",
    ),
)


def _project_metadata(package: ReleasePackage) -> tuple[str, str]:
    with package.project_file.open("rb") as project_file:
        project = tomllib.load(project_file)["project"]
    return str(project["name"]), str(project["version"])


def _require_lockstep_metadata() -> str:
    versions: set[str] = set()
    for package in _PACKAGES:
        name, version = _project_metadata(package)
        if name != package.distribution:
            msg = f"release manifest expects {package.distribution!r}, found project name {name!r}"
            raise RuntimeError(msg)
        versions.add(version)
    if len(versions) != 1:
        rendered = ", ".join(sorted(versions))
        msg = f"workspace distributions are not on one lockstep version: {rendered}"
        raise RuntimeError(msg)
    return versions.pop()


def _artifacts(dist_dir: Path) -> dict[str, tuple[Path, Path]]:
    expected: dict[str, tuple[Path, Path]] = {}
    for package in _PACKAGES:
        package_dir = dist_dir / package.distribution
        wheels = tuple(package_dir.glob("*.whl"))
        source_distributions = tuple(package_dir.glob("*.tar.gz"))
        if len(wheels) != 1 or len(source_distributions) != 1:
            msg = (
                f"{package.distribution} must have exactly one wheel and one sdist under {package_dir}; "
                f"found {len(wheels)} wheel(s) and {len(source_distributions)} sdist(s)"
            )
            raise RuntimeError(msg)
        expected[package.distribution] = (wheels[0], source_distributions[0])
    return expected


def _uv_executable() -> str:
    executable = shutil.which("uv")
    if executable is None:
        msg = "uv is required to build and smoke-test release artifacts"
        raise RuntimeError(msg)
    return executable


def build(dist_dir: Path) -> None:
    """Build all workspace wheels and sdists into distribution-specific directories."""
    _require_lockstep_metadata()
    uv = _uv_executable()
    for package in _PACKAGES:
        package_dist_dir = dist_dir / package.distribution
        shutil.rmtree(package_dist_dir, ignore_errors=True)
        subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - manifest arguments
            (
                uv,
                "build",
                "--package",
                package.distribution,
                "--no-sources",
                "--out-dir",
                str(package_dist_dir),
            ),
            cwd=_REPOSITORY_ROOT,
            check=True,
        )
    _artifacts(dist_dir)


def compare(first: Path, second: Path) -> None:
    """Require byte-identical artifacts for every release distribution.

    Raises:
        RuntimeError: If the inventory is incomplete or any artifact differs.
    """
    _require_lockstep_metadata()
    first_artifacts = _artifacts(first)
    second_artifacts = _artifacts(second)
    for package in _PACKAGES:
        for first_path, second_path in zip(
            first_artifacts[package.distribution],
            second_artifacts[package.distribution],
            strict=True,
        ):
            first_digest = hashlib.sha256(first_path.read_bytes()).digest()
            second_digest = hashlib.sha256(second_path.read_bytes()).digest()
            if first_path.name != second_path.name or first_digest != second_digest:
                msg = f"release artifact is not reproducible: {package.distribution}/{first_path.name}"
                raise RuntimeError(msg)


def smoke(dist_dir: Path) -> None:
    """Install and import each wheel in its own isolated environment."""
    version = _require_lockstep_metadata()
    artifacts = _artifacts(dist_dir)
    wheel_directories = tuple(artifacts[package.distribution][0].parent for package in _PACKAGES)
    uv = _uv_executable()
    with tempfile.TemporaryDirectory(prefix="authweave-release-smoke-") as temporary_directory:
        for package in _PACKAGES:
            environment = Path(temporary_directory) / package.distribution
            subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - locally resolved arguments
                (uv, "venv", str(environment), "--python", sys.executable),
                cwd=_REPOSITORY_ROOT,
                check=True,
            )
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            find_links = tuple(
                argument for directory in wheel_directories for argument in ("--find-links", str(directory))
            )
            subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - validated wheel paths
                (
                    uv,
                    "pip",
                    "install",
                    "--python",
                    str(python),
                    *find_links,
                    str(artifacts[package.distribution][0]),
                ),
                cwd=_REPOSITORY_ROOT,
                check=True,
            )
            import_check = f"import {package.module}; assert {package.module}.__version__ == {version!r}"
            subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true] - isolated interpreter
                (str(python), "-I", "-c", import_check),
                cwd=temporary_directory,
                check=True,
            )


def verify(dist_dir: Path) -> None:
    """Validate lockstep metadata and the complete wheel/sdist inventory."""
    _require_lockstep_metadata()
    _artifacts(dist_dir)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "verify", "smoke"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("--dist-dir", type=Path, required=True)
    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("--first", type=Path, required=True)
    compare_parser.add_argument("--second", type=Path, required=True)
    return parser


def main() -> int:
    """Run the selected release artifact operation.

    Returns:
        Process exit status.
    """
    arguments = _parser().parse_args()
    if arguments.command == "build":
        build(arguments.dist_dir)
    elif arguments.command == "verify":
        verify(arguments.dist_dir)
    elif arguments.command == "smoke":
        smoke(arguments.dist_dir)
    else:
        compare(arguments.first, arguments.second)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
