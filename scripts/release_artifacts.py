"""Build and verify the complete lockstep AuthWeave workspace release."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - release orchestration requires uv subprocesses
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class ReleasePackage:
    """One independently installable workspace distribution."""

    distribution: str
    module: str
    project_file: Path
    extra_version_files: tuple[Path, ...] = ()

    @property
    def version_files(self) -> tuple[Path, ...]:
        """Source files that publish this distribution's version."""
        return (self.project_file.parent / self.module / "__init__.py", *self.extra_version_files)


_PACKAGES = (
    ReleasePackage("authweave-core", "authweave_core", _REPOSITORY_ROOT / "packages/authweave-core/pyproject.toml"),
    ReleasePackage("litestar-auth", "litestar_auth", _REPOSITORY_ROOT / "pyproject.toml"),
    ReleasePackage(
        "authweave-workload",
        "authweave_workload",
        _REPOSITORY_ROOT / "packages/authweave-workload/pyproject.toml",
    ),
    ReleasePackage(
        "authweave-otel",
        "authweave_otel",
        _REPOSITORY_ROOT / "packages/authweave-otel/pyproject.toml",
        (_REPOSITORY_ROOT / "packages/authweave-otel/authweave_otel/telemetry.py",),
    ),
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
_REQUIREMENT = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+\])?(?P<constraint>.*)$")
_MODULE_VERSION = re.compile(r'^__version__\s*=\s*["\'](?P<version>[^"\']+)["\']\s*$', re.MULTILINE)
_STABLE_VERSION = re.compile(r"(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)\Z")


def _normalize_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _project_metadata(package: ReleasePackage) -> tuple[str, str, dict[str, Any]]:
    with package.project_file.open("rb") as project_file:
        metadata = tomllib.load(project_file)
    project = metadata["project"]
    return str(project["name"]), str(project["version"]), metadata


def _requirements(metadata: dict[str, Any]) -> list[str]:
    project = metadata["project"]
    requirements = list(project.get("dependencies", ()))
    for optional_requirements in project.get("optional-dependencies", {}).values():
        requirements.extend(optional_requirements)
    for grouped_requirements in metadata.get("dependency-groups", {}).values():
        requirements.extend(grouped_requirements)
    return requirements


def _require_module_versions(package: ReleasePackage, version: str) -> None:
    """Require public source versions to match package metadata.

    Raises:
        RuntimeError: If a source version is missing or stale.
    """
    for version_file in package.version_files:
        source_versions = _MODULE_VERSION.findall(version_file.read_text(encoding="utf-8"))
        if source_versions != [version]:
            relative_path = version_file.relative_to(_REPOSITORY_ROOT)
            msg = f"{relative_path}: expected one __version__ assignment equal to {version}"
            raise RuntimeError(msg)


def _stable_version(value: str) -> tuple[int, int, int]:
    """Parse one canonical stable SemVer value.

    Returns:
        Major, minor, and patch components.

    Raises:
        RuntimeError: If the value is not canonical stable SemVer.
    """
    match = _STABLE_VERSION.fullmatch(value)
    if match is None:
        msg = f"release version {value!r} is not canonical stable SemVer"
        raise RuntimeError(msg)
    return (int(match.group("major")), int(match.group("minor")), int(match.group("patch")))


def _require_version_advance(current: str, latest: str, *, resume: bool) -> None:
    """Require a new stable version or an exact latest-version resume.

    Raises:
        RuntimeError: If the requested release does not advance monotonically.
    """
    current_version = _stable_version(current)
    latest_version = _stable_version(latest)
    if (resume and current_version != latest_version) or (not resume and current_version <= latest_version):
        msg = f"release version {current} must advance latest stable tag {latest}"
        raise RuntimeError(msg)


def _require_lockstep_metadata() -> str:
    package_metadata = tuple((package, _project_metadata(package)) for package in _PACKAGES)
    versions: set[str] = set()
    for package, (name, version, _metadata) in package_metadata:
        if name != package.distribution:
            msg = f"release manifest expects {package.distribution!r}, found project name {name!r}"
            raise RuntimeError(msg)
        versions.add(version)
    if len(versions) != 1:
        rendered = ", ".join(sorted(versions))
        msg = f"workspace distributions are not on one lockstep version: {rendered}"
        raise RuntimeError(msg)
    version = versions.pop()
    _stable_version(version)
    distributions = {package.distribution for package in _PACKAGES}
    for package, (_name, _version, metadata) in package_metadata:
        _require_module_versions(package, version)
        for requirement in _requirements(metadata):
            match = _REQUIREMENT.fullmatch(requirement)
            if match is None:
                continue
            dependency = _normalize_distribution(match.group("name"))
            if dependency in distributions and dependency != package.distribution:
                expected = f"=={version}"
                if match.group("constraint") != expected:
                    relative_path = package.project_file.relative_to(_REPOSITORY_ROOT)
                    msg = f"{relative_path}: {requirement!r} must use the exact lockstep pin {expected}"
                    raise RuntimeError(msg)
    return version


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


def _clear_stale_artifacts(dist_dir: Path) -> None:
    """Remove only release artifacts owned by this workspace."""
    dist_dir.mkdir(parents=True, exist_ok=True)
    for package in _PACKAGES:
        package_dir = dist_dir / package.distribution
        if package_dir.is_symlink():
            package_dir.unlink()
        elif package_dir.is_dir():
            shutil.rmtree(package_dir)
        elif package_dir.exists():
            package_dir.unlink()
        artifact_prefix = package.distribution.replace("-", "_")
        for pattern in (f"{artifact_prefix}-*.whl", f"{artifact_prefix}-*.tar.gz"):
            for artifact in dist_dir.glob(pattern):
                if artifact.is_file() or artifact.is_symlink():
                    artifact.unlink()


def build(dist_dir: Path) -> None:
    """Build all workspace wheels and sdists into distribution-specific directories."""
    _require_lockstep_metadata()
    uv = _uv_executable()
    _clear_stale_artifacts(dist_dir)
    for package in _PACKAGES:
        package_dist_dir = dist_dir / package.distribution
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
    version_parser = subparsers.add_parser("version")
    version_parser.add_argument("--latest-tag")
    version_parser.add_argument("--resume", action="store_true")
    return parser


def main() -> int:
    """Run the selected release artifact operation.

    Returns:
        Process exit status.
    """
    arguments = _parser().parse_args()
    if arguments.command == "version":
        version = _require_lockstep_metadata()
        if arguments.latest_tag is not None:
            _require_version_advance(version, arguments.latest_tag, resume=arguments.resume)
        sys.stdout.write(f"{version}\n")
    elif arguments.command == "build":
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
