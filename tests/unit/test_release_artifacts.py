"""Release artifact manifest regressions."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from scripts import release_artifacts
from scripts.release_artifacts import _PACKAGES, ReleasePackage, _clear_stale_artifacts

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit


def _write_module_version(root: Path, module: str, version: str) -> None:
    package = root / module
    package.mkdir()
    (package / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")


def test_clear_stale_artifacts_preserves_unowned_files(tmp_path: Path) -> None:
    """Release cleanup removes owned stale artifacts but preserves unrelated files."""
    unrelated = tmp_path / "keep.txt"
    unrelated.write_text("keep", encoding="utf-8")
    for index, package in enumerate(_PACKAGES):
        package_path = tmp_path / package.distribution
        if index == 0:
            package_path.touch()
        else:
            package_path.mkdir()
        prefix = package.distribution.replace("-", "_")
        (tmp_path / f"{prefix}-7.0.0-py3-none-any.whl").touch()
        (tmp_path / f"{prefix}-7.0.0.tar.gz").touch()

    _clear_stale_artifacts(tmp_path)

    assert unrelated.read_text(encoding="utf-8") == "keep"
    assert {path.name for path in tmp_path.iterdir()} == {unrelated.name}


def test_release_metadata_rejects_stale_internal_pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every cross-workspace requirement must exactly match the release version."""
    core = tmp_path / "core.toml"
    core.write_text('[project]\nname = "authweave-core"\nversion = "7.1.0"\n', encoding="utf-8")
    workload = tmp_path / "workload.toml"
    workload.write_text(
        '[project]\nname = "authweave-workload"\nversion = "7.1.0"\ndependencies = ["authweave-core==7.0.0"]\n',
        encoding="utf-8",
    )
    _write_module_version(tmp_path, "authweave_core", "7.1.0")
    _write_module_version(tmp_path, "authweave_workload", "7.1.0")
    monkeypatch.setattr(
        release_artifacts,
        "_PACKAGES",
        (
            ReleasePackage("authweave-core", "authweave_core", core),
            ReleasePackage("authweave-workload", "authweave_workload", workload),
        ),
    )
    monkeypatch.setattr(release_artifacts, "_REPOSITORY_ROOT", tmp_path)

    with pytest.raises(RuntimeError, match=r"must use the exact lockstep pin ==7.1.0"):
        release_artifacts._require_lockstep_metadata()


def test_release_metadata_rejects_stale_module_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The tag cannot precede a forgotten public module version update."""
    project = tmp_path / "pyproject.toml"
    project.write_text('[project]\nname = "authweave-core"\nversion = "7.1.0"\n', encoding="utf-8")
    _write_module_version(tmp_path, "authweave_core", "7.0.0")
    monkeypatch.setattr(
        release_artifacts,
        "_PACKAGES",
        (ReleasePackage("authweave-core", "authweave_core", project),),
    )
    monkeypatch.setattr(release_artifacts, "_REPOSITORY_ROOT", tmp_path)

    with pytest.raises(RuntimeError, match=r"expected one __version__ assignment equal to 7.1.0"):
        release_artifacts._require_lockstep_metadata()


@pytest.mark.parametrize("version", ["07.1.0", "7.01.0", "7.1.00", "7.1.0rc1"])
def test_release_metadata_rejects_noncanonical_stable_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: str,
) -> None:
    """Package metadata and release tags use one unambiguous stable SemVer spelling."""
    project = tmp_path / "pyproject.toml"
    project.write_text(f'[project]\nname = "authweave-core"\nversion = "{version}"\n', encoding="utf-8")
    _write_module_version(tmp_path, "authweave_core", version)
    monkeypatch.setattr(
        release_artifacts,
        "_PACKAGES",
        (ReleasePackage("authweave-core", "authweave_core", project),),
    )
    monkeypatch.setattr(release_artifacts, "_REPOSITORY_ROOT", tmp_path)

    with pytest.raises(RuntimeError, match="is not canonical stable SemVer"):
        release_artifacts._require_lockstep_metadata()


@pytest.mark.parametrize(
    ("current", "latest", "resume"),
    [
        ("7.0.0", "7.0.0", False),
        ("6.9.9", "7.0.0", False),
        ("7.1.0", "7.0.0", True),
    ],
)
def test_release_version_must_advance_or_resume_latest(current: str, latest: str, *, resume: bool) -> None:
    """A prepared release cannot downgrade, repeat, or resume a non-latest version."""
    with pytest.raises(RuntimeError, match="must advance latest stable tag"):
        release_artifacts._require_version_advance(current, latest, resume=resume)


def test_release_version_accepts_advance_and_exact_resume() -> None:
    """A strictly newer version and an exact latest-tag resume are valid."""
    release_artifacts._require_version_advance("7.1.0", "7.0.0", resume=False)
    release_artifacts._require_version_advance("7.0.0", "7.0.0", resume=True)
