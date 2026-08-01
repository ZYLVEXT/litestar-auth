"""Dependency pin policy regressions."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from scripts.validate_dependency_pins import invalid_dependency_pins

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("reference", "error_count"),
    [
        (f"actions/checkout@{'a' * 40}", 0),
        ("./.github/actions/local", 0),
        (f"docker://alpine:3.24.1@sha256:{'b' * 64}", 0),
        ("docker://alpine:3.24.1", 1),
        (f"docker://alpine:latest@sha256:{'b' * 64}", 1),
        ("actions/checkout@main", 1),
        (f"actions/checkout@{'a' * 39}", 1),
    ],
)
def test_action_references_require_full_commit_shas(tmp_path: Path, reference: str, error_count: int) -> None:
    """Only local actions and external actions pinned to full SHAs satisfy the policy."""
    workflow = tmp_path / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(f"jobs:\n  example:\n    uses: {reference}\n", encoding="utf-8")
    compose = tmp_path / "docker/reference/compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text(f"services:\n  example:\n    image: example/image:1.2.3@sha256:{'b' * 64}\n", encoding="utf-8")

    errors = invalid_dependency_pins(tmp_path)

    expected = [] if error_count == 0 else [f".github/workflows/test.yml:3: {reference}"]
    assert errors == expected


@pytest.mark.parametrize(
    ("repository", "tag", "error_count"),
    [
        ("example/image", "8.10.0-alpine", 0),
        ("example/image", "v1.39.0", 0),
        ("example/image", "0.12.1-python3.14-trixie-slim", 0),
        ("postgres", "18.4-alpine", 0),
        ("example/image", "18.4-alpine", 1),
        ("example/image", "latest", 1),
        ("example/image", "7.4-alpine", 1),
        ("example/image", "v1.39-latest", 1),
        ("example/image", "1.2.3-latest", 1),
        ("example/image", "1.2.3-rc1", 1),
        ("example/image", "1.2.3-alpha", 1),
        ("example/image", "1.2.3-beta2", 1),
        ("example/image", "1.2.3-nightly", 1),
        ("example/image", "1.2.3-edge", 1),
    ],
)
def test_image_references_require_exact_stable_tags(
    tmp_path: Path,
    repository: str,
    tag: str,
    error_count: int,
) -> None:
    """Only exact stable tags paired with a digest satisfy the image policy."""
    workflow = tmp_path / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(f"jobs:\n  example:\n    uses: actions/checkout@{'a' * 40}\n", encoding="utf-8")
    compose = tmp_path / "docker/reference/compose.yml"
    compose.parent.mkdir(parents=True)
    reference = f"{repository}:{tag}@sha256:{'b' * 64}"
    compose.write_text(f"services:\n  example:\n    image: {reference}\n", encoding="utf-8")

    errors = invalid_dependency_pins(tmp_path)

    expected = [] if error_count == 0 else [f"docker/reference/compose.yml:3: {reference}"]
    assert errors == expected


def test_quoted_image_references_are_validated(tmp_path: Path) -> None:
    """Quoting a Compose image reference cannot bypass the pin policy."""
    workflow = tmp_path / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(f"jobs:\n  example:\n    uses: actions/checkout@{'a' * 40}\n", encoding="utf-8")
    compose = tmp_path / "docker/reference/compose.yml"
    compose.parent.mkdir(parents=True)
    reference = f"example/image:latest@sha256:{'b' * 64}"
    compose.write_text(f'services:\n  example:\n    image: "{reference}"\n', encoding="utf-8")

    assert invalid_dependency_pins(tmp_path) == [f"docker/reference/compose.yml:3: {reference}"]


@pytest.mark.parametrize(
    ("workflow", "line_number"),
    [
        ('jobs:\n  example:\n    "uses": actions/checkout@main\n', 3),
        ("jobs:\n  example:\n    uses : actions/checkout@main\n", 3),
        ("jobs: {example: {uses: actions/checkout@main}}\n", 1),
    ],
)
def test_valid_yaml_syntax_cannot_hide_action_references(
    tmp_path: Path,
    workflow: str,
    line_number: int,
) -> None:
    """Quoted, spaced, and flow-style keys remain subject to pin validation."""
    workflow_path = tmp_path / ".github/workflows/test.yml"
    workflow_path.parent.mkdir(parents=True)
    workflow_path.write_text(workflow, encoding="utf-8")
    compose = tmp_path / "docker/reference/compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text(f"services: {{example: {{image: example/image:1.2.3@sha256:{'b' * 64}}}}}\n", encoding="utf-8")

    assert invalid_dependency_pins(tmp_path) == [f".github/workflows/test.yml:{line_number}: actions/checkout@main"]


@pytest.mark.parametrize(
    "container",
    [
        "{image: example/image:latest}",
        "example/image:latest",
    ],
)
def test_workflow_container_images_are_validated(tmp_path: Path, container: str) -> None:
    """Workflow container images cannot bypass the Docker pin policy."""
    workflow = tmp_path / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(f"jobs: {{example: {{container: {container}}}}}\n", encoding="utf-8")
    compose = tmp_path / "docker/reference/compose.yaml"
    compose.parent.mkdir(parents=True)
    compose.write_text(f"services: {{example: {{image: example/image:1.2.3@sha256:{'b' * 64}}}}}\n", encoding="utf-8")

    assert invalid_dependency_pins(tmp_path) == [".github/workflows/test.yml:1: example/image:latest"]


def test_action_families_use_one_pin(tmp_path: Path) -> None:
    """All actions from one upstream repository must use one release commit."""
    workflow = tmp_path / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        f"jobs:\n  first:\n    uses: github/codeql-action/init@{'a' * 40}\n"
        f"  second:\n    uses: github/codeql-action/analyze@{'b' * 40}\n",
        encoding="utf-8",
    )
    compose = tmp_path / "docker/reference/compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text(f"services: {{example: {{image: example/image:1.2.3@sha256:{'c' * 64}}}}}\n", encoding="utf-8")

    assert invalid_dependency_pins(tmp_path) == [
        (
            f".github/workflows/test.yml:5: github/codeql-action/analyze@{'b' * 40} conflicts with "
            f".github/workflows/test.yml:3: github/codeql-action/init@{'a' * 40}"
        )
    ]


def test_action_subpaths_may_share_one_family_pin(tmp_path: Path) -> None:
    """Different entry points from one action release share its commit pin."""
    workflow = tmp_path / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        f"jobs:\n  first:\n    uses: github/codeql-action/init@{'a' * 40}\n"
        f"  second:\n    uses: github/codeql-action/analyze@{'a' * 40}\n",
        encoding="utf-8",
    )
    compose = tmp_path / "docker/reference/compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text(f"services: {{example: {{image: example/image:1.2.3@sha256:{'c' * 64}}}}}\n", encoding="utf-8")

    assert invalid_dependency_pins(tmp_path) == []


def test_image_families_use_one_pin_across_workflows_and_compose(tmp_path: Path) -> None:
    """One image repository cannot drift between workflow and Compose pins."""
    workflow = tmp_path / ".github/workflows/test.yml"
    workflow.parent.mkdir(parents=True)
    first = f"example/image:1.2.3@sha256:{'a' * 64}"
    second = f"example/image:1.2.4@sha256:{'b' * 64}"
    workflow.write_text(f"jobs:\n  example:\n    container:\n      image: {first}\n", encoding="utf-8")
    compose = tmp_path / "docker/reference/compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text(f"services:\n  example:\n    image: {second}\n", encoding="utf-8")

    assert invalid_dependency_pins(tmp_path) == [
        f"docker/reference/compose.yml:3: {second} conflicts with .github/workflows/test.yml:4: {first}"
    ]
