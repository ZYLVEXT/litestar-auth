"""Smoke tests for executable documentation snippets."""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

import pytest
from litestar import Litestar

from litestar_auth.totp import SecurityWarning
from tests._helpers import build_fake_aiosqlite_module

pytestmark = [pytest.mark.unit, pytest.mark.imports]

REPO_ROOT = Path(__file__).resolve().parents[2]
README_FILE = REPO_ROOT / "README.md"
QUICKSTART_DOC = REPO_ROOT / "docs" / "quickstart.md"
QUICKSTART_SNIPPET = REPO_ROOT / "docs" / "snippets" / "quickstart_plugin.py"


def test_home_quick_peek_snippet_imports_cleanly() -> None:
    """Import the home-page quick-peek snippet so placeholder names cannot drift in."""
    module = importlib.import_module("docs.snippets.home_quick_peek")

    assert isinstance(module.app, Litestar)


def test_quickstart_snippet_imports_cleanly(monkeypatch: pytest.MonkeyPatch) -> None:
    """Import the quickstart app module so the docs example stays executable."""
    sys.modules.pop("docs.snippets.quickstart_plugin", None)
    monkeypatch.setitem(sys.modules, "aiosqlite", build_fake_aiosqlite_module())
    with pytest.warns(SecurityWarning, match="process-local in-memory denylist"):
        module = importlib.import_module("docs.snippets.quickstart_plugin")

    assert isinstance(module.app, Litestar)


def test_quickstart_app_block_matches_snippet_file() -> None:
    """Keep the inline quickstart app block and the tested snippet module in sync."""
    markdown = QUICKSTART_DOC.read_text(encoding="utf-8")
    python_blocks = re.findall(r"```python\n(.*?)\n```", markdown, re.DOTALL)
    app_block = next(
        block
        for block in python_blocks
        if "app = Litestar(route_handlers=[protected], plugins=[LitestarAuth(config)])" in block
    )

    assert app_block.strip() == QUICKSTART_SNIPPET.read_text(encoding="utf-8").strip()


def test_readme_quick_peek_matches_quickstart_snippet_file() -> None:
    """Keep the PyPI landing-page example aligned with the quickstart source of truth."""
    markdown = README_FILE.read_text(encoding="utf-8")
    python_blocks = re.findall(r"```python\n(.*?)\n```", markdown, re.DOTALL)
    app_block = next(
        block
        for block in python_blocks
        if "app = Litestar(route_handlers=[protected], plugins=[LitestarAuth(config)])" in block
    )

    assert app_block.strip() == QUICKSTART_SNIPPET.read_text(encoding="utf-8").strip()


def test_readme_uses_absolute_docs_links() -> None:
    """Keep PyPI-facing docs links usable outside the GitHub repository context."""
    markdown = README_FILE.read_text(encoding="utf-8")

    assert "](docs/" not in markdown
    assert "](./" not in markdown
