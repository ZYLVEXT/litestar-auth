"""Smoke tests for executable documentation snippets."""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

import msgspec
import pytest
from litestar import Litestar

from litestar_auth.payloads import (
    TotpConfirmEnableResponse,
    TotpRecoveryCodesResponse,
    TotpRegenerateRecoveryCodesRequest,
    TotpVerifyRequest,
)
from litestar_auth.schemas import ChangePasswordRequest
from litestar_auth.totp import SecurityWarning
from tests._helpers import build_fake_aiosqlite_module

pytestmark = [pytest.mark.unit, pytest.mark.imports]

REPO_ROOT = Path(__file__).resolve().parents[2]
README_FILE = REPO_ROOT / "README.md"
PRD_FILE = REPO_ROOT / "PRD.md"
MIGRATION_DOC = REPO_ROOT / "docs" / "migration.md"
QUICKSTART_DOC = REPO_ROOT / "docs" / "quickstart.md"
QUICKSTART_SNIPPET = REPO_ROOT / "docs" / "snippets" / "quickstart_plugin.py"
CHANGE_PASSWORD_REQUEST_MARKER = "litestar-auth:change-password-request"
TOTP_CODE_MIN_LENGTH = 6
TOTP_CODE_MAX_LENGTH = 16
TOTP_CONFIRM_ENABLE_RESPONSE_MARKER = "litestar-auth:totp-confirm-enable-response"
TOTP_REGENERATE_RECOVERY_CODES_REQUEST_MARKER = "litestar-auth:totp-regenerate-recovery-codes-request"
TOTP_RECOVERY_CODES_RESPONSE_MARKER = "litestar-auth:totp-recovery-codes-response"
TOTP_VERIFY_RECOVERY_CODE_REQUEST_MARKER = "litestar-auth:totp-verify-request-recovery-code"


def _json_blocks_for_marker(markdown: str, marker: str) -> list[str]:
    """Return JSON fenced blocks immediately following a docs marker."""
    return re.findall(
        rf"<!-- {re.escape(marker)} -->\s*```json\n(.*?)\n```",
        markdown,
        re.DOTALL,
    )


def _assert_totp_doc_payload(payload: msgspec.Struct) -> None:
    """Assert decoded TOTP docs payloads carry non-empty meaningful values.

    Raises:
        AssertionError: If a decoded docs payload is empty or unexpected.
    """
    if isinstance(payload, TotpConfirmEnableResponse):
        assert payload.enabled is True
        assert payload.recovery_codes
        return
    if isinstance(payload, TotpRecoveryCodesResponse):
        assert payload.recovery_codes
        return
    if isinstance(payload, TotpRegenerateRecoveryCodesRequest):
        assert payload.current_password
        return
    if isinstance(payload, TotpVerifyRequest):
        assert payload.pending_token
        assert TOTP_CODE_MIN_LENGTH <= len(payload.code) <= TOTP_CODE_MAX_LENGTH
        return
    msg = f"Unexpected TOTP docs payload type: {type(payload).__name__}"
    raise AssertionError(msg)


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


@pytest.mark.parametrize("document", [README_FILE, PRD_FILE, MIGRATION_DOC])
def test_change_password_request_json_examples_decode(document: Path) -> None:
    """Credential-rotation request examples stay aligned with ChangePasswordRequest."""
    markdown = document.read_text(encoding="utf-8")
    json_blocks = _json_blocks_for_marker(markdown, CHANGE_PASSWORD_REQUEST_MARKER)

    assert json_blocks
    for block in json_blocks:
        payload = msgspec.json.decode(block.encode(), type=ChangePasswordRequest)
        assert payload.current_password
        assert payload.new_password


@pytest.mark.parametrize(
    ("marker", "schema_type"),
    [
        (TOTP_CONFIRM_ENABLE_RESPONSE_MARKER, TotpConfirmEnableResponse),
        (TOTP_REGENERATE_RECOVERY_CODES_REQUEST_MARKER, TotpRegenerateRecoveryCodesRequest),
        (TOTP_RECOVERY_CODES_RESPONSE_MARKER, TotpRecoveryCodesResponse),
        (TOTP_VERIFY_RECOVERY_CODE_REQUEST_MARKER, TotpVerifyRequest),
    ],
)
def test_readme_totp_json_examples_decode(marker: str, schema_type: type[msgspec.Struct]) -> None:
    """README TOTP examples stay aligned with the public msgspec payloads."""
    markdown = README_FILE.read_text(encoding="utf-8")
    json_blocks = _json_blocks_for_marker(markdown, marker)

    assert json_blocks
    for block in json_blocks:
        _assert_totp_doc_payload(msgspec.json.decode(block.encode(), type=schema_type))


@pytest.mark.parametrize("document", [README_FILE, PRD_FILE])
def test_totp_recovery_and_client_binding_docs_stay_visible(document: Path) -> None:
    """Primary docs mention the recovery-code and pending-token binding contracts."""
    content = document.read_text(encoding="utf-8").lower()

    assert "recovery code" in content or "recovery-code" in content
    assert "client binding" in content or "client-bound" in content
