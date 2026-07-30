"""Version 7 removal-audit contract."""

from pathlib import Path

from scripts.audit_v7_removals import audit


def test_removal_audit_finds_source_configuration_and_records(tmp_path: Path) -> None:
    """Source, configuration, and exported credential rows are reported."""
    application = tmp_path / "application.py"
    application.write_text(
        "from litestar_auth.authentication.strategy.jwt import JWTStrategy\napi_keys = True\n",
    )
    exported = tmp_path / "credentials.sql"
    exported.write_text("INSERT INTO api_key VALUES ('legacy');\n")

    findings = audit([tmp_path])

    assert {finding.category for finding in findings} == {
        "removed configuration",
        "removed credential record",
        "removed import",
        "removed module",
    }


def test_removal_audit_does_not_flag_v7_profiles(tmp_path: Path) -> None:
    """Supported certificate profiles remain clean."""
    source = tmp_path / "application.py"
    source.write_text("from authweave_workload import DirectMTLSProvider\n")

    assert audit([source]) == []
