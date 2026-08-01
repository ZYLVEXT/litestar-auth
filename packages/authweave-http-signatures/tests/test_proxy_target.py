"""Allowlisted proxy external-target projection tests."""

from __future__ import annotations

import pytest
from authweave_http_signatures.proxy_target import UNIX_SOCKET_PROXY, AllowlistedProxyExternalTarget


def _scope(*, client: str | None = "127.0.0.1", headers: list[tuple[bytes, bytes]] | None = None) -> dict[str, object]:
    return {
        "client": None if client is None else (client, 443),
        "headers": headers or [],
    }


pytestmark = pytest.mark.unit


def test_absent_header_returns_none() -> None:
    factory = AllowlistedProxyExternalTarget(frozenset({"127.0.0.1"}))
    assert factory(_scope(headers=[(b"other", b"value")])) is None


def test_trusted_proxy_projects_https_target() -> None:
    factory = AllowlistedProxyExternalTarget(frozenset({"127.0.0.1"}))
    target = factory(
        _scope(headers=[(b"x-auth-external-target", b"https://payments.example/v1/payments")]),
    )
    assert target == "https://payments.example/v1/payments"


def test_unix_socket_proxy_is_supported() -> None:
    factory = AllowlistedProxyExternalTarget(frozenset({UNIX_SOCKET_PROXY}))
    target = factory(
        _scope(client=None, headers=[(b"x-auth-external-target", b"https://payments.example/v1/payments")]),
    )
    assert target == "https://payments.example/v1/payments"
    assert factory(_scope(client="", headers=[(b"x-auth-external-target", target.encode())])) == target
    assert factory(_scope(client=UNIX_SOCKET_PROXY, headers=[(b"x-auth-external-target", target.encode())])) == target


def test_untrusted_proxy_is_rejected() -> None:
    factory = AllowlistedProxyExternalTarget(frozenset({"127.0.0.1"}))
    with pytest.raises(ValueError, match="not trusted"):
        factory(
            _scope(
                client="203.0.113.5",
                headers=[(b"x-auth-external-target", b"https://payments.example/v1/payments")],
            ),
        )


def test_duplicate_header_is_ambiguous() -> None:
    factory = AllowlistedProxyExternalTarget(frozenset({"127.0.0.1"}))
    with pytest.raises(ValueError, match="ambiguous"):
        factory(
            _scope(
                headers=[
                    (b"x-auth-external-target", b"https://payments.example/v1/payments"),
                    (b"x-auth-external-target", b"https://evil.example/v1/payments"),
                ],
            ),
        )


def test_http_target_is_rejected() -> None:
    factory = AllowlistedProxyExternalTarget(frozenset({"127.0.0.1"}))
    with pytest.raises(ValueError, match="https"):
        factory(_scope(headers=[(b"x-auth-external-target", b"http://payments.example/v1/payments")]))


def test_invalid_proxy_shape_and_non_ascii_target_are_rejected() -> None:
    factory = AllowlistedProxyExternalTarget(frozenset({"127.0.0.1"}))
    malformed_scope = {"client": "127.0.0.1", "headers": [(b"x-auth-external-target", b"https://example.test")]}
    with pytest.raises(ValueError, match="not trusted"):
        factory(malformed_scope)
    with pytest.raises(ValueError, match="invalid"):
        factory(_scope(headers=[(b"x-auth-external-target", "https://é.example".encode())]))


def test_empty_allowlist_rejected() -> None:
    with pytest.raises(ValueError, match="proxy addresses"):
        AllowlistedProxyExternalTarget(frozenset())
