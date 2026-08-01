"""Delegation mapping tests."""

from __future__ import annotations

import pytest
from authweave_core import FailureCode, PrincipalRef
from authweave_workload.delegation import Delegation, map_rfc8693_actor

pytestmark = pytest.mark.unit


def test_rfc8693_actor_mapping_is_bounded_and_scope_intersected() -> None:
    subject = PrincipalRef("https://issuer.test", "resource-owner", "agent")
    result = map_rfc8693_actor(
        {
            "sub": "agent-1",
            "scope": "read",
            "act": {"sub": "operator-1", "scope": "read write"},
        },
        issuer=subject.issuer,
        subject=subject,
        actor_kind="agent",
        credential_scopes=("read", "write"),
        maximum_depth=2,
    )

    assert isinstance(result, Delegation)
    assert result.actor.subject == "agent-1"
    assert tuple(item.subject for item in result.chain) == ("agent-1", "operator-1")
    assert result.effective_scopes == ("read",)

    cycle = map_rfc8693_actor(
        {"sub": "agent-1", "act": {"sub": "agent-1"}},
        issuer=subject.issuer,
        subject=subject,
        actor_kind="agent",
        credential_scopes=(),
        maximum_depth=3,
    )
    assert cycle is FailureCode.INVALID


@pytest.mark.parametrize(
    ("claim", "depth"),
    [
        ({"sub": "agent"}, 0),
        ("agent", 2),
        ({"sub": "agent", "unknown": "value"}, 2),
        ({}, 2),
        ({"sub": ""}, 2),
        ({"sub": "agent", "act": {"sub": "nested"}}, 1),
        ({"sub": "agent", "scope": 1}, 2),
        ({"sub": "agent", "scope": "read read"}, 2),
        ({"sub": "agent", "scope": "read:*"}, 2),
        ({"sub": "agent", "scope": " ".join(f"s{index}" for index in range(65))}, 2),
    ],
)
def test_rfc8693_actor_mapping_rejects_untrusted_or_unbounded_claims(claim: object, depth: int) -> None:
    """Actor claims cannot self-declare cycles, wildcards, or excess authority."""
    subject = PrincipalRef("https://issuer.test", "subject", "service")
    assert map_rfc8693_actor(
        claim,
        issuer=subject.issuer,
        subject=subject,
        actor_kind="agent",
        credential_scopes=("read",),
        maximum_depth=depth,
    ) in {FailureCode.INVALID, FailureCode.INTERNAL_INVARIANT}

    assert (
        map_rfc8693_actor(
            {"sub": "agent"},
            issuer="",
            subject=subject,
            actor_kind="agent",
            credential_scopes=(),
            maximum_depth=1,
        )
        is FailureCode.INVALID
    )
