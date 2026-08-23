"""Trusted RFC 8693 actor-claim mapping with bounded delegation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from authweave_core import FailureCode, PrincipalRef

_MAX_SCOPE_VALUES = 64
_ACTOR_KEYS = frozenset({"act", "client_id", "scope", "sub"})


@dataclass(frozen=True, slots=True)
class Delegation:
    """Verified actor and bounded actor chain derived from a trusted token."""

    actor: PrincipalRef
    chain: tuple[PrincipalRef, ...]
    effective_scopes: tuple[str, ...]


def map_rfc8693_actor(
    claim: object,
    *,
    issuer: str,
    subject: PrincipalRef,
    actor_kind: str,
    credential_scopes: tuple[str, ...],
    maximum_depth: int,
) -> Delegation | FailureCode:
    """Map a signed actor claim without deriving authority from metadata or kind.

    Returns:
        The mapped rfc8693 actor.
    """
    if maximum_depth < 1:
        return FailureCode.INTERNAL_INVARIANT
    if not isinstance(claim, Mapping):
        return FailureCode.INVALID
    chain: list[PrincipalRef] = []
    seen = {(subject.issuer, subject.subject)}
    effective_scopes = set(credential_scopes)
    current: object = claim
    while current is not None:
        if len(chain) >= maximum_depth or not isinstance(current, Mapping) or not set(current) <= _ACTOR_KEYS:
            return FailureCode.INVALID
        actor_subject = current.get("sub")
        if not isinstance(actor_subject, str) or not actor_subject:
            return FailureCode.INVALID
        identity = (issuer, actor_subject)
        if identity in seen:
            return FailureCode.INVALID
        seen.add(identity)
        try:
            actor = PrincipalRef(issuer, actor_subject, actor_kind)
        except ValueError:
            return FailureCode.INVALID
        chain.append(actor)
        actor_scopes = current.get("scope")
        if actor_scopes is not None:
            if not isinstance(actor_scopes, str):
                return FailureCode.INVALID
            parsed_scopes = tuple(actor_scopes.split())
            if (
                len(parsed_scopes) > _MAX_SCOPE_VALUES
                or len(parsed_scopes) != len(set(parsed_scopes))
                or any("*" in value for value in parsed_scopes)
            ):
                return FailureCode.INVALID
            effective_scopes.intersection_update(parsed_scopes)
        current = current.get("act")
    return Delegation(
        actor=chain[0],
        chain=tuple(chain),
        effective_scopes=tuple(scope for scope in credential_scopes if scope in effective_scopes),
    )


__all__ = ("Delegation", "map_rfc8693_actor")
