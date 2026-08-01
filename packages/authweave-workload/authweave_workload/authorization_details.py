"""Exact typed payment profile for RFC 9396 authorization details."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, cast
from urllib.parse import urlsplit

from authweave_core import AuthorizationValue, freeze_authorization_details

if TYPE_CHECKING:
    from authweave_core import AuthenticationEvidence

PAYMENT_AUTHORIZATION_TYPE = "https://zylvext.github.io/litestar-auth/schemas/payment-authorization-v1"
_ACTIONS = frozenset({"initiate", "status", "cancel", "refund"})
_AMOUNT_PATTERN = re.compile(r"^(?:0|[1-9][0-9]{0,15})\.[0-9]{2}$")
_CURRENCY_PATTERN = re.compile(r"^[A-Z]{3}$")
_SCOPE_PATTERN = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]{1,512}$")
_MAX_DETAILS = 8
_MAX_LOCATIONS = 8
_MAX_IDENTIFIER_LENGTH = 128
_MAX_LOCATION_LENGTH = 2048
_CURRENCY_SCALE = -2

type PaymentAction = Literal["initiate", "status", "cancel", "refund"]


class PaymentAuthorizationError(ValueError):
    """Raised when payment authority is malformed or widens its parent authority."""


@dataclass(frozen=True, slots=True)
class PaymentAuthorizationDetail:
    """One immutable payment authority entry."""

    actions: tuple[PaymentAction, ...]
    locations: tuple[str, ...]
    currency: str
    amount: Decimal
    identifier: str | None = None

    def __post_init__(self) -> None:
        """Validate the exact v1 value domain.

        Raises:
            PaymentAuthorizationError: If a field violates the v1 schema.
        """
        actions_invalid = not self.actions or len(self.actions) != len(set(self.actions))
        if actions_invalid or any(action not in _ACTIONS for action in self.actions):
            msg = "payment actions are invalid"
            raise PaymentAuthorizationError(msg)
        if (
            not self.locations
            or len(self.locations) > _MAX_LOCATIONS
            or len(self.locations) != len(set(self.locations))
        ):
            msg = "payment locations are invalid"
            raise PaymentAuthorizationError(msg)
        for location in self.locations:
            _validate_location(location)
        if not isinstance(self.currency, str) or _CURRENCY_PATTERN.fullmatch(self.currency) is None:
            msg = "payment currency must be an uppercase three-letter code"
            raise PaymentAuthorizationError(msg)
        if (
            not isinstance(self.amount, Decimal)
            or not self.amount.is_finite()
            or self.amount <= 0
            or self.amount.as_tuple().exponent != _CURRENCY_SCALE
        ):
            msg = "payment amount must be positive with exactly two fractional digits"
            raise PaymentAuthorizationError(msg)
        if self.identifier is not None and (
            not isinstance(self.identifier, str) or not _valid_identifier(self.identifier)
        ):
            msg = "payment identifier is invalid"
            raise PaymentAuthorizationError(msg)
        object.__setattr__(self, "actions", tuple(sorted(self.actions)))
        object.__setattr__(self, "locations", tuple(sorted(self.locations)))

    def contains(self, requested: PaymentAuthorizationDetail) -> bool:
        """Return whether ``requested`` is no broader than this detail.

        Returns:
            Whether every requested authority dimension is contained.
        """
        return (
            requested.currency == self.currency
            and requested.amount <= self.amount
            and set(requested.actions) <= set(self.actions)
            and set(requested.locations) <= set(self.locations)
            and (self.identifier is None or requested.identifier == self.identifier)
        )

    def as_evidence(self) -> Mapping[str, AuthorizationValue]:
        """Return the exact RFC 9396 mapping stored on authentication evidence.

        Returns:
            JSON-compatible payment authorization detail.
        """
        value: dict[str, AuthorizationValue] = {
            "type": PAYMENT_AUTHORIZATION_TYPE,
            "actions": self.actions,
            "locations": self.locations,
            "instructedAmount": {"currency": self.currency, "amount": format(self.amount, "f")},
        }
        if self.identifier is not None:
            value["identifier"] = self.identifier
        return MappingProxyType(value)


@dataclass(frozen=True, slots=True)
class PaymentAuthorizationPolicy:
    """Issuer-specific trust ceilings for payment authorization details."""

    scope_actions: Mapping[str, frozenset[PaymentAction]]
    allowed_locations: frozenset[str]
    currency_limits: Mapping[str, str]
    required: bool = True

    def __post_init__(self) -> None:
        """Freeze and validate scope, location, and currency ceilings.

        Raises:
            PaymentAuthorizationError: If a policy ceiling is invalid.
        """
        scopes: dict[str, frozenset[PaymentAction]] = {}
        for scope, actions in self.scope_actions.items():
            if (
                not isinstance(scope, str)
                or not isinstance(actions, frozenset)
                or _SCOPE_PATTERN.fullmatch(scope) is None
                or "*" in scope
                or not actions
            ):
                msg = "payment scope-to-action policy is invalid"
                raise PaymentAuthorizationError(msg)
            if any(action not in _ACTIONS for action in actions):
                msg = "payment scope-to-action policy is invalid"
                raise PaymentAuthorizationError(msg)
            scopes[scope] = frozenset(actions)
        if not scopes or not self.allowed_locations:
            msg = "payment policy requires scope and location ceilings"
            raise PaymentAuthorizationError(msg)
        for location in self.allowed_locations:
            _validate_location(location)
        limits: dict[str, str] = {}
        for currency, amount in self.currency_limits.items():
            if not isinstance(currency, str) or _CURRENCY_PATTERN.fullmatch(currency) is None:
                msg = "payment currency policy is invalid"
                raise PaymentAuthorizationError(msg)
            parsed = _parse_amount(amount)
            if parsed <= 0:
                msg = "payment currency limit must be positive"
                raise PaymentAuthorizationError(msg)
            limits[currency] = amount
        if not limits:
            msg = "payment policy requires currency ceilings"
            raise PaymentAuthorizationError(msg)
        object.__setattr__(self, "scope_actions", MappingProxyType(scopes))
        object.__setattr__(self, "allowed_locations", frozenset(self.allowed_locations))
        object.__setattr__(self, "currency_limits", MappingProxyType(limits))

    def parse(
        self,
        value: object,
        *,
        scopes: tuple[str, ...],
    ) -> tuple[PaymentAuthorizationDetail, ...]:
        """Parse details under this issuer policy and verified scopes.

        Returns:
            Immutable typed payment authority.

        """
        return parse_payment_authorization_details(value, policy=self, scopes=scopes)

    def from_evidence(self, evidence: AuthenticationEvidence) -> tuple[PaymentAuthorizationDetail, ...]:
        """Recover typed details from already verified authentication evidence.

        Returns:
            Immutable typed payment authority.

        """
        return self.parse(evidence.authorization_details or None, scopes=evidence.scopes)


def parse_payment_authorization_details(
    value: object,
    *,
    policy: PaymentAuthorizationPolicy | None,
    scopes: tuple[str, ...],
) -> tuple[PaymentAuthorizationDetail, ...]:
    """Validate one payment claim without accepting other RFC 9396 types.

    Returns:
        Immutable typed payment authority.

    Raises:
        PaymentAuthorizationError: If the claim is absent, malformed, or too broad.
    """
    if value is None:
        if policy is not None and policy.required:
            msg = "payment authorization_details are required"
            raise PaymentAuthorizationError(msg)
        return ()
    if policy is None:
        msg = "authorization_details were not enabled for this issuer"
        raise PaymentAuthorizationError(msg)
    try:
        frozen = freeze_authorization_details(value)
    except (TypeError, ValueError) as exc:
        msg = "payment authorization_details transport is invalid"
        raise PaymentAuthorizationError(msg) from exc
    if not frozen or len(frozen) > _MAX_DETAILS:
        msg = f"payment authorization_details must contain between 1 and {_MAX_DETAILS} entries"
        raise PaymentAuthorizationError(msg)
    scoped_actions = frozenset().union(*(policy.scope_actions.get(scope, frozenset()) for scope in scopes))
    parsed = tuple(_parse_detail(entry, policy=policy, scoped_actions=scoped_actions) for entry in frozen)
    fingerprints = {
        (detail.actions, detail.locations, detail.currency, detail.amount, detail.identifier) for detail in parsed
    }
    if len(fingerprints) != len(parsed):
        msg = "payment authorization_details must not contain duplicates"
        raise PaymentAuthorizationError(msg)
    return parsed


def validate_payment_authorization_narrowing(
    granted: tuple[PaymentAuthorizationDetail, ...],
    requested: tuple[PaymentAuthorizationDetail, ...],
) -> tuple[PaymentAuthorizationDetail, ...]:
    """Reject any requested detail not contained by one granted detail.

    Returns:
        The unchanged narrower request.

    Raises:
        PaymentAuthorizationError: If requested authority widens the grant.
    """
    if not requested or any(not any(parent.contains(child) for parent in granted) for child in requested):
        msg = "requested payment authorization widens granted authority"
        raise PaymentAuthorizationError(msg)
    return requested


def payment_authorization_evidence(
    value: object,
    *,
    policy: PaymentAuthorizationPolicy | None,
    scopes: tuple[str, ...],
) -> tuple[Mapping[str, AuthorizationValue], ...]:
    """Validate a claim and return its immutable generic evidence representation.

    Returns:
        Payment details ready for ``AuthenticationEvidence``.

    """
    return tuple(
        detail.as_evidence() for detail in parse_payment_authorization_details(value, policy=policy, scopes=scopes)
    )


def find_payment_authorization(
    details: tuple[PaymentAuthorizationDetail, ...],
    requested: PaymentAuthorizationDetail,
) -> PaymentAuthorizationDetail | None:
    """Find verified OAuth authority covering one application payment operation.

    Returns:
        The covering detail, or ``None``. This is not a business approval.
    """
    for detail in details:
        if detail.contains(requested):
            return detail
    return None


def _parse_detail(
    value: Mapping[str, AuthorizationValue],
    *,
    policy: PaymentAuthorizationPolicy,
    scoped_actions: frozenset[PaymentAction],
) -> PaymentAuthorizationDetail:
    allowed_fields = {"type", "actions", "locations", "instructedAmount", "identifier"}
    if set(value) not in (allowed_fields, allowed_fields - {"identifier"}):
        msg = "payment authorization detail fields are invalid"
        raise PaymentAuthorizationError(msg)
    if value.get("type") != PAYMENT_AUTHORIZATION_TYPE:
        msg = "payment authorization detail type is invalid"
        raise PaymentAuthorizationError(msg)
    actions = _parse_actions(value.get("actions"))
    if not set(actions) <= scoped_actions:
        msg = "payment authorization actions exceed verified scopes"
        raise PaymentAuthorizationError(msg)
    locations = _parse_locations(value.get("locations"), policy.allowed_locations)
    currency, amount = _parse_instructed_amount(value.get("instructedAmount"), policy.currency_limits)
    identifier = value.get("identifier")
    if identifier is not None and (not isinstance(identifier, str) or not _valid_identifier(identifier)):
        msg = "payment identifier is invalid"
        raise PaymentAuthorizationError(msg)
    return PaymentAuthorizationDetail(
        actions=actions,
        locations=locations,
        currency=currency,
        amount=amount,
        identifier=identifier,
    )


def _parse_actions(value: object) -> tuple[PaymentAction, ...]:
    if not isinstance(value, tuple) or not value or len(value) > len(_ACTIONS):
        msg = "payment actions are invalid"
        raise PaymentAuthorizationError(msg)
    if len(value) != len(set(value)) or any(not isinstance(action, str) or action not in _ACTIONS for action in value):
        msg = "payment actions are invalid"
        raise PaymentAuthorizationError(msg)
    return tuple(sorted(cast("tuple[PaymentAction, ...]", value)))


def _parse_locations(value: object, allowed: frozenset[str]) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value or len(value) > _MAX_LOCATIONS:
        msg = "payment locations are invalid"
        raise PaymentAuthorizationError(msg)
    if len(value) != len(set(value)) or any(
        not isinstance(location, str) or location not in allowed for location in value
    ):
        msg = "payment locations exceed issuer policy"
        raise PaymentAuthorizationError(msg)
    return tuple(sorted(cast("tuple[str, ...]", value)))


def _parse_instructed_amount(value: object, limits: Mapping[str, str]) -> tuple[str, Decimal]:
    if not isinstance(value, Mapping) or set(value) != {"currency", "amount"}:
        msg = "payment instructedAmount is invalid"
        raise PaymentAuthorizationError(msg)
    currency = value.get("currency")
    amount_text = value.get("amount")
    if not isinstance(currency, str) or not isinstance(amount_text, str) or currency not in limits:
        msg = "payment currency is not allowed"
        raise PaymentAuthorizationError(msg)
    amount = _parse_amount(amount_text)
    if amount <= 0 or amount > _parse_amount(limits[currency]):
        msg = "payment amount exceeds issuer policy"
        raise PaymentAuthorizationError(msg)
    return currency, amount


def _parse_amount(value: str) -> Decimal:
    if not isinstance(value, str) or _AMOUNT_PATTERN.fullmatch(value) is None:
        msg = "payment amount must be a canonical decimal with two fractional digits"
        raise PaymentAuthorizationError(msg)
    return Decimal(value)


def _validate_location(value: str) -> None:
    if not isinstance(value, str):
        msg = "payment location must be an exact HTTPS URI"
        raise PaymentAuthorizationError(msg)
    try:
        parts = urlsplit(value)
        _ = parts.port
    except (TypeError, ValueError) as exc:
        msg = "payment location must be an exact HTTPS URI"
        raise PaymentAuthorizationError(msg) from exc
    invalid = (
        not value
        or len(value) > _MAX_LOCATION_LENGTH
        or not value.isascii()
        or any(character.isspace() for character in value)
    )
    authority_invalid = not parts.hostname or parts.username is not None or parts.password is not None
    if invalid or parts.scheme != "https" or authority_invalid or "#" in value:
        msg = "payment location must be an exact HTTPS URI"
        raise PaymentAuthorizationError(msg)


def _valid_identifier(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and len(value) <= _MAX_IDENTIFIER_LENGTH
        and value.isascii()
        and value.isprintable()
    )


__all__ = (
    "PAYMENT_AUTHORIZATION_TYPE",
    "PaymentAction",
    "PaymentAuthorizationDetail",
    "PaymentAuthorizationError",
    "PaymentAuthorizationPolicy",
    "find_payment_authorization",
    "parse_payment_authorization_details",
    "payment_authorization_evidence",
    "validate_payment_authorization_narrowing",
)
