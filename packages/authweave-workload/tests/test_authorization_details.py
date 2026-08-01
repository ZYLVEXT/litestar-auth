"""Tests for the exact payment authorization-details profile."""

from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
from typing import Any, cast

import pytest
from authweave_core import AuthenticationEvidence
from authweave_workload.authorization_details import (
    PAYMENT_AUTHORIZATION_TYPE,
    PaymentAuthorizationDetail,
    PaymentAuthorizationError,
    PaymentAuthorizationPolicy,
    find_payment_authorization,
    parse_payment_authorization_details,
    payment_authorization_evidence,
    validate_payment_authorization_narrowing,
)

_LOCATION = "https://api.example/payments"
_OTHER_LOCATION = "https://api.example/payments/other"


def _policy(*, required: bool = True) -> PaymentAuthorizationPolicy:
    return PaymentAuthorizationPolicy(
        scope_actions={
            "payments:write": frozenset({"initiate", "cancel"}),
            "payments:read": frozenset({"status"}),
            "payments:refund": frozenset({"refund"}),
        },
        allowed_locations=frozenset({_LOCATION, _OTHER_LOCATION}),
        currency_limits={"EUR": "1000.00", "USD": "500.00"},
        required=required,
    )


def _raw(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "type": PAYMENT_AUTHORIZATION_TYPE,
        "actions": ["initiate", "cancel"],
        "locations": [_LOCATION],
        "instructedAmount": {"currency": "EUR", "amount": "125.50"},
        "identifier": "payment-123",
    }
    value.update(updates)
    return value


def _detail(**updates: object) -> PaymentAuthorizationDetail:
    values: dict[str, object] = {
        "actions": ("initiate", "cancel"),
        "locations": (_LOCATION,),
        "currency": "EUR",
        "amount": Decimal("125.50"),
        "identifier": "payment-123",
    }
    values.update(updates)
    return PaymentAuthorizationDetail(**cast("dict[str, Any]", values))


pytestmark = pytest.mark.unit


def test_policy_parses_freezes_and_recovers_typed_evidence() -> None:
    """Valid payment authority round-trips through generic immutable evidence."""
    scopes = ("payments:write",)
    policy = _policy()
    parsed = policy.parse([_raw()], scopes=scopes)
    detail = parsed[0]
    generic = payment_authorization_evidence([_raw()], policy=policy, scopes=scopes)
    evidence = AuthenticationEvidence(
        provider="issuer",
        profile="dpop_bound_access_token",
        method="dpop",
        issuer="https://issuer.example",
        scopes=scopes,
        authorization_details=generic,
    )

    assert detail == _detail()
    assert detail.as_evidence()["instructedAmount"] == {"currency": "EUR", "amount": "125.50"}
    assert policy.from_evidence(evidence) == parsed
    assert find_payment_authorization(parsed, _detail(actions=("initiate",), amount=Decimal("100.00"))) == detail
    assert find_payment_authorization(parsed, _detail(amount=Decimal("200.00"))) is None
    assert isinstance(policy.scope_actions, type(cast("Any", evidence.authorization_details[0])))
    with pytest.raises(TypeError):
        cast("dict[str, object]", policy.scope_actions)["new"] = frozenset({"status"})


def test_optional_policy_accepts_absent_details_and_disabled_policy_rejects_claim() -> None:
    """Absence is explicit while an unconfigured issuer cannot carry typed authority."""
    assert parse_payment_authorization_details(None, policy=None, scopes=()) == ()
    optional = _policy(required=False)
    assert parse_payment_authorization_details(None, policy=optional, scopes=()) == ()
    assert (
        optional.from_evidence(
            AuthenticationEvidence(provider="issuer", profile="optional", method="jwt", issuer="https://issuer.example")
        )
        == ()
    )
    with pytest.raises(PaymentAuthorizationError, match="required"):
        parse_payment_authorization_details(None, policy=_policy(), scopes=())
    with pytest.raises(PaymentAuthorizationError, match="not enabled"):
        parse_payment_authorization_details([_raw()], policy=None, scopes=("payments:write",))


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"actions": ()}, "actions"),
        ({"actions": ("initiate", "initiate")}, "actions"),
        ({"actions": ("unknown",)}, "actions"),
        ({"locations": ()}, "locations"),
        ({"locations": (_LOCATION,) * 2}, "locations"),
        ({"locations": tuple(f"https://api.example/{index}" for index in range(9))}, "locations"),
        ({"currency": "eur"}, "currency"),
        ({"currency": 1}, "currency"),
        ({"amount": Decimal("0.00")}, "amount"),
        ({"amount": Decimal("1.0")}, "amount"),
        ({"amount": Decimal("NaN")}, "amount"),
        ({"amount": "1.00"}, "amount"),
        ({"identifier": " bad"}, "identifier"),
        ({"identifier": 1}, "identifier"),
    ],
)
def test_typed_detail_rejects_invalid_values(updates: dict[str, object], message: str) -> None:
    """The public immutable model cannot be constructed outside its schema."""
    with pytest.raises(PaymentAuthorizationError, match=message):
        _detail(**updates)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"scope_actions": {}}, "scope and location"),
        ({"scope_actions": {"bad scope": frozenset({"initiate"})}}, "scope-to-action"),
        ({"scope_actions": {1: frozenset({"initiate"})}}, "scope-to-action"),
        ({"scope_actions": {"payments:write": ("initiate",)}}, "scope-to-action"),
        ({"scope_actions": {"payments:*": frozenset({"initiate"})}}, "scope-to-action"),
        ({"scope_actions": {"payments:write": frozenset()}}, "scope-to-action"),
        ({"scope_actions": {"payments:write": frozenset({"unknown"})}}, "scope-to-action"),
        ({"allowed_locations": frozenset()}, "scope and location"),
        ({"allowed_locations": frozenset({1})}, "HTTPS"),
        ({"allowed_locations": frozenset({"http://api.example/payments"})}, "HTTPS"),
        ({"currency_limits": {}}, "currency ceilings"),
        ({"currency_limits": {"eur": "10.00"}}, "currency policy"),
        ({"currency_limits": {1: "10.00"}}, "currency policy"),
        ({"currency_limits": {"EUR": "10"}}, "canonical decimal"),
        ({"currency_limits": {"EUR": "0.00"}}, "positive"),
    ],
)
def test_policy_rejects_invalid_ceilings(updates: dict[str, object], message: str) -> None:
    """Issuer policy cannot contain open, malformed, or non-positive ceilings."""
    values: dict[str, object] = {
        "scope_actions": {"payments:write": frozenset({"initiate"})},
        "allowed_locations": frozenset({_LOCATION}),
        "currency_limits": {"EUR": "100.00"},
    }
    values.update(updates)
    with pytest.raises(PaymentAuthorizationError, match=message):
        PaymentAuthorizationPolicy(**cast("dict[str, Any]", values))


@pytest.mark.parametrize(
    ("location", "message"),
    [
        ("", "HTTPS"),
        ("https://", "HTTPS"),
        ("https://user@api.example/payments", "HTTPS"),
        ("https://api.example/payments#fragment", "HTTPS"),
        ("https://api.example/payments#", "HTTPS"),
        ("https://api.example:invalid/payments", "HTTPS"),
        ("https://api.example/bad path", "HTTPS"),
        ("https://api.example/é", "HTTPS"),
        ("https://api.example/" + "x" * 2048, "HTTPS"),
    ],
)
def test_policy_rejects_ambiguous_locations(location: str, message: str) -> None:
    """Locations are bounded exact HTTPS identifiers."""
    with pytest.raises(PaymentAuthorizationError, match=message):
        replace(_policy(), allowed_locations=frozenset({location}))


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("not-an-array", "transport"),
        ([], "between 1 and 8"),
        ([_raw() for _ in range(9)], "between 1 and 8"),
        ([_raw(extra=True)], "fields"),
        ([{key: member for key, member in _raw().items() if key != "actions"}], "fields"),
        ([_raw(type="other")], "type"),
        ([_raw(actions="initiate")], "actions"),
        ([_raw(actions=[])], "actions"),
        ([_raw(actions=["initiate"] * 2)], "actions"),
        ([_raw(actions=["unknown"])], "actions"),
        ([_raw(actions=["refund"])], "scopes"),
        ([_raw(locations="https://api.example/payments")], "locations"),
        ([_raw(locations=[])], "locations"),
        ([_raw(locations=[_LOCATION] * 2)], "locations"),
        ([_raw(locations=[f"https://api.example/{index}" for index in range(9)])], "locations"),
        ([_raw(locations=["https://not-allowed.example/payments"])], "issuer policy"),
        ([_raw(instructedAmount="EUR 1.00")], "instructedAmount"),
        ([_raw(instructedAmount={"currency": "EUR"})], "instructedAmount"),
        ([_raw(instructedAmount={"currency": 1, "amount": "1.00"})], "currency"),
        ([_raw(instructedAmount={"currency": "GBP", "amount": "1.00"})], "currency"),
        ([_raw(instructedAmount={"currency": "EUR", "amount": 1})], "currency"),
        ([_raw(instructedAmount={"currency": "EUR", "amount": "1"})], "canonical"),
        ([_raw(instructedAmount={"currency": "EUR", "amount": "0.00"})], "exceeds"),
        ([_raw(instructedAmount={"currency": "EUR", "amount": "1000.01"})], "exceeds"),
        ([_raw(identifier=1)], "identifier"),
        ([_raw(identifier=" bad")], "identifier"),
        ([_raw(), _raw()], "duplicates"),
    ],
)
def test_parser_rejects_malformed_or_broadened_authority(value: object, message: str) -> None:
    """Every schema, scope, resource, currency, and duplicate failure is closed."""
    with pytest.raises(PaymentAuthorizationError, match=message):
        parse_payment_authorization_details(value, policy=_policy(), scopes=("payments:write",))


def test_narrowing_accepts_subsets_and_rejects_every_widening_dimension() -> None:
    """Delegated authority can only reduce actions, locations, amount, and identifier reach."""
    granted = (_detail(actions=("initiate", "cancel"), locations=(_LOCATION, _OTHER_LOCATION)),)
    requested = (_detail(actions=("initiate",), amount=Decimal("100.00")),)

    assert validate_payment_authorization_narrowing(granted, requested) is requested
    widenings = (
        (),
        (_detail(actions=("refund",)),),
        (_detail(locations=("https://api.example/not-granted",)),),
        (_detail(currency="USD"),),
        (_detail(amount=Decimal("200.00")),),
        (_detail(identifier="other-payment"),),
    )
    for widening in widenings:
        with pytest.raises(PaymentAuthorizationError, match="widens"):
            validate_payment_authorization_narrowing(granted, widening)


def test_detail_without_identifier_serializes_and_contains_unbound_child() -> None:
    """An omitted identifier is deliberately broader than a specifically bound child."""
    parent = _detail(identifier=None)
    child = _detail(identifier="payment-456", actions=("initiate",))

    assert "identifier" not in parent.as_evidence()
    assert parent.contains(child)
