# Payment authorization details

Configure the exact issuer ceilings next to `TrustedIssuer` or
`IntrospectionIssuerProfile`:

```python
from authweave_workload import PaymentAuthorizationPolicy

payment_policy = PaymentAuthorizationPolicy(
    scope_actions={"payments:write": frozenset({"initiate"})},
    allowed_locations=frozenset({"https://api.example/v1/payments"}),
    currency_limits={"EUR": "1000.00"},
)
```

Pass it as `payment_authorization=payment_policy`. The JWT, DPoP, and
introspection providers then reject missing, malformed, mixed-type, or wider
details before returning `Authenticated`.

After authentication, authorize the concrete endpoint operation from verified
evidence:

```python
from decimal import Decimal

from authweave_core import AuthenticationEvidence
from authweave_workload import PaymentAuthorizationDetail, find_payment_authorization


def require_payment_authority(evidence: AuthenticationEvidence) -> None:
    granted = payment_policy.from_evidence(evidence)
    requested = PaymentAuthorizationDetail(
        actions=("initiate",),
        locations=("https://api.example/v1/payments",),
        currency="EUR",
        amount=Decimal("75.00"),
        identifier="payment-123",
    )
    if find_payment_authorization(granted, requested) is None:
        raise PermissionError("insufficient payment authority")
```

Never parse the raw token again in a handler. This guard proves only that the
verified OAuth authority contains the requested operation. The application must
still decide account ownership and state, beneficiary rules, fraud controls,
idempotency, ledger effects, and final transaction approval.

The exact schema is [payment authorization details v1](../schemas/payment-authorization-v1.md).
The live FAPI-to-DPoP example runs with:

```bash
sh docker/reference/fapi/verify.sh
```
