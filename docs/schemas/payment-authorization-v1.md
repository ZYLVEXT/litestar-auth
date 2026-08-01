# Payment authorization details v1

Type identifier:
`https://zylvext.github.io/litestar-auth/schemas/payment-authorization-v1`

This RFC 9396 profile is one exact JSON object:

```json
{
  "type": "https://zylvext.github.io/litestar-auth/schemas/payment-authorization-v1",
  "actions": ["initiate"],
  "locations": ["https://api.example/v1/payments"],
  "instructedAmount": {"currency": "EUR", "amount": "100.00"},
  "identifier": "payment-123"
}
```

The fields are:

- `type`: the identifier above;
- `actions`: a non-empty unique subset of `initiate`, `status`, `cancel`, and
  `refund`;
- `locations`: one to eight unique exact HTTPS URIs allowed by issuer policy;
- `instructedAmount`: exactly `currency` and `amount`; currency is an
  issuer-allowed uppercase three-letter code and amount is a positive decimal
  string with exactly two fractional digits;
- `identifier`: optional printable ASCII, 1–128 characters.

Unknown fields, mixed detail types, duplicate entries, scope/action mismatch,
and values above issuer ceilings are rejected. A child authority may reduce
actions, locations, or amount, but cannot change currency or a parent-bound
identifier. See [ADR 0009](../adr/0009-payment-authorization-details-v1.md).

This object is verified authorization evidence. Account state, beneficiary,
fraud, idempotency, ledger, and transaction approval remain application
decisions.
