# TOTP

Time-based one-time passwords in **litestar-auth** split into a **low-level crypto and replay layer** and a **login-flow orchestration layer**.

**`litestar_auth.totp`** holds the primitives: generating secrets and otpauth URIs (**`generate_totp_secret`**, **`generate_totp_uri`**), verifying a code against a stored secret (**`verify_totp`**, **`verify_totp_with_store`**), and the **`UsedTotpCodeStore`** protocol used to reject **replay** of successfully verified codes. Two built-in stores implement that contract: **`InMemoryUsedTotpCodeStore`** (async-safe, single-process) and **`RedisUsedTotpCodeStore`** (shared Redis `SET … NX` semantics for multi-worker deployments). Choose the store that matches your durability and scaling needs; production setups typically wire Redis through plugin configuration (see [TOTP guide](../guides/totp.md)).

**`litestar_auth.totp_flow`** builds on those primitives for **pending-login** challenges: **`TotpLoginFlowService`** issues short-lived pending JWTs and finishes login after a valid TOTP code, using **`verify_totp_with_store`** and optional **`UsedTotpCodeStore`** / denylist wiring. That path complements the HTTP **`controllers`** enrollment and verify routes.

**Enrollment** is intentionally **two-phase**: first **enable** (receive secret, otpauth material, and a short-lived enrollment token without persisting the secret), then **confirm** with a valid code so the secret is stored—mirroring the route flow documented in [TOTP (two-factor authentication)](../guides/totp.md). **Verification** (during login or disable flows) checks the current code and relies on replay protection when configured.

## Replay store contract (`UsedTotpCodeStore` and `UsedTotpMarkResult`)

Custom implementations of **`UsedTotpCodeStore`** must implement **`mark_used(user_id, counter, ttl_seconds)`** and return **`UsedTotpMarkResult`**, not a bare boolean. The result tells callers whether the `(user_id, counter)` pair was newly recorded and, when it was not, **why** verification should fail:

| `stored` | `rejected_as_replay` | Meaning |
| -------- | -------------------- | ------- |
| `True`   | (ignored)            | The pair was **newly** recorded; verification succeeds when the cryptographic check already passed. |
| `False`  | `True`               | The pair was **already** present—**replay** of a successfully verified code in the TTL window. |
| `False`  | `False`              | The store **rejected** the insert for a **non-replay** reason and verification **fails closed**. The built-in **`InMemoryUsedTotpCodeStore`** uses this when **capacity** is exhausted (no expired entries left to prune); **`RedisUsedTotpCodeStore`** does not use this path (a missed `SET NX` implies an existing key, i.e. replay). |

**`verify_totp_with_store()`** uses that contract: on `stored=False` it logs **`totp_replay`** when `rejected_as_replay=True`, and **`totp_replay_store_capacity`** when `rejected_as_replay=False`, so operators can tell true replay from fail-closed store pressure. Authentication still returns `False` in both cases.

::: litestar_auth.totp

::: litestar_auth.totp_flow
