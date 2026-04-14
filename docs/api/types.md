# Types and protocols

Runtime-checkable **`Protocol`** definitions and type aliases used across transports, strategies, and user models.

`RoleCapableUserProtocol` is the dedicated public typing surface for user objects that expose normalized flat `roles` membership. Use that protocol directly instead of treating an arbitrary `roles` attribute as sufficient.

That protocol describes the library boundary rather than a storage implementation detail. Bundled
SQLAlchemy models now persist roles through relational `role` / `user_role` tables, but managers,
schemas, and guards still exchange one normalized flat `roles` collection. This remains flat role
membership, not a full RBAC permission model.

## Which protocol should my user model implement?

Pick the **narrowest** protocol that covers the features you enable. If a guard or TOTP flow needs
attributes your model does not expose, authentication may succeed while authorization fails with a
generic permission error—so align the model with [Guards](guards.md) and TOTP usage up front.

| If you use… | Implement |
|-------------|-----------|
| Basic authentication only (strategies resolve `request.user` by `id`) | **`UserProtocol`** — `id` |
| `is_active`, `is_verified`, `is_superuser` [guards](guards.md) | **`GuardedUserProtocol`** — `is_active`, `is_verified`, `is_superuser` |
| `has_any_role` / `has_all_roles` [guards](guards.md) | **`RoleCapableUserProtocol`** — `roles` |
| TOTP enrollment, verification, or 2FA flows | **`TotpUserProtocol`** — `email`, `totp_secret` |

### Example: account state and roles together

A single model often needs **`GuardedUserProtocol`** and **`RoleCapableUserProtocol`** so both
account-state and role [guards](guards.md) can run:

```python
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(slots=True)
class StaffUser:
    """Satisfies GuardedUserProtocol and RoleCapableUserProtocol."""

    id: int
    is_active: bool
    is_verified: bool
    is_superuser: bool
    roles: Sequence[str]
```

Add TOTP fields when you enable 2FA; see **`TotpUserProtocol`** in the generated API below.

::: litestar_auth.types
