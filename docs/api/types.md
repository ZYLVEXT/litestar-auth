# Types and protocols

Runtime-checkable **`Protocol`** definitions and type aliases used across transports, strategies, and user models.

`RoleCapableUserProtocol` is the dedicated public typing surface for user objects that expose normalized flat `roles` membership. Use that protocol directly instead of treating an arbitrary `roles` attribute as sufficient.

That protocol describes the library boundary rather than a storage implementation detail. Bundled
SQLAlchemy models now persist roles through relational `role` / `user_role` tables, but managers,
schemas, and guards still exchange one normalized flat `roles` collection. This remains flat role
membership, not a full RBAC permission model.

::: litestar_auth.types
