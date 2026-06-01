# Roadmap and product boundaries

What this library aims to cover today, what it deliberately does not include, and likely directions for future work.

## In scope today

Registration, login/logout, email verification and password reset, Bearer / cookie / API-key transports, JWT / database / Redis / API-key strategies, guards, role-derived permission authorization, optional user CRUD, TOTP, OAuth login and account linking, rate limiting, hooks, configurable login identifier (`email` or `username`). See [Features on the home page](index.md).

## Explicitly out of scope (library core)

- Built-in **email transport** (use hooks).
- **UI** or admin panel.
- Full **RBAC** policy framework, including permission matrices, policy DSLs, built-in DB-backed
  permission catalogs, or multi-tenant authorization semantics. The shipped `role` / `user_role`
  tables remain the persistence layer behind flat role membership; `role_permissions` and custom
  `permission_resolver` objects are the current extension points for effective permissions.
- **WebAuthn** / passkeys.
- Built-in **audit log** storage.
- End-user **session dashboard** API.

## Product evolution

Planned directions include: production-first durable JWT denylist defaults, operator tooling around the documented Fernet keyring rotation helpers, audit trails, WebAuthn, richer RBAC policy tooling, DB-backed permission resolution helpers, session management APIs, and multi-tenant authorization semantics. Timelines are not committed here.

## Definition of done (feature-level)

A feature is complete when it ships with HTTP flows, tests where appropriate, **documented configuration**, stated limitations for security-sensitive behavior, and **documented extension points** without requiring a fork.
