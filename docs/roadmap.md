# Roadmap and product boundaries

What this library aims to cover today, what it deliberately does not include, and likely directions for future work.

## In scope today

Registration, login/logout, email verification and password reset, Bearer and Cookie transports, JWT / database / Redis token strategies, guards, optional user CRUD, TOTP, OAuth login and account linking, rate limiting, hooks, configurable login identifier (`email` or `username`). See [Features on the home page](index.md).

## Explicitly out of scope (library core)

- Built-in **email transport** (use hooks).
- **UI** or admin panel.
- Full **RBAC** / permissions framework.
- **WebAuthn** / passkeys.
- Built-in **audit log** storage.
- End-user **session dashboard** API.

## Product evolution

Planned directions include: production-first durable JWT denylist defaults, encryption key rotation workflows, audit trails, WebAuthn, RBAC, session management APIs, and multi-tenant authorization semantics. Timelines are not committed here.

## Definition of done (feature-level)

A feature is complete when it ships with HTTP flows, tests where appropriate, **documented configuration**, stated limitations for security-sensitive behavior, and **documented extension points** without requiring a fork.
