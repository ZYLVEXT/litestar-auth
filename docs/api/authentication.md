# Authentication (middleware, authenticator, backend)

An **`AuthenticationBackend`** pairs a **transport** with a **strategy**: the transport reads token material from the request (for example `Authorization: Bearer` or cookies), and the strategy validates or issues tokens and resolves the user through the user manager. Login and logout flow through the same pair so issuing, invalidation, and response shaping stay consistent.

An **`Authenticator`** holds an ordered list of backends plus a **`UserManagerProtocol`**. For each request it tries backends in order and returns the first user that authenticates, so you can stack transports (Bearer plus cookie, multiple named backends, and so on) without duplicating strategy wiring.

API-key backends use `ApiKeyTransport` with `ApiKeyStrategy`. Successful API-key authentication
sets `request.auth` to `ApiKeyContext` rather than the backend name string, so scope guards can
inspect the authenticated key id, prefix environment, and key scopes.

**`LitestarAuthMiddleware`** plugs the authenticator into Litestar’s ASGI pipeline so `connection.user` and related auth state are populated from the same backend list your routes and guards use.

Signed API-key requests need pre-auth body buffering so the HMAC check can commit to the raw request
body. Plugin-managed applications opt into that buffering automatically when the startup backend
inventory includes an `ApiKeyTransport`. Direct integrations that construct `LitestarAuthMiddleware`
outside the plugin fail closed by default: `LitestarAuthMiddlewareConfig.api_key_backend_present`
defaults to `False`, so signed-body buffering is skipped unless you pass
`api_key_backend_present=True` for a backend list that contains an `ApiKeyTransport`.

For diagrams, transport vs strategy tables, and plugin-oriented setup, see [Backends: transports and strategies](../concepts/backends.md).

```python
from litestar_auth.authentication import (
    AuthenticationBackend,
    Authenticator,
    LitestarAuthMiddleware,
)

# Typical wiring: build AuthenticationBackend(name, transport, strategy) instances,
# wrap them in Authenticator(backends, user_manager), then register LitestarAuthMiddleware.
```

::: litestar_auth.authentication
