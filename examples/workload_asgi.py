"""Minimal non-Litestar ASGI portability proof for authweave-core."""

from authweave_core import (
    Authenticated,
    AuthenticationCoordinator,
    AuthenticationRuntime,
    InvariantFailure,
    RequestAuthenticationProvider,
    RequestView,
    RouteProviderPolicy,
    Unavailable,
)


def build_asgi_authenticator(provider: RequestAuthenticationProvider) -> object:
    """Return a tiny ASGI app showing the neutral coordinator boundary."""
    coordinator = AuthenticationCoordinator((provider,))
    policy = RouteProviderPolicy((provider.name,))

    async def app(scope: dict[str, object], _receive: object, send: object) -> None:
        request = RequestView(
            method=str(scope.get("method", "GET")),
            headers=tuple(scope.get("headers", ())),  # ty: ignore[invalid-argument-type]
        )
        decision = await coordinator.authenticate(request, AuthenticationRuntime(), policy=policy)
        body = type(decision).__name__.encode()
        if isinstance(decision, Authenticated):
            status = 200
        elif isinstance(decision, (Unavailable, InvariantFailure)):
            status = 503
        else:
            status = 401
        await send({"type": "http.response.start", "status": status, "headers": []})  # ty: ignore[call-non-callable]
        await send({"type": "http.response.body", "body": body})  # ty: ignore[call-non-callable]

    return app
