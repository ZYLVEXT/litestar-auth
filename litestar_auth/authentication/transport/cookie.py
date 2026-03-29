"""Cookie-based transport implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, override

from litestar_auth.authentication.transport.base import Transport

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.response import Response

type SameSitePolicy = Literal["lax", "strict", "none"]


class CookieTransport(Transport):
    """Transport that stores authentication tokens in HTTP cookies."""

    def __init__(  # noqa: PLR0913
        self,
        *,
        cookie_name: str = "litestar_auth",
        max_age: int | None = None,
        path: str = "/",
        domain: str | None = None,
        secure: bool = True,
        httponly: bool = True,
        samesite: SameSitePolicy = "lax",
        allow_insecure_cookie_auth: bool = False,
        refresh_max_age: int | None = None,
    ) -> None:
        """Initialize the cookie transport configuration.

        Args:
            cookie_name: Name of the auth cookie.
            max_age: Optional cookie max-age in seconds.
            path: Cookie path.
            domain: Optional cookie domain.
            secure: Whether to set the Secure attribute.
            httponly: Whether to set the HttpOnly attribute on the auth cookie.
            samesite: SameSite policy for cookies.
            allow_insecure_cookie_auth: When ``True``, allow cookie auth with
                plugin-managed CSRF disabled outside testing mode. This is unsafe for
                browser authentication and should only be used for controlled,
                non-browser scenarios.
            refresh_max_age: Optional cookie max-age in seconds for the refresh-token
                cookie. When ``None``, falls back to ``max_age``. Set this to match
                your strategy's ``refresh_max_age`` so the cookie outlives the
                access-token cookie.

        Raises:
            ValueError: If ``samesite="none"`` is configured with ``secure=False``.
        """
        if samesite == "none" and not secure:
            msg = 'CookieTransport with samesite="none" requires secure=True.'
            raise ValueError(msg)
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.path = path
        self.domain = domain
        self.secure = secure
        self.httponly = httponly
        self.samesite = samesite
        self.allow_insecure_cookie_auth = allow_insecure_cookie_auth
        # Security: separate refresh cookie lifetime prevents premature browser
        # deletion when access-token max_age is shorter than the refresh strategy TTL.
        self.refresh_max_age = refresh_max_age

    @property
    def refresh_cookie_name(self) -> str:
        """Return the cookie key used to carry refresh tokens in cookie flows."""
        return f"{self.cookie_name}_refresh"

    def _set_cookie(
        self,
        response: Response[Any],
        *,
        key: str,
        value: str,
        max_age: int | None,
        httponly: bool,
    ) -> Response[Any]:
        """Apply the transport cookie configuration to a response cookie.

        Returns:
            The mutated response.
        """
        response.set_cookie(
            key=key,
            value=value,
            max_age=max_age,
            path=self.path,
            domain=self.domain,
            secure=self.secure,
            httponly=httponly,
            samesite=self.samesite,
        )
        return response

    @override
    async def read_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Return the authentication token from the configured cookie."""
        return connection.cookies.get(self.cookie_name)

    async def read_logout_token(self, connection: ASGIConnection[Any, Any, Any, Any]) -> str | None:
        """Return the access-token cookie value to invalidate during logout.

        Logout token sourcing is explicit here: cookie logout invalidates the
        access-token cookie and does not read refresh-token cookies.
        """
        return await self.read_token(connection)

    def set_refresh_token(self, response: Response[Any], refresh_token: str) -> Response[Any]:
        """Persist a refresh token in a dedicated HttpOnly cookie.

        Note:
            This library intentionally treats refresh tokens as a separate artifact from the
            access-token cookie used for request authentication.

        Returns:
            The mutated response.
        """
        # Security: use dedicated refresh_max_age so the cookie outlives the access-token cookie.
        effective_max_age = self.refresh_max_age if self.refresh_max_age is not None else self.max_age
        return self._set_cookie(
            response,
            key=self.refresh_cookie_name,
            value=refresh_token,
            max_age=effective_max_age,
            httponly=True,
        )

    def clear_refresh_token(self, response: Response[Any]) -> Response[Any]:
        """Expire the refresh-token cookie immediately.

        Returns:
            The mutated response.
        """
        return self._set_cookie(
            response,
            key=self.refresh_cookie_name,
            value="",
            max_age=0,
            httponly=True,
        )

    @override
    def set_login_token(self, response: Response[Any], token: str) -> Response[Any]:
        r"""Persist the issued token in the configured cookie.

        Security:
            When this transport is used for browser-based authentication, you MUST
            pair it with an explicit CSRF protection mechanism (for example, a
            separate CSRF cookie and a required X-CSRF-Token header on state-changing
            requests). This is especially important when ``samesite=\"none\"`` is used
            for cross-site scenarios, because browsers will attach cookies
            automatically to cross-origin requests.

        Returns:
            The mutated response.
        """
        return self._set_cookie(
            response,
            key=self.cookie_name,
            value=token,
            max_age=self.max_age,
            httponly=self.httponly,
        )

    @override
    def set_logout(self, response: Response[Any]) -> Response[Any]:
        """Remove the access-token cookie by expiring it immediately.

        Note:
            This transport-level method clears only the access-token cookie.
            The refresh-token cookie is cleared by
            :meth:`AuthenticationBackend.logout`, which calls
            :meth:`clear_refresh_token` after this method.

        Returns:
            The mutated response.
        """
        return self._set_cookie(
            response,
            key=self.cookie_name,
            value="",
            max_age=0,
            httponly=self.httponly,
        )
