"""Cookie-based transport implementation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, TypedDict, Unpack, override

from litestar_auth.authentication.transport.base import Transport

if TYPE_CHECKING:
    from litestar.connection import ASGIConnection
    from litestar.response import Response

type SameSitePolicy = Literal["lax", "strict", "none"]


@dataclass(frozen=True, slots=True)
class CookieTransportConfig:
    """Configuration for :class:`CookieTransport`."""

    cookie_name: str = "litestar_auth"
    max_age: int | None = None
    path: str = "/"
    domain: str | None = None
    secure: bool = True
    httponly: bool = True
    samesite: SameSitePolicy = "lax"
    allow_insecure_cookie_auth: bool = False
    refresh_max_age: int | None = None


class CookieTransportConfigOptions(TypedDict, total=False):
    """Keyword options accepted by :class:`CookieTransport`."""

    cookie_name: str
    max_age: int | None
    path: str
    domain: str | None
    secure: bool
    httponly: bool
    samesite: SameSitePolicy
    allow_insecure_cookie_auth: bool
    refresh_max_age: int | None


class CookieTransport(Transport):
    """Transport that stores authentication tokens in HTTP cookies."""

    def __init__(
        self,
        config: CookieTransportConfig | None = None,
        **options: Unpack[CookieTransportConfigOptions],
    ) -> None:
        """Initialize the cookie transport configuration.

        Args:
            config: Cookie transport configuration. Omit for secure defaults.
            **options: Individual cookie transport settings. Do not combine with
                ``config``.

        Raises:
            ValueError: If ``config`` and keyword options are combined.
            ValueError: If ``samesite="none"`` is configured with ``secure=False``.
        """
        if config is not None and options:
            msg = "Pass either CookieTransportConfig or keyword options, not both."
            raise ValueError(msg)
        settings = CookieTransportConfig(**options) if config is None else config
        if settings.samesite == "none" and not settings.secure:
            msg = 'CookieTransport with samesite="none" requires secure=True.'
            raise ValueError(msg)
        self.cookie_name = settings.cookie_name
        self.max_age = settings.max_age
        self.path = settings.path
        self.domain = settings.domain
        self.secure = settings.secure
        self.httponly = settings.httponly
        self.samesite = settings.samesite
        self.allow_insecure_cookie_auth = settings.allow_insecure_cookie_auth
        # Security: separate refresh cookie lifetime prevents premature browser
        # deletion when access-token max_age is shorter than the refresh strategy TTL.
        self.refresh_max_age = settings.refresh_max_age

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
