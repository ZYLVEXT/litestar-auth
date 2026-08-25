"""Integration coverage for the root package public API."""

from __future__ import annotations

import importlib
import inspect
import logging
from datetime import UTC, datetime
from typing import (
    TYPE_CHECKING,
    Annotated,
    Any,
    cast,
    get_args,
    get_origin,
    get_type_hints,
)
from uuid import UUID

import pytest

import litestar_auth
import litestar_auth.authentication.strategy as strategy_module
import litestar_auth.config as config_module
import litestar_auth.contrib.redis as redis_contrib_module
import litestar_auth.controllers as controllers_package
import litestar_auth.controllers.oauth as oauth_controller_module
import litestar_auth.db as db_module
import litestar_auth.models as models_module
import litestar_auth.oauth as oauth_package_module
import litestar_auth.oauth._client as oauth_client_module
import litestar_auth.payloads as payloads_module
import litestar_auth.plugin as plugin_module
import litestar_auth.ratelimit as ratelimit_module
import litestar_auth.schemas as schemas_module
import litestar_auth.totp as totp_module
from litestar_auth.authentication.strategy._jwt_denylist import RedisJWTDenylistStore
from litestar_auth.authentication.strategy.db_models import AccessToken, RefreshToken
from litestar_auth.authentication.transport import Transport
from litestar_auth.db.sqlalchemy import SQLAlchemyOrganizationStore, SQLAlchemyUserDatabase
from litestar_auth.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    InvalidPasswordError,
    InvalidResetPasswordTokenError,
    InvalidVerifyTokenError,
    OAuthAccountAlreadyLinkedError,
    TokenError,
    UserAlreadyExistsError,
    UserNotExistsError,
)
from litestar_auth.oauth._client import (
    OAuthEmailVerificationAsyncClientProtocol,
    OAuthEmailVerificationSyncClientProtocol,
    make_async_email_verification_client,
)
from litestar_auth.password import PasswordHelper
from litestar_auth.types import DbSessionDependencyKey
from tests._helpers import ExampleUser, cast_fakeredis
from tests.conftest import project_version_from_pyproject

AuthExtension = litestar_auth.AuthExtension
AuthExtensionRegistrationContext = litestar_auth.AuthExtensionRegistrationContext
AuthExtensionValidationContext = litestar_auth.AuthExtensionValidationContext
AuthenticationResultHook = litestar_auth.AuthenticationResultHook
BaseUserManager = litestar_auth.BaseUserManager
BaseUserManagerConfig = litestar_auth.BaseUserManagerConfig
CookieTransport = litestar_auth.CookieTransport
CookieTransport = litestar_auth.CookieTransport
CookieTransportConfig = litestar_auth.CookieTransportConfig
DatabaseTokenAuthConfig = litestar_auth.DatabaseTokenAuthConfig
ErrorCode = litestar_auth.ErrorCode
FernetKeyringConfig = litestar_auth.FernetKeyringConfig
GuardedUserProtocol = litestar_auth.GuardedUserProtocol
LitestarAuth = litestar_auth.LitestarAuth
LitestarAuthConfig = litestar_auth.LitestarAuthConfig
LitestarAuthError = litestar_auth.LitestarAuthError
OAuthConfig = litestar_auth.OAuthConfig
OAuthProviderConfig = litestar_auth.OAuthProviderConfig
OrganizationConfig = litestar_auth.OrganizationConfig
RoleCapableUserProtocol = litestar_auth.RoleCapableUserProtocol
RequestSessionProvider = litestar_auth.RequestSessionProvider
TotpConfig = litestar_auth.TotpConfig
TotpUserProtocol = litestar_auth.TotpUserProtocol
UserManagerSecurity = litestar_auth.UserManagerSecurity
UserProtocol = litestar_auth.UserProtocol
UserProtocolStrict = litestar_auth.UserProtocolStrict
__all__ = litestar_auth.__all__
__version__ = litestar_auth.__version__
has_all_roles = litestar_auth.has_all_roles
has_any_role = litestar_auth.has_any_role
is_active = litestar_auth.is_active
is_authenticated = litestar_auth.is_authenticated
is_superuser = litestar_auth.is_superuser
is_verified = litestar_auth.is_verified
DatabaseTokenStrategy = strategy_module.DatabaseTokenStrategy
DatabaseTokenStrategyConfig = strategy_module.DatabaseTokenStrategyConfig
RedisTokenStrategy = strategy_module.RedisTokenStrategy
RedisTokenStrategyConfig = strategy_module.RedisTokenStrategyConfig
Strategy = strategy_module.Strategy
require_password_length = config_module.require_password_length
RedisAuthClientProtocol = redis_contrib_module.RedisAuthClientProtocol
RedisAuthPreset = redis_contrib_module.RedisAuthPreset
RedisAuthRateLimitConfigOptions = redis_contrib_module.RedisAuthRateLimitConfigOptions
RedisAuthRateLimitTier = redis_contrib_module.RedisAuthRateLimitTier
ContribRedisTokenStrategyConfig = redis_contrib_module.RedisTokenStrategyConfig
ContribRedisTotpEnrollmentStore = redis_contrib_module.RedisTotpEnrollmentStore
AuthControllerConfig = controllers_package.AuthControllerConfig
OAuthAssociateControllerConfig = controllers_package.OAuthAssociateControllerConfig
OAuthControllerConfig = controllers_package.OAuthControllerConfig
RegisterControllerConfig = controllers_package.RegisterControllerConfig
TotpControllerOptions = controllers_package.TotpControllerOptions
TotpUserManagerProtocol = controllers_package.TotpUserManagerProtocol
UsersControllerConfig = controllers_package.UsersControllerConfig
create_auth_controller = controllers_package.create_auth_controller
create_oauth_associate_controller = controllers_package.create_oauth_associate_controller
create_oauth_controller = controllers_package.create_oauth_controller
create_register_controller = controllers_package.create_register_controller
create_reset_password_controller = controllers_package.create_reset_password_controller
create_totp_controller = controllers_package.create_totp_controller
create_users_controller = controllers_package.create_users_controller
create_verify_controller = controllers_package.create_verify_controller
BaseOAuthAccountStore = db_module.BaseOAuthAccountStore
BaseOrganizationStore = db_module.BaseOrganizationStore
BaseUserStore = db_module.BaseUserStore
MembershipData = db_module.MembershipData
OAuthAccountData = db_module.OAuthAccountData
OrganizationData = db_module.OrganizationData
OrganizationInvitationData = db_module.OrganizationInvitationData


class _InMemoryOrganizationStore:  # ruff: ignore[too-many-public-methods] - protocol fixture
    """Minimal organization store satisfying the runtime-checkable protocol."""

    def __init__(self, *, organization: dict[str, Any], membership: dict[str, Any]) -> None:
        self.organization = organization
        self.membership = membership

    async def create_organization(self, data: OrganizationData) -> dict[str, Any]:
        return {"id": self.organization["id"], "slug": data.slug, "name": data.name}

    async def get_organization(self, organization_id: UUID) -> dict[str, Any] | None:
        return self.organization if organization_id == self.organization["id"] else None

    async def get_organization_by_slug(self, slug: str) -> dict[str, Any] | None:
        return self.organization if slug == self.organization["slug"] else None

    async def update_organization(self, organization_id: UUID, data: OrganizationData) -> dict[str, Any] | None:
        if organization_id != self.organization["id"]:
            return None
        return {"id": organization_id, "slug": data.slug, "name": data.name}

    async def delete_organization(self, organization_id: UUID) -> bool:
        return organization_id == self.organization["id"]

    async def add_membership(self, data: MembershipData[UUID]) -> dict[str, Any]:
        return {
            "organization_id": data.organization_id,
            "user_id": data.user_id,
            "roles": data.roles,
        }

    async def get_membership(self, *, organization_id: UUID, user_id: UUID) -> dict[str, Any] | None:
        if organization_id == self.membership["organization_id"] and user_id == self.membership["user_id"]:
            return self.membership
        return None

    async def list_memberships(
        self,
        organization_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> tuple[list[dict[str, Any]], int]:
        memberships = [self.membership] if organization_id == self.membership["organization_id"] else []
        return memberships[offset : offset + limit], len(memberships)

    async def remove_membership(self, *, organization_id: UUID, user_id: UUID) -> bool:
        return organization_id == self.membership["organization_id"] and user_id == self.membership["user_id"]

    async def remove_membership_preserving_privileged_member(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        privileged_roles: frozenset[str],
    ) -> bool:
        return await self.remove_membership(organization_id=organization_id, user_id=user_id)

    async def set_membership_roles(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        roles: list[str],
    ) -> dict[str, Any] | None:
        if organization_id != self.membership["organization_id"] or user_id != self.membership["user_id"]:
            return None
        return {"organization_id": organization_id, "user_id": user_id, "roles": roles}

    async def set_membership_roles_preserving_privileged_member(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        roles: list[str],
        privileged_roles: frozenset[str],
    ) -> dict[str, Any] | None:
        return await self.set_membership_roles(organization_id=organization_id, user_id=user_id, roles=roles)

    async def list_organizations_for_user(
        self,
        user_id: UUID,
        *,
        offset: int,
        limit: int,
    ) -> tuple[list[dict[str, Any]], int]:
        organizations = [self.organization] if user_id == self.membership["user_id"] else []
        return organizations[offset : offset + limit], len(organizations)

    async def create_invitation(self, data: OrganizationInvitationData[UUID]) -> dict[str, Any]:
        return {
            "id": UUID(int=3),
            "organization_id": data.organization_id,
            "invited_email": data.invited_email,
            "roles": data.roles,
            "token_hash": data.token_hash,
            "expires_at": data.expires_at,
            "status": "pending",
        }

    async def get_invitation_by_token_hash(self, token_hash: bytes) -> dict[str, Any] | None:
        if token_hash == b"invitation-hash":
            return {"token_hash": token_hash, "status": "pending"}
        return None

    async def get_invitation(self, invitation_id: UUID) -> dict[str, Any] | None:
        if invitation_id == UUID(int=3):
            return {"id": invitation_id, "organization_id": self.organization["id"], "status": "pending"}
        return None

    async def list_pending_invitations(
        self,
        organization_id: UUID,
        *,
        now: datetime,
        offset: int,
        limit: int,
    ) -> tuple[list[dict[str, Any]], int]:
        if organization_id != self.organization["id"]:
            return [], 0
        invitations = [{"organization_id": organization_id, "expires_at": now, "status": "pending"}]
        return invitations[offset : offset + limit], len(invitations)

    async def revoke_invitation(self, invitation_id: UUID) -> dict[str, Any] | None:
        if invitation_id != UUID(int=3):
            return None
        return {"id": invitation_id, "status": "revoked"}

    async def consume_invitation(self, invitation_id: UUID, *, consumed_at: datetime) -> dict[str, Any] | None:
        if invitation_id != UUID(int=3):
            return None
        return {"id": invitation_id, "consumed_at": consumed_at, "status": "consumed"}

    async def finalize_invitation_acceptance(
        self,
        invitation_id: UUID,
        *,
        consumed_at: datetime,
        membership_data: MembershipData[UUID],
    ) -> dict[str, Any] | None:
        if invitation_id != UUID(int=3):
            return None
        return {
            "organization_id": membership_data.organization_id,
            "user_id": membership_data.user_id,
            "roles": membership_data.roles,
            "consumed_at": consumed_at,
        }


create_provider_oauth_controller = oauth_package_module.create_provider_oauth_controller
load_httpx_oauth_client = oauth_package_module.load_httpx_oauth_client
ForgotPassword = payloads_module.ForgotPassword
LoginCredentials = payloads_module.LoginCredentials
RequestVerifyToken = payloads_module.RequestVerifyToken
ResetPassword = payloads_module.ResetPassword
TotpConfirmEnableRequest = payloads_module.TotpConfirmEnableRequest
TotpConfirmEnableResponse = payloads_module.TotpConfirmEnableResponse
TotpDisableRequest = payloads_module.TotpDisableRequest
TotpEnableResponse = payloads_module.TotpEnableResponse
TotpVerifyRequest = payloads_module.TotpVerifyRequest
VerifyToken = payloads_module.VerifyToken
AuthRateLimitConfig = ratelimit_module.AuthRateLimitConfig
AuthRateLimitEndpointGroup = ratelimit_module.AuthRateLimitEndpointGroup
AuthRateLimitSlot = ratelimit_module.AuthRateLimitSlot
EndpointRateLimit = ratelimit_module.EndpointRateLimit
InMemoryRateLimiter = ratelimit_module.InMemoryRateLimiter
RedisRateLimiter = ratelimit_module.RedisRateLimiter
SharedRateLimitConfigOptions = ratelimit_module.SharedRateLimitConfigOptions
AdminUserUpdate = schemas_module.AdminUserUpdate
ChangePasswordRequest = schemas_module.ChangePasswordRequest
UserCreate = schemas_module.UserCreate
UserRead = schemas_module.UserRead
UserUpdate = schemas_module.UserUpdate
InMemoryTotpEnrollmentStore = totp_module.InMemoryTotpEnrollmentStore
InMemoryUsedTotpCodeStore = totp_module.InMemoryUsedTotpCodeStore
RedisTotpEnrollmentStore = totp_module.RedisTotpEnrollmentStore
RedisUsedTotpCodeStore = totp_module.RedisUsedTotpCodeStore
generate_totp_secret = totp_module.generate_totp_secret
generate_totp_uri = totp_module.generate_totp_uri
verify_totp = totp_module.verify_totp
verify_totp_with_store = totp_module.verify_totp_with_store

if TYPE_CHECKING:
    import msgspec
    from sqlalchemy.ext.asyncio import AsyncSession

    from tests._helpers import AsyncFakeRedis, AsyncFakeRedisFactory

SHARED_MAX_ATTEMPTS = 5
SHARED_WINDOW_SECONDS = 60
REFRESH_MAX_ATTEMPTS = 10
REFRESH_WINDOW_SECONDS = 300
TOTP_MAX_ATTEMPTS = 5
TOTP_WINDOW_SECONDS = 300
ONE_MINUTE_TTL_SECONDS = 60
ONE_MINUTE_TTL_FLOOR = ONE_MINUTE_TTL_SECONDS - 1
ONE_MINUTE_TTL_MS = ONE_MINUTE_TTL_SECONDS * 1000
AUTH_RATE_LIMIT_VERIFICATION_SLOT_IDENTIFIERS = frozenset(
    {
        AuthRateLimitSlot.VERIFY_TOKEN,
        AuthRateLimitSlot.REQUEST_VERIFY_TOKEN,
        AuthRateLimitSlot.ORGANIZATION_INVITATION_ACCEPT,
        AuthRateLimitSlot.ORGANIZATION_INVITATION_DECLINE,
    },
)
REMOVED_ROOT_PAYLOAD_EXPORTS = (
    "AdminUserUpdate",
    "ChangePasswordRequest",
    "ForgotPassword",
    "LoginCredentials",
    "RequestVerifyToken",
    "ResetPassword",
    "TotpConfirmEnableRequest",
    "TotpConfirmEnableResponse",
    "TotpDisableRequest",
    "TotpEnableResponse",
    "TotpVerifyRequest",
    "UserCreate",
    "UserRead",
    "UserUpdate",
    "VerifyToken",
)
REMOVED_CONTROLLERS_PAYLOAD_EXPORTS = (
    "ForgotPassword",
    "LoginCredentials",
    "RequestVerifyToken",
    "ResetPassword",
    "TotpConfirmEnableRequest",
    "TotpConfirmEnableResponse",
    "TotpDisableRequest",
    "TotpEnableResponse",
    "TotpVerifyRequest",
    "VerifyToken",
)
REMOVED_PAYLOAD_SCHEMA_EXPORTS = ("AdminUserUpdate", "ChangePasswordRequest", "UserCreate", "UserRead", "UserUpdate")
REMOVED_ROOT_SECONDARY_EXPORTS = (
    "AccessToken",
    "AuthRateLimitConfig",
    "AuthenticationBackend",
    "AuthenticationError",
    "Authenticator",
    "AuthorizationError",
    "ConfigurationError",
    "DatabaseTokenStrategyConfig",
    "DatabaseTokenStrategy",
    "DbSessionDependencyKey",
    "EndpointRateLimit",
    "InMemoryJWTDenylistStore",
    "InMemoryRateLimiter",
    "InMemoryTotpEnrollmentStore",
    "InMemoryUsedTotpCodeStore",
    "InvalidPasswordError",
    "InvalidResetPasswordTokenError",
    "InvalidVerifyTokenError",
    "JWTDenylistStore",
    "JWTStrategyConfig",
    "JWTStrategy",
    "OAuthAccountAlreadyLinkedError",
    "PasswordHelper",
    "RedisJWTDenylistStore",
    "RedisRateLimiter",
    "RedisTokenStrategy",
    "RedisTokenStrategyConfig",
    "RedisTotpEnrollmentStore",
    "RedisUsedTotpCodeStore",
    "RefreshToken",
    "Strategy",
    "TokenError",
    "TotpEnrollmentStore",
    "TotpUserManagerProtocol",
    "Transport",
    "UsedTotpCodeStore",
    "UserAlreadyExistsError",
    "UserNotExistsError",
    "create_auth_controller",
    "create_oauth_associate_controller",
    "create_oauth_controller",
    "create_provider_oauth_controller",
    "create_register_controller",
    "create_reset_password_controller",
    "create_totp_controller",
    "create_users_controller",
    "create_verify_controller",
    "generate_totp_secret",
    "generate_totp_uri",
    "load_httpx_oauth_client",
    "require_password_length",
    "verify_totp",
    "verify_totp_with_store",
)
REMOVED_OAUTH_CONTROLLER_ADAPTER_PASSTHROUGH_HELPERS = (
    "_get_authorization_url",
    "_get_access_token",
    "_get_account_identity",
    "_get_email_verified",
    "_as_mapping",
)

pytestmark = [pytest.mark.unit, pytest.mark.imports]
EMAIL_PATTERN = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
EMAIL_MAX_LENGTH = 320


def _field_meta(schema_type: type[msgspec.Struct], field_name: str) -> msgspec.Meta:
    """Return the ``msgspec.Meta`` attached to a struct field annotation.

    Raises:
        AssertionError: If the field annotation does not expose ``msgspec.Meta``.
    """
    annotation = get_type_hints(schema_type, include_extras=True)[field_name]

    for candidate in (annotation, *get_args(annotation)):
        value = candidate
        seen: set[int] = set()
        while (next_value := getattr(value, "__value__", None)) is not None and id(value) not in seen:
            seen.add(id(value))
            value = next_value
        if get_origin(value) is not Annotated:
            continue

        _, meta = get_args(value)
        return meta

    msg = f"{schema_type.__name__}.{field_name} is missing msgspec metadata."
    raise AssertionError(msg)


class _RootImportCoverageUserManager(BaseUserManager[ExampleUser, UUID]):
    """Minimal manager type for public import coverage."""


class _RootImportCoverageSession:
    """Minimal request-scoped session stub for preset import coverage."""

    async def commit(self) -> None:
        """No-op commit for request lifecycle parity."""

    async def rollback(self) -> None:
        """No-op rollback for request lifecycle parity."""

    async def close(self) -> None:
        """No-op close for request lifecycle parity."""


class _RootImportCoverageSessionFactory:
    """Callable session factory matching the documented plugin contract."""

    def __call__(self) -> AsyncSession:
        """Return a request-scoped session stub."""
        return cast("AsyncSession", _RootImportCoverageSession())


def _current_database_token_strategy_type() -> type[Any]:
    """Return the current DB-token strategy class after cross-test module reloads."""
    db_strategy_module = importlib.import_module("litestar_auth.authentication.strategy.db")
    return cast("type[Any]", db_strategy_module.DatabaseTokenStrategy)


def test_root_package_reexports_public_api() -> None:
    """The package root exposes the documented public auth API."""
    assert __version__ == project_version_from_pyproject()
    assert LitestarAuth is not None
    assert LitestarAuthConfig is not None
    assert AuthenticationResultHook is not None
    assert RequestSessionProvider is not None
    assert UserProtocol is not None
    assert UserProtocolStrict is not None
    assert GuardedUserProtocol is not None
    assert RoleCapableUserProtocol is not None
    assert TotpUserProtocol is not None
    assert CookieTransport is not None
    assert CookieTransport is not None
    assert CookieTransportConfig is not None
    assert DatabaseTokenAuthConfig is not None
    assert FernetKeyringConfig is not None
    assert OAuthConfig is not None
    assert OAuthProviderConfig is not None
    assert OrganizationConfig is not None
    assert TotpConfig is not None
    assert BaseUserManager is not None
    assert BaseUserManagerConfig is not None
    assert UserManagerSecurity is not None
    assert callable(is_authenticated)
    assert callable(is_active)
    assert callable(is_verified)
    assert callable(is_superuser)
    assert callable(has_any_role)
    assert callable(has_all_roles)
    assert ErrorCode is not None
    assert LitestarAuthError is not None


def test_root_package_reexports_role_guard_factories() -> None:
    """The package root exposes the documented role guard factories."""
    assert callable(has_any_role)
    assert callable(has_all_roles)


def test_root_package_exports_canonical_database_token_preset_entrypoint() -> None:
    """The root package exposes the documented DB cookie-session preset entrypoint."""
    session_maker = _RootImportCoverageSessionFactory()
    config = LitestarAuthConfig[ExampleUser, UUID](
        database_token_auth=DatabaseTokenAuthConfig(
            token_hash_secret="157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe"
        ),
        user_model=ExampleUser,
        user_manager_class=_RootImportCoverageUserManager,
        session_maker=session_maker,
        user_db_factory=lambda _session: cast("Any", object()),
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe",
            reset_password_token_secret="6a04e4ffd25866a9cce15600e9ff4bd0865b84e7474f6c7eb2d75fef3c0a81d8",
        ),
    )

    preset = config.database_token_auth
    assert preset is not None
    assert preset.token_hash_secret == "157261932c2bdecb9f6c6ee849a24e3a979a9bf46cf50e99a739b4cd5545cebe"
    assert config.session_maker is session_maker

    backend = config.resolve_startup_backends()[0]
    assert isinstance(backend, plugin_module.StartupBackendTemplate)
    assert backend.name == "database"
    assert isinstance(backend.transport, CookieTransport)
    assert not isinstance(backend.strategy, DatabaseTokenStrategy)
    assert callable(getattr(backend.strategy, "with_session", None))


def test_public_user_schema_reuse_surface_stays_importable() -> None:
    """Custom-schema email/password helpers stay on the dedicated public schemas module.

    The self-service ``UserUpdate`` carries email plus optional current-password
    proof for email changes. Privileged fields (``is_active`` / ``is_verified``
    / ``roles``) live exclusively on :class:`AdminUserUpdate`, so this contract
    no longer exposes a ``roles`` or any other privileged annotation.
    """
    user_create_email_meta = _field_meta(UserCreate, "email")
    user_update_email_meta = _field_meta(UserUpdate, "email")
    user_create_meta = _field_meta(UserCreate, "password")
    user_update_current_password_meta = _field_meta(UserUpdate, "current_password")
    user_read_roles_annotation = get_type_hints(UserRead, include_extras=True)["roles"]
    user_create_email_annotation = get_type_hints(UserCreate, include_extras=True)["email"]
    user_update_email_annotation = get_type_hints(UserUpdate, include_extras=True)["email"]
    user_create_annotation = get_type_hints(UserCreate, include_extras=True)["password"]
    user_update_current_password_annotation = get_type_hints(UserUpdate, include_extras=True)["current_password"]
    user_update_hints = get_type_hints(UserUpdate, include_extras=True)
    email_field_value = getattr(schemas_module.UserEmailField, "__value__", schemas_module.UserEmailField)
    password_field_value = getattr(schemas_module.UserPasswordField, "__value__", schemas_module.UserPasswordField)

    assert schemas_module.__all__ == (
        "AdminUserUpdate",
        "ChangePasswordRequest",
        "CurrentPasswordField",
        "UserCreate",
        "UserEmailField",
        "UserPasswordField",
        "UserRead",
        "UserUpdate",
    )
    assert schemas_module.AdminUserUpdate is AdminUserUpdate
    assert schemas_module.ChangePasswordRequest is ChangePasswordRequest
    assert schemas_module.CurrentPasswordField is not None
    assert schemas_module.CurrentPasswordField.__module__ == "litestar_auth.schemas"
    assert schemas_module.UserEmailField is not None
    assert schemas_module.UserEmailField.__module__ == "litestar_auth.schemas"
    assert schemas_module.UserPasswordField is not None
    assert schemas_module.UserPasswordField.__module__ == "litestar_auth.schemas"
    assert not hasattr(litestar_auth, "AdminUserUpdate")
    assert not hasattr(litestar_auth, "ChangePasswordRequest")
    assert not hasattr(litestar_auth, "CurrentPasswordField")
    assert not hasattr(litestar_auth, "UserEmailField")
    assert not hasattr(litestar_auth, "UserPasswordField")
    assert getattr(user_create_email_annotation, "__value__", user_create_email_annotation) == email_field_value
    assert (
        getattr(get_args(user_update_email_annotation)[0], "__value__", get_args(user_update_email_annotation)[0])
        == email_field_value
    )
    assert get_args(user_update_email_annotation)[1] is type(None)
    assert getattr(user_create_annotation, "__value__", user_create_annotation) == password_field_value
    assert get_args(user_update_current_password_annotation)[1] is type(None)
    assert "password" not in user_update_hints
    # Privileged fields live exclusively on AdminUserUpdate now.
    assert "is_active" not in user_update_hints
    assert "is_verified" not in user_update_hints
    assert "roles" not in user_update_hints
    assert user_read_roles_annotation == list[str]
    assert user_create_email_meta.max_length == EMAIL_MAX_LENGTH
    assert user_update_email_meta.max_length == EMAIL_MAX_LENGTH
    assert user_create_email_meta.pattern == EMAIL_PATTERN
    assert user_update_email_meta.pattern == EMAIL_PATTERN
    assert user_create_meta.min_length == config_module.DEFAULT_MINIMUM_PASSWORD_LENGTH
    assert user_create_meta.max_length == config_module.MAX_PASSWORD_LENGTH
    assert user_update_current_password_meta.min_length == 1
    assert user_update_current_password_meta.max_length == config_module.MAX_PASSWORD_LENGTH
    assert (
        importlib.import_module("litestar_auth.config").require_password_length is config_module.require_password_length
    )


def test_admin_user_update_schema_reuse_surface_stays_importable() -> None:
    """AdminUserUpdate mirrors the current public update helper contracts."""
    admin_user_update_email_meta = _field_meta(AdminUserUpdate, "email")
    admin_user_update_meta = _field_meta(AdminUserUpdate, "password")
    admin_user_update_current_password_meta = _field_meta(AdminUserUpdate, "current_password")
    admin_user_update_roles_annotation = get_type_hints(AdminUserUpdate, include_extras=True)["roles"]
    admin_user_update_email_annotation = get_type_hints(AdminUserUpdate, include_extras=True)["email"]
    admin_user_update_annotation = get_type_hints(AdminUserUpdate, include_extras=True)["password"]
    admin_user_update_current_password_annotation = get_type_hints(AdminUserUpdate, include_extras=True)[
        "current_password"
    ]
    email_field_value = getattr(schemas_module.UserEmailField, "__value__", schemas_module.UserEmailField)
    password_field_value = getattr(schemas_module.UserPasswordField, "__value__", schemas_module.UserPasswordField)

    assert (
        getattr(
            get_args(admin_user_update_email_annotation)[0],
            "__value__",
            get_args(admin_user_update_email_annotation)[0],
        )
        == email_field_value
    )
    assert get_args(admin_user_update_email_annotation)[1] is type(None)
    assert getattr(
        get_args(admin_user_update_annotation)[0],
        "__value__",
        get_args(admin_user_update_annotation)[0],
    ) == (password_field_value)
    assert get_args(admin_user_update_annotation)[1] is type(None)
    assert get_args(admin_user_update_current_password_annotation)[1] is type(None)
    assert get_args(admin_user_update_roles_annotation)[0] == list[str]
    assert get_args(admin_user_update_roles_annotation)[1] is type(None)
    assert admin_user_update_email_meta.max_length == EMAIL_MAX_LENGTH
    assert admin_user_update_email_meta.pattern == EMAIL_PATTERN
    assert admin_user_update_meta.min_length == config_module.DEFAULT_MINIMUM_PASSWORD_LENGTH
    assert admin_user_update_meta.max_length == config_module.MAX_PASSWORD_LENGTH
    assert admin_user_update_current_password_meta.min_length == 1
    assert admin_user_update_current_password_meta.max_length == config_module.MAX_PASSWORD_LENGTH


def test_change_password_request_reuse_surface_stays_importable() -> None:
    """ChangePasswordRequest accepts old credentials but applies policy to the replacement."""
    current_password_meta = _field_meta(ChangePasswordRequest, "current_password")
    new_password_meta = _field_meta(ChangePasswordRequest, "new_password")
    new_password_annotation = get_type_hints(ChangePasswordRequest, include_extras=True)["new_password"]
    password_field_value = getattr(schemas_module.UserPasswordField, "__value__", schemas_module.UserPasswordField)

    assert getattr(new_password_annotation, "__value__", new_password_annotation) == password_field_value
    assert current_password_meta.min_length == 1
    assert current_password_meta.max_length == config_module.MAX_PASSWORD_LENGTH
    assert new_password_meta.min_length == config_module.DEFAULT_MINIMUM_PASSWORD_LENGTH
    assert new_password_meta.max_length == config_module.MAX_PASSWORD_LENGTH


def test_root_package_does_not_promote_token_orm_bootstrap_helper() -> None:
    """The token bootstrap helper stays on ``litestar_auth.models`` rather than root or strategy modules."""
    assert "import_token_orm_models" not in __all__
    assert not hasattr(litestar_auth, "import_token_orm_models")
    assert "import_token_orm_models" in models_module.__all__
    assert "import_token_orm_models" not in strategy_module.__all__
    assert not hasattr(strategy_module, "import_token_orm_models")


async def test_organization_store_contract_accepts_structural_backend() -> None:
    """A minimal organization store satisfies the runtime-checkable protocol."""
    organization_id = UUID(int=1)
    user_id = UUID(int=2)
    organization = {"id": organization_id, "slug": "acme", "name": "Acme"}
    membership = {"organization_id": organization_id, "user_id": user_id, "roles": ["owner"]}
    store = _InMemoryOrganizationStore(organization=organization, membership=membership)

    assert isinstance(store, BaseOrganizationStore)
    assert await store.create_organization(OrganizationData(slug="acme", name="Acme")) == organization
    assert await store.get_organization(organization_id) == organization
    assert await store.get_organization_by_slug("acme") == organization
    assert await store.update_organization(organization_id, OrganizationData(slug="acme-updated", name="Acme Updated"))
    assert await store.delete_organization(organization_id) is True
    assert await store.add_membership(MembershipData(organization_id=organization_id, user_id=user_id, roles=["owner"]))
    assert await store.get_membership(organization_id=organization_id, user_id=user_id) == membership
    assert await store.list_memberships(organization_id, offset=0, limit=10) == ([membership], 1)
    assert await store.remove_membership(organization_id=organization_id, user_id=user_id) is True
    assert await store.set_membership_roles(organization_id=organization_id, user_id=user_id, roles=["admin"])
    assert await store.list_organizations_for_user(user_id, offset=0, limit=10) == ([organization], 1)
    invitation_data = OrganizationInvitationData(
        organization_id=organization_id,
        invited_email="invitee@example.com",
        roles=["member"],
        token_hash=b"invitation-hash",
        expires_at=datetime.now(tz=UTC),
    )
    assert await store.create_invitation(invitation_data)
    assert await store.get_invitation_by_token_hash(b"invitation-hash")
    assert await store.list_pending_invitations(organization_id, now=invitation_data.expires_at, offset=0, limit=10)
    assert await store.revoke_invitation(UUID(int=3))
    assert await store.consume_invitation(UUID(int=3), consumed_at=invitation_data.expires_at)
    accepted = await store.finalize_invitation_acceptance(
        UUID(int=3),
        consumed_at=invitation_data.expires_at,
        membership_data=MembershipData(organization_id=organization_id, user_id=user_id, roles=["member"]),
    )
    assert accepted == {
        "organization_id": organization_id,
        "user_id": user_id,
        "roles": ["member"],
        "consumed_at": invitation_data.expires_at,
    }


def test_sqlalchemy_user_database_keeps_documented_keyword_contract() -> None:
    """The SQLAlchemy adapter keeps ``user_model`` and ``oauth_account_model`` as keyword-only inputs."""
    init_signature = inspect.signature(SQLAlchemyUserDatabase.__init__)

    assert init_signature.parameters["session"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert init_signature.parameters["user_model"].kind is inspect.Parameter.KEYWORD_ONLY
    assert init_signature.parameters["oauth_account_model"].kind is inspect.Parameter.KEYWORD_ONLY
    assert init_signature.parameters["oauth_account_model"].default is None


def test_sqlalchemy_organization_store_keeps_documented_keyword_contract() -> None:
    """The organization SQLAlchemy adapter keeps model inputs explicit and keyword-only."""
    init_signature = inspect.signature(SQLAlchemyOrganizationStore.__init__)

    assert init_signature.parameters["session"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert init_signature.parameters["organization_model"].kind is inspect.Parameter.KEYWORD_ONLY
    assert init_signature.parameters["membership_model"].kind is inspect.Parameter.KEYWORD_ONLY
    assert init_signature.parameters["organization_model"].default is inspect.Parameter.empty
    assert init_signature.parameters["membership_model"].default is inspect.Parameter.empty


def test_controller_factories_and_payloads_stay_canonical() -> None:
    """Controller factories and payload structs resolve from their canonical modules."""
    assert LoginCredentials.__struct_fields__ == ("identifier", "password")
    assert ForgotPassword.__struct_fields__ == ("email",)
    assert ResetPassword.__struct_fields__ == ("token", "password")
    assert VerifyToken.__struct_fields__ == ("token",)
    assert RequestVerifyToken.__struct_fields__ == ("email",)
    assert TotpConfirmEnableRequest.__struct_fields__ == ("enrollment_token", "code")
    assert TotpConfirmEnableResponse.__struct_fields__ == ("enabled", "recovery_codes")
    assert TotpEnableResponse.__struct_fields__ == ("secret", "uri", "enrollment_token")
    assert TotpVerifyRequest.__struct_fields__ == ("pending_token", "code")
    assert TotpDisableRequest.__struct_fields__ == ("code",)
    assert {
        "backend",
        "user_manager_dependency_key",
        "totp_pending_secret",
    } <= TotpControllerOptions.__annotations__.keys()
    assert TotpUserManagerProtocol is not None
    assert AuthControllerConfig is not None
    assert OAuthAssociateControllerConfig is not None
    assert OAuthControllerConfig is not None
    assert RegisterControllerConfig is not None
    assert UsersControllerConfig is not None
    assert callable(create_auth_controller)
    assert callable(create_register_controller)
    assert callable(create_verify_controller)
    assert callable(create_reset_password_controller)
    assert callable(create_users_controller)
    assert callable(create_totp_controller)
    assert callable(create_oauth_controller)


def test_root_package_does_not_reexport_payload_or_schema_structs() -> None:
    """Payload and schema structs must be imported from ``payloads`` or ``schemas``."""
    for symbol in REMOVED_ROOT_PAYLOAD_EXPORTS:
        assert symbol not in __all__
        assert not hasattr(litestar_auth, symbol)

    assert payloads_module.LoginCredentials is LoginCredentials
    assert payloads_module.ForgotPassword is ForgotPassword
    assert payloads_module.ResetPassword is ResetPassword
    assert payloads_module.VerifyToken is VerifyToken
    assert payloads_module.RequestVerifyToken is RequestVerifyToken
    assert payloads_module.TotpConfirmEnableRequest is TotpConfirmEnableRequest
    assert payloads_module.TotpConfirmEnableResponse is TotpConfirmEnableResponse
    assert payloads_module.TotpEnableResponse is TotpEnableResponse
    assert payloads_module.TotpVerifyRequest is TotpVerifyRequest
    assert payloads_module.TotpDisableRequest is TotpDisableRequest
    assert schemas_module.AdminUserUpdate is AdminUserUpdate
    assert schemas_module.UserCreate is UserCreate
    assert schemas_module.UserRead is UserRead
    assert schemas_module.UserUpdate is UserUpdate


def test_oauth_package_exposes_canonical_login_helper_and_not_advanced_controller_factory() -> None:
    """The OAuth package keeps the login helper canonical and custom controller factories elsewhere."""
    assert oauth_package_module.__all__ == (
        "OAuthEmailVerificationAsyncClientProtocol",
        "OAuthEmailVerificationSyncClientProtocol",
        "ProviderOAuthControllerConfig",
        "create_provider_oauth_controller",
        "load_httpx_oauth_client",
        "make_async_email_verification_client",
    )
    assert oauth_package_module.OAuthEmailVerificationAsyncClientProtocol is OAuthEmailVerificationAsyncClientProtocol
    assert oauth_package_module.OAuthEmailVerificationSyncClientProtocol is OAuthEmailVerificationSyncClientProtocol
    assert oauth_package_module.OAuthEmailVerificationAsyncClientProtocol is (
        oauth_client_module.OAuthEmailVerificationAsyncClientProtocol
    )
    assert oauth_package_module.OAuthEmailVerificationSyncClientProtocol is (
        oauth_client_module.OAuthEmailVerificationSyncClientProtocol
    )
    assert oauth_package_module.ProviderOAuthControllerConfig.__module__ == "litestar_auth.oauth.router"
    assert oauth_package_module.ProviderOAuthControllerConfig.__name__ == "ProviderOAuthControllerConfig"
    assert oauth_package_module.create_provider_oauth_controller.__module__ == "litestar_auth.oauth.router"
    assert oauth_package_module.create_provider_oauth_controller.__name__ == create_provider_oauth_controller.__name__
    assert oauth_package_module.load_httpx_oauth_client.__module__ == "litestar_auth.oauth.router"
    assert oauth_package_module.load_httpx_oauth_client.__name__ == load_httpx_oauth_client.__name__
    assert oauth_package_module.make_async_email_verification_client is make_async_email_verification_client
    assert oauth_package_module.make_async_email_verification_client is (
        oauth_client_module.make_async_email_verification_client
    )
    assert not hasattr(litestar_auth, "create_provider_oauth_controller")
    assert not hasattr(litestar_auth, "load_httpx_oauth_client")
    assert not hasattr(oauth_package_module, "create_oauth_controller")
    assert controllers_package.create_oauth_controller is create_oauth_controller
    assert controllers_package.create_oauth_associate_controller is create_oauth_associate_controller


def test_totp_module_exposes_canonical_public_surface() -> None:
    """The TOTP facade exports stable helpers without private internals."""
    assert totp_module.__all__ == (
        "DEFAULT_TOTP_ENROLLMENT_KEY_PREFIX",
        "DEFAULT_TOTP_RECOVERY_CODE_COUNT",
        "DEFAULT_TOTP_USED_KEY_PREFIX",
        "TIME_STEP_SECONDS",
        "TOTP_ALGORITHM",
        "TOTP_DIGITS",
        "TOTP_DRIFT_STEPS",
        "TOTP_RECOVERY_CODE_HEX_BYTES",
        "InMemoryTotpEnrollmentStore",
        "InMemoryUsedTotpCodeStore",
        "RedisTotpEnrollmentStore",
        "RedisTotpEnrollmentStoreClient",
        "RedisUsedTotpCodeStore",
        "RedisUsedTotpCodeStoreClient",
        "SecurityWarning",
        "TotpAlgorithm",
        "TotpEnrollmentStore",
        "TotpRecoveryCodeUserManager",
        "TotpReplayProtection",
        "UsedTotpCodeStore",
        "UsedTotpMarkResult",
        "abuild_recovery_code_index",
        "build_recovery_code_index",
        "generate_totp_recovery_codes",
        "generate_totp_secret",
        "generate_totp_uri",
        "verify_totp",
        "verify_totp_with_store",
    )
    assert inspect.iscoroutinefunction(totp_module.abuild_recovery_code_index)
    assert callable(totp_module.build_recovery_code_index)
    assert all(not symbol.startswith("_") for symbol in totp_module.__all__)


def test_oauth_controller_module_keeps_removed_adapter_shims_off_the_import_surface() -> None:
    """Removed controller shim names stay absent from the tested import boundary."""
    module_members = vars(oauth_controller_module)

    for helper_name in REMOVED_OAUTH_CONTROLLER_ADAPTER_PASSTHROUGH_HELPERS:
        assert helper_name not in module_members
        assert not hasattr(oauth_controller_module, helper_name)
        assert not hasattr(controllers_package, helper_name)


def test_legacy_contrib_oauth_package_is_removed() -> None:
    """The old contrib OAuth import path is not a compatibility re-export."""
    with pytest.raises(ModuleNotFoundError, match=r"litestar_auth\.contrib\.oauth"):
        importlib.import_module("litestar_auth.contrib.oauth")


def test_ratelimit_module_exposes_canonical_shared_backend_builder() -> None:
    """The public ratelimit module exposes the shared-backend builder entrypoint."""
    AuthRateLimitConfig = ratelimit_module.AuthRateLimitConfig
    EndpointRateLimit = ratelimit_module.EndpointRateLimit
    current_memory_limiter_class = ratelimit_module.InMemoryRateLimiter
    current_redis_limiter_class = ratelimit_module.RedisRateLimiter
    credential_backend = current_memory_limiter_class(max_attempts=3, window_seconds=60)
    refresh_backend = current_memory_limiter_class(max_attempts=4, window_seconds=90)
    totp_backend = current_memory_limiter_class(max_attempts=5, window_seconds=120)
    group_backends: dict[AuthRateLimitEndpointGroup, InMemoryRateLimiter] = {
        "totp": totp_backend,
        "refresh": refresh_backend,
    }
    disabled_slots = AUTH_RATE_LIMIT_VERIFICATION_SLOT_IDENTIFIERS

    config = AuthRateLimitConfig.from_shared_backend(
        credential_backend,
        options=SharedRateLimitConfigOptions(
            group_backends=group_backends,
            disabled=disabled_slots,
        ),
    )

    assert ratelimit_module.AuthRateLimitConfig is AuthRateLimitConfig
    assert ratelimit_module.EndpointRateLimit is EndpointRateLimit
    assert current_memory_limiter_class.__name__ == InMemoryRateLimiter.__name__
    assert current_redis_limiter_class.__name__ == RedisRateLimiter.__name__
    assert "AuthRateLimitConfig" in ratelimit_module.__all__
    assert "EndpointRateLimit" in ratelimit_module.__all__
    assert "InMemoryRateLimiter" in ratelimit_module.__all__
    assert "RedisRateLimiter" in ratelimit_module.__all__
    assert not hasattr(ratelimit_module, "_extract_email")
    assert not hasattr(ratelimit_module, "_load_redis_asyncio")
    assert not hasattr(ratelimit_module, "_safe_key_part")
    assert not hasattr(ratelimit_module, "_validate_configuration")
    assert not hasattr(ratelimit_module, "importlib")
    assert not hasattr(ratelimit_module, "logger")
    assert config.login == EndpointRateLimit(backend=credential_backend, scope="ip_email", namespace="login")
    assert config.refresh == EndpointRateLimit(backend=refresh_backend, scope="ip", namespace="refresh")
    assert config.forgot_password == EndpointRateLimit(
        backend=credential_backend,
        scope="ip_email",
        namespace="forgot-password",
    )
    assert config.totp_verify == EndpointRateLimit(backend=totp_backend, scope="ip", namespace="totp-verify")
    assert config.verify_token is None
    assert config.request_verify_token is None
    assert config.totp_disable == EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp-disable",
    )
    assert config.totp_regenerate_recovery_codes == EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp-regenerate-recovery-codes",
    )


async def test_root_package_supports_documented_redis_migration_recipe_and_totp_replay_store(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis_factory: AsyncFakeRedisFactory,
) -> None:
    """Public imports remain sufficient for the documented Redis migration recipe."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr("litestar_auth.ratelimit._redis._load_redis_asyncio", load_optional_redis)
    monkeypatch.setattr(totp_module._totp_stores, "_load_used_totp_redis_asyncio", load_optional_redis)
    monkeypatch.setattr(totp_module._totp_stores, "_load_enrollment_redis_asyncio", load_optional_redis)

    AuthRateLimitConfig = ratelimit_module.AuthRateLimitConfig
    EndpointRateLimit = ratelimit_module.EndpointRateLimit
    AuthRateLimitSlot = ratelimit_module.AuthRateLimitSlot
    rate_limit_redis_client = async_fakeredis_factory()
    rate_limit_redis = cast_fakeredis(rate_limit_redis_client, RedisAuthClientProtocol)
    totp_redis_client = async_fakeredis_factory()
    totp_redis = cast_fakeredis(totp_redis_client, RedisAuthClientProtocol)
    credential_backend = RedisRateLimiter(redis=rate_limit_redis, max_attempts=5, window_seconds=60)
    refresh_backend = RedisRateLimiter(redis=rate_limit_redis, max_attempts=10, window_seconds=300)
    totp_backend = RedisRateLimiter(redis=rate_limit_redis, max_attempts=5, window_seconds=300)
    forgot_password_override = EndpointRateLimit(
        backend=credential_backend,
        scope="ip_email",
        namespace="forgot_password",
    )
    reset_password_override = EndpointRateLimit(
        backend=credential_backend,
        scope="ip",
        namespace="reset_password",
    )
    totp_enable_override = EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp_enable",
    )
    totp_confirm_enable_override = EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp_confirm_enable",
    )
    totp_verify_override = EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp_verify",
    )
    totp_disable_override = EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp_disable",
    )
    totp_regenerate_override = EndpointRateLimit(
        backend=totp_backend,
        scope="ip",
        namespace="totp_regenerate_recovery_codes",
    )
    rate_limit_config = AuthRateLimitConfig.from_shared_backend(
        credential_backend,
        options=SharedRateLimitConfigOptions(
            group_backends={"refresh": refresh_backend, "totp": totp_backend},
            disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOT_IDENTIFIERS,
            endpoint_overrides={
                AuthRateLimitSlot.FORGOT_PASSWORD: forgot_password_override,
                AuthRateLimitSlot.RESET_PASSWORD: reset_password_override,
                AuthRateLimitSlot.TOTP_ENABLE: totp_enable_override,
                AuthRateLimitSlot.TOTP_CONFIRM_ENABLE: totp_confirm_enable_override,
                AuthRateLimitSlot.TOTP_VERIFY: totp_verify_override,
                AuthRateLimitSlot.TOTP_DISABLE: totp_disable_override,
                AuthRateLimitSlot.TOTP_REGENERATE_RECOVERY_CODES: totp_regenerate_override,
            },
        ),
    )
    used_tokens_store = RedisUsedTotpCodeStore(redis=totp_redis)
    enrollment_store = RedisTotpEnrollmentStore(redis=totp_redis)
    pending_jti_store = RedisJWTDenylistStore(redis=totp_redis)
    totp_config = TotpConfig(
        totp_pending_secret="2b101e06ab63b75e08f84e82a86e5d1d5f6bd92b8645ed3769a10b867bc10f44",
        totp_pending_jti_store=pending_jti_store,
        totp_used_tokens_store=used_tokens_store,
        totp_enrollment_store=enrollment_store,
    )

    assert litestar_auth.TotpConfig is plugin_module.TotpConfig
    assert AuthRateLimitConfig.__name__ == ratelimit_module.AuthRateLimitConfig.__name__
    assert RedisTotpEnrollmentStore.__name__ == totp_module.RedisTotpEnrollmentStore.__name__
    assert RedisUsedTotpCodeStore.__name__ == totp_module.RedisUsedTotpCodeStore.__name__
    assert rate_limit_config.login == EndpointRateLimit(
        backend=credential_backend,
        scope="ip_email",
        namespace="login",
    )
    assert rate_limit_config.refresh == EndpointRateLimit(backend=refresh_backend, scope="ip", namespace="refresh")
    assert rate_limit_config.forgot_password is forgot_password_override
    assert rate_limit_config.totp_verify is totp_verify_override
    assert rate_limit_config.totp_disable is totp_disable_override
    assert rate_limit_config.totp_regenerate_recovery_codes is totp_regenerate_override
    assert rate_limit_config.verify_token is None
    assert rate_limit_config.request_verify_token is None
    assert totp_config.totp_pending_jti_store is pending_jti_store
    assert totp_config.totp_used_tokens_store is used_tokens_store
    assert totp_config.totp_enrollment_store is enrollment_store
    assert (await used_tokens_store.mark_used("user-1", 7, 60.0)).stored is True
    await pending_jti_store.deny("pending-jti", ttl_seconds=ONE_MINUTE_TTL_SECONDS)
    assert await pending_jti_store.is_denied("pending-jti") is True
    assert await totp_redis_client.get("litestar_auth:totp:used:user-1:7") == b"1"
    assert await totp_redis_client.get("litestar_auth:jwt:denylist:pending-jti") == b"1"
    assert 0 < await totp_redis_client.pttl("litestar_auth:totp:used:user-1:7") <= ONE_MINUTE_TTL_MS
    assert (
        ONE_MINUTE_TTL_FLOOR
        <= await totp_redis_client.ttl("litestar_auth:jwt:denylist:pending-jti")
        <= ONE_MINUTE_TTL_SECONDS
    )


async def test_contrib_redis_preset_supports_documented_shared_client_recipe(
    monkeypatch: pytest.MonkeyPatch,
    async_fakeredis: AsyncFakeRedis,
) -> None:
    """The canonical contrib preset recipe derives rate limiting plus the TOTP Redis stores."""

    def load_optional_redis() -> object:
        return object()

    monkeypatch.setattr("litestar_auth.ratelimit._redis._load_redis_asyncio", load_optional_redis)
    monkeypatch.setattr(totp_module._totp_stores, "_load_used_totp_redis_asyncio", load_optional_redis)
    monkeypatch.setattr(totp_module._totp_stores, "_load_enrollment_redis_asyncio", load_optional_redis)
    monkeypatch.setattr("litestar_auth.authentication.strategy._jwt_denylist._load_redis_asyncio", load_optional_redis)
    redis_client = cast_fakeredis(async_fakeredis, RedisAuthClientProtocol)
    assert isinstance(redis_client, RedisAuthClientProtocol)
    preset = RedisAuthPreset(
        redis=redis_client,
        rate_limit_tier=RedisAuthRateLimitTier(
            max_attempts=SHARED_MAX_ATTEMPTS,
            window_seconds=SHARED_WINDOW_SECONDS,
        ),
        group_rate_limit_tiers={
            "refresh": RedisAuthRateLimitTier(
                max_attempts=REFRESH_MAX_ATTEMPTS,
                window_seconds=REFRESH_WINDOW_SECONDS,
            ),
            "totp": RedisAuthRateLimitTier(
                max_attempts=TOTP_MAX_ATTEMPTS,
                window_seconds=TOTP_WINDOW_SECONDS,
                key_prefix="totp:",
            ),
        },
        totp_used_tokens_key_prefix="used:",
        totp_pending_jti_key_prefix="pending:",
    )

    rate_limit_config = preset.build_rate_limit_config(
        options=RedisAuthRateLimitConfigOptions(disabled=AUTH_RATE_LIMIT_VERIFICATION_SLOT_IDENTIFIERS),
    )
    used_tokens_store = preset.build_totp_used_tokens_store()
    pending_jti_store = preset.build_totp_pending_jti_store()
    enrollment_store = preset.build_totp_enrollment_store()
    totp_config = TotpConfig(
        totp_pending_secret="2b101e06ab63b75e08f84e82a86e5d1d5f6bd92b8645ed3769a10b867bc10f44",
        totp_pending_jti_store=pending_jti_store,
        totp_used_tokens_store=used_tokens_store,
        totp_enrollment_store=enrollment_store,
    )

    assert rate_limit_config.login is not None
    assert rate_limit_config.login.backend.__class__ is ratelimit_module.RedisRateLimiter
    assert rate_limit_config.login.backend.redis is redis_client
    assert rate_limit_config.login.backend.max_attempts == SHARED_MAX_ATTEMPTS
    assert rate_limit_config.login.backend.window_seconds == SHARED_WINDOW_SECONDS
    assert rate_limit_config.refresh is not None
    assert rate_limit_config.refresh.backend.__class__ is ratelimit_module.RedisRateLimiter
    assert rate_limit_config.refresh.backend.redis is redis_client
    assert rate_limit_config.refresh.backend.max_attempts == REFRESH_MAX_ATTEMPTS
    assert rate_limit_config.refresh.backend.window_seconds == REFRESH_WINDOW_SECONDS
    assert rate_limit_config.totp_verify is not None
    assert rate_limit_config.totp_verify.backend.__class__ is ratelimit_module.RedisRateLimiter
    assert rate_limit_config.totp_verify.backend.key_prefix == "totp:"
    assert rate_limit_config.verify_token is None
    assert rate_limit_config.request_verify_token is None
    assert totp_config.totp_pending_jti_store is pending_jti_store
    assert totp_config.totp_used_tokens_store is used_tokens_store
    assert totp_config.totp_enrollment_store is enrollment_store
    assert used_tokens_store._redis is redis_client
    assert pending_jti_store.redis is redis_client
    assert enrollment_store._redis is redis_client
    assert (await used_tokens_store.mark_used("user-1", 7, 60.0)).stored is True
    await pending_jti_store.deny("pending-jti", ttl_seconds=ONE_MINUTE_TTL_SECONDS)
    assert await pending_jti_store.is_denied("pending-jti") is True
    assert await async_fakeredis.get("used:user-1:7") == b"1"
    assert await async_fakeredis.get("pending:pending-jti") == b"1"
    assert 0 < await async_fakeredis.pttl("used:user-1:7") <= ONE_MINUTE_TTL_MS
    assert ONE_MINUTE_TTL_FLOOR <= await async_fakeredis.ttl("pending:pending-jti") <= ONE_MINUTE_TTL_SECONDS


def test_exception_hierarchy_stays_on_canonical_module() -> None:
    """Exception subclasses stay on ``litestar_auth.exceptions`` while the root exports the base type."""
    assert issubclass(AuthenticationError, LitestarAuthError)
    assert issubclass(AuthorizationError, LitestarAuthError)
    assert issubclass(ConfigurationError, LitestarAuthError)
    assert issubclass(OAuthAccountAlreadyLinkedError, AuthenticationError)
    assert issubclass(OAuthAccountAlreadyLinkedError, LitestarAuthError)
    assert issubclass(TokenError, LitestarAuthError)
    assert issubclass(UserAlreadyExistsError, AuthenticationError)
    assert issubclass(UserNotExistsError, AuthenticationError)
    assert issubclass(InvalidPasswordError, AuthenticationError)
    assert issubclass(InvalidVerifyTokenError, TokenError)
    assert issubclass(InvalidResetPasswordTokenError, TokenError)
    assert not hasattr(litestar_auth, "AuthenticationError")
    assert not hasattr(litestar_auth, "TokenError")


def test_root_package_does_not_reexport_secondary_surfaces() -> None:
    """Secondary APIs stay on canonical submodules instead of the package root."""
    for symbol in REMOVED_ROOT_SECONDARY_EXPORTS:
        assert not hasattr(litestar_auth, symbol)

    assert AccessToken is not None
    assert RefreshToken is not None
    assert PasswordHelper is not None
    assert Transport is not None
    assert Strategy is not None
    assert DbSessionDependencyKey is not None
    assert DatabaseTokenStrategy is not None
    assert DatabaseTokenStrategyConfig is not None
    assert RedisTokenStrategy is not None
    assert RedisTokenStrategyConfig is not None
    assert ContribRedisTokenStrategyConfig is not None
    assert InMemoryRateLimiter is not None
    assert RedisRateLimiter is not None
    assert EndpointRateLimit is not None
    assert AuthRateLimitConfig is not None
    assert InMemoryTotpEnrollmentStore is not None
    assert InMemoryUsedTotpCodeStore is not None
    assert RedisTotpEnrollmentStore is not None
    assert RedisUsedTotpCodeStore is not None
    assert BaseUserStore is not None
    assert SQLAlchemyOrganizationStore is not None
    assert SQLAlchemyUserDatabase is not None
    assert UserRead.__struct_fields__ == ("id", "email", "is_active", "is_verified", "roles")
    assert UserCreate.__struct_fields__ == ("email", "password")
    assert AdminUserUpdate.__struct_fields__ == (
        "password",
        "email",
        "is_active",
        "is_verified",
        "roles",
        "current_password",
        "totp_code",
    )
    assert ChangePasswordRequest.__struct_fields__ == ("current_password", "new_password")
    assert UserUpdate.__struct_fields__ == ("email", "current_password", "totp_code")
    assert callable(create_provider_oauth_controller)
    assert callable(create_oauth_associate_controller)
    assert callable(load_httpx_oauth_client)
    assert callable(require_password_length)
    assert callable(generate_totp_secret)
    assert callable(generate_totp_uri)
    assert callable(verify_totp)
    assert callable(verify_totp_with_store)


def test_root_package_all_entries_resolve_to_attributes() -> None:
    """Each declared public export resolves from the package root."""
    for symbol in __all__:
        assert hasattr(litestar_auth, symbol)
        assert getattr(litestar_auth, symbol) is not None


def test_root_package_does_not_export_compat_aliases() -> None:
    """Backward-compat root aliases were removed; import from ``litestar_auth.plugin`` or ``litestar_auth.db``."""
    assert "AuthPlugin" not in __all__
    assert "BaseUserDatabase" not in __all__
    assert not hasattr(litestar_auth, "AuthPlugin")
    assert not hasattr(litestar_auth, "BaseUserDatabase")


def test_root_package_installs_null_handler() -> None:
    """The package root configures a NullHandler for library-safe logging."""
    assert any(
        isinstance(handler, logging.NullHandler) for handler in logging.getLogger(litestar_auth.__name__).handlers
    )
