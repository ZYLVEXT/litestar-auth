"""Tests for the public plugin extension contract."""

from __future__ import annotations

import inspect
import logging
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID, uuid4

import pytest
from litestar import Litestar
from litestar.config.app import AppConfig
from litestar.openapi.config import OpenAPIConfig
from litestar.openapi.spec import Components, SecurityScheme
from litestar.testing import AsyncTestClient

import litestar_auth
import litestar_auth._optional_deps as optional_deps_module
import litestar_auth._plugin.extensions._discovery as extension_discovery_module
import litestar_auth._plugin.extensions._registry as extension_registry_module
import litestar_auth._plugin.totp_controller as totp_controller_package
import litestar_auth.controllers.api_keys as api_keys_controllers_module
import litestar_auth.extensions as public_extensions
from litestar_auth._plugin.api_key_controller._extension import _ApiKeyExtension
from litestar_auth._plugin.extensions import (
    EXTENSION_API_VERSION,
    EXTENSION_ENTRY_POINT_GROUP,
    AuthCliExtension,
    AuthEventSubscriberExtension,
    AuthExtension,
    AuthExtensionRegistrationContext,
    AuthExtensionValidationContext,
    ExtensionDependencyContribution,
    ExtensionRegistrationContext,
    ExtensionValidationContext,
    build_extension_registration_context,
    build_extension_validation_context,
    register_extension_openapi_security,
    register_extensions,
    validate_extensions,
)
from litestar_auth._plugin.features import (
    ApiKeyConfig,
    OAuthConfig,
    OrganizationConfig,
    TotpConfig,
    TotpStepUpPolicyMode,
)
from litestar_auth._plugin.organization_cli import _OrganizationCliExtension
from litestar_auth._plugin.totp_controller._extension import _TotpExtension
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.config import OAuthProviderConfig
from litestar_auth.contrib.organization_admin import (
    OrganizationAdminControllerConfig,
    OrganizationAdminExtension,
    OrganizationInvitationControllerConfig,
    create_organization_admin_controller,
    create_organization_invitation_controller,
)
from litestar_auth.contrib.role_admin import RoleAdminControllerConfig, create_role_admin_controller
from litestar_auth.controllers import (
    ApiKeysControllerConfig,
    AuthControllerConfig,
    OAuthAssociateControllerConfig,
    OAuthControllerConfig,
    OrganizationControllerConfig,
    RegisterControllerConfig,
    SessionDevicesControllerConfig,
    TotpControllerOptions,
    TotpUserManagerProtocol,
    UsersControllerConfig,
    backend_supports_organization_tokens,
    create_api_keys_controllers,
    create_auth_controller,
    create_oauth_associate_controller,
    create_oauth_controller,
    create_organization_controller,
    create_register_controller,
    create_reset_password_controller,
    create_session_devices_controller,
    create_totp_controller,
    create_users_controller,
    create_verify_controller,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.manager import FernetKeyringConfig, UserManagerSecurity
from litestar_auth.oauth import ProviderOAuthControllerConfig, create_provider_oauth_controller
from litestar_auth.oauth._extension import _OAuthExtension
from litestar_auth.oauth_encryption import _build_oauth_token_encryption
from litestar_auth.password import PasswordHelper
from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)
from tests.support.extensions import EventSubscriberProbeExtension

if TYPE_CHECKING:
    from types import ModuleType

    from litestar_auth.extensions import ExtensionManagerHookEvent, ExtensionManagerHookSubscriber

pytestmark = [pytest.mark.unit, pytest.mark.imports]
_REPO_ROOT = Path(__file__).resolve().parents[2]
PUBLIC_EXTENSION_EXPORTS = (
    "EXTENSION_API_VERSION",
    "EXTENSION_ENTRY_POINT_GROUP",
    "ApiKeysControllerConfig",
    "AuthBackendsDependency",
    "AuthCliExtension",
    "AuthControllerConfig",
    "AuthEventSubscriberExtension",
    "AuthExtension",
    "AuthExtensionRegistrationContext",
    "AuthExtensionValidationContext",
    "ExtensionManagerHookEvent",
    "ExtensionManagerHookSubscriber",
    "OAuthAssociateControllerConfig",
    "OAuthControllerConfig",
    "OrganizationAdminControllerConfig",
    "OrganizationControllerConfig",
    "OrganizationInvitationControllerConfig",
    "OrganizationStoreDependency",
    "ProviderOAuthControllerConfig",
    "RegisterControllerConfig",
    "ResolvedPermissionsDependency",
    "RoleAdminControllerConfig",
    "SessionDevicesControllerConfig",
    "TotpControllerOptions",
    "TotpUserManagerProtocol",
    "UserManagerDependency",
    "UsersControllerConfig",
    "backend_supports_organization_tokens",
    "create_api_keys_controllers",
    "create_auth_controller",
    "create_oauth_associate_controller",
    "create_oauth_controller",
    "create_organization_admin_controller",
    "create_organization_controller",
    "create_organization_invitation_controller",
    "create_provider_oauth_controller",
    "create_register_controller",
    "create_reset_password_controller",
    "create_role_admin_controller",
    "create_session_devices_controller",
    "create_totp_controller",
    "create_users_controller",
    "create_verify_controller",
)
VERIFICATION_SECRET = "0123456789abcdef" * 4
RESET_PASSWORD_SECRET = "fedcba9876543210" * 4
ORGANIZATION_INVITATION_SECRET = "c4b7e9a13f6d8c2059ab7e3041f8d6e2" * 2
OAUTH_FLOW_COOKIE_SECRET = "oauth-flow-cookie-secret-1234567890"
OAUTH_TOKEN_ENCRYPTION_KEY = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
ALPHA_COUNTER = 1
BETA_COUNTER = 2
VERSIONED_EXTENSION_CONTRIBUTION_COUNT = 2
HTTP_CREATED = 201
HTTP_OK = 200
LOGIN_EVENT_COUNT = 2
UPDATE_EVENT_COUNT = 2
NON_COLLIDING_OPENAPI_COMPONENT_COUNT = 3


@dataclass(frozen=True, slots=True)
class FakeExtensionEntryPoint:
    """Small entry-point stand-in for deterministic discovery tests."""

    name: str
    value: str
    target: object
    group: str = EXTENSION_ENTRY_POINT_GROUP

    def load(self) -> object:
        """Return or raise the configured entry-point target."""
        if isinstance(self.target, BaseException):
            raise self.target
        return self.target


@dataclass(frozen=True, slots=True)
class FakeSelectableEntryPoints:
    """Entry-points collection stand-in for modern importlib.metadata."""

    selected: tuple[FakeExtensionEntryPoint, ...]

    def select(self, *, group: str) -> tuple[FakeExtensionEntryPoint, ...]:
        """Return entry points for the requested group."""
        if group == EXTENSION_ENTRY_POINT_GROUP:
            return self.selected
        return ()


class ExampleExtension:
    """Concrete structural implementation used to lock the public shape."""

    name = "example"

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Accept the narrow validation context."""
        assert context is not None

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Accept the registration context."""
        assert context is not None


class NamedExtension:
    """Extension fixture with a configurable name."""

    def __init__(self, name: str, *, enabled: bool = True) -> None:
        """Store the extension name used by the guard tests."""
        self.name = name
        self.enabled = enabled

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Accept the validation context."""
        assert context is not None

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Accept the registration context."""
        assert context is not None


class OmittedEnabledExtension:
    """Extension fixture that intentionally omits the optional enabled flag."""

    name = "omitted-enabled"

    def __init__(self) -> None:
        """Track validation and registration calls."""
        self.validated = False
        self.registered = False

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Record that validation still runs when enabled is omitted."""
        assert context is not None
        self.validated = True

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Record that registration still runs when enabled is omitted."""
        assert context is not None
        self.registered = True


class VersionedContributingExtension:
    """Extension fixture that declares and contributes through the versioned API."""

    requires_api: tuple[int, int] | None

    def __init__(
        self,
        requires_api: tuple[int, int] | object = EXTENSION_API_VERSION,
        *,
        enabled: bool = True,
        name: str = "versioned",
    ) -> None:
        """Store the requested extension API version declaration."""
        self.name = name
        self.enabled = enabled
        self.requires_api = cast("Any", requires_api)
        self.validated = False
        self.registered = False

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Record that normal extension validation ran."""
        assert context.backend_names == ("primary",)
        self.validated = True

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Contribute one item to each registration bucket."""
        self.registered = True
        context.add_controller(RouteHandlerSentinel())
        context.add_dependency(self.name, "versioned_dependency", object())
        context.add_middleware(object())
        context.add_openapi_security_scheme(self.name, "versionedAuth", SecurityScheme(type="http", scheme="Bearer"))
        context.add_exception_handler(self.name, RuntimeError, object())


class OpenApiSecurityExtension:
    """Extension fixture that contributes one configurable OpenAPI security scheme."""

    def __init__(self, *, extension_name: str = "openapi", scheme_name: str = "extensionAuth") -> None:
        """Store the extension and scheme names for conflict tests."""
        self.name = extension_name
        self.scheme_name = scheme_name
        self.scheme = SecurityScheme(type="http", scheme="Bearer")
        self.registered = False

    def validate(self, context: AuthExtensionValidationContext) -> None:
        """Accept the validation context."""
        assert context is not None

    def register(self, context: AuthExtensionRegistrationContext) -> None:
        """Contribute the configured OpenAPI security scheme."""
        self.registered = True
        context.add_openapi_security_scheme(self.name, self.scheme_name, self.scheme)


class RouteHandlerSentinel:
    """Mutable object that can carry the auth-owned route marker."""


def _run_isolated(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(_REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )


def _assert_contract_exports(module: ModuleType) -> None:
    assert module.__all__ == PUBLIC_EXTENSION_EXPORTS
    assert dir(module) == sorted(PUBLIC_EXTENSION_EXPORTS)
    assert module.EXTENSION_ENTRY_POINT_GROUP == EXTENSION_ENTRY_POINT_GROUP
    assert module.AuthCliExtension is AuthCliExtension
    assert module.AuthEventSubscriberExtension is AuthEventSubscriberExtension
    assert module.AuthExtension is AuthExtension
    assert module.AuthExtensionRegistrationContext is AuthExtensionRegistrationContext
    assert module.AuthExtensionValidationContext is AuthExtensionValidationContext


def _create_invalid_factory_target() -> object:
    return object()


def _raise_factory_error() -> object:
    raise ValueError


def _minimal_config(  # noqa: PLR0913 - tests use a compact config factory with feature toggles.
    *,
    extensions: tuple[AuthExtension, ...] = (),
    auto_discover_extensions: bool = False,
    api_keys: ApiKeyConfig | None = None,
    organization_config: OrganizationConfig | None = None,
    totp_config: TotpConfig | None = None,
    unsafe_testing: bool = False,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    user_db = InMemoryUserDatabase([])
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-extension")),
    )
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("Any", assert_structural_session_factory(DummySessionMaker())),
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            organization_invitation_token_secret=ORGANIZATION_INVITATION_SECRET,
            api_key_hash_secret="1234567890abcdef" * 4,
        ),
        extensions=extensions,
        auto_discover_extensions=auto_discover_extensions,
        api_keys=ApiKeyConfig() if api_keys is None else api_keys,
        organization_config=OrganizationConfig() if organization_config is None else organization_config,
        totp_config=totp_config,
        unsafe_testing=unsafe_testing,
    )


def test_auth_extension_contract_is_importable_from_public_surfaces() -> None:
    """The extension facade exports the public authoring surface."""
    _assert_contract_exports(public_extensions)
    assert public_extensions.EXTENSION_API_VERSION == EXTENSION_API_VERSION
    assert public_extensions.EXTENSION_ENTRY_POINT_GROUP == EXTENSION_ENTRY_POINT_GROUP
    assert litestar_auth.AuthExtension is AuthExtension
    assert litestar_auth.AuthExtensionRegistrationContext is AuthExtensionRegistrationContext
    assert litestar_auth.AuthExtensionValidationContext is AuthExtensionValidationContext
    assert "AuthExtension" in litestar_auth.__all__
    assert "AuthExtensionRegistrationContext" in litestar_auth.__all__
    assert "AuthExtensionValidationContext" in litestar_auth.__all__


def test_auth_extension_public_facade_lazily_resolves_documented_helpers() -> None:
    """Extension authors can import stable controller helpers from the public facade."""
    expected_public_helpers = {
        "ApiKeysControllerConfig": ApiKeysControllerConfig,
        "AuthControllerConfig": AuthControllerConfig,
        "OAuthAssociateControllerConfig": OAuthAssociateControllerConfig,
        "OAuthControllerConfig": OAuthControllerConfig,
        "OrganizationAdminControllerConfig": OrganizationAdminControllerConfig,
        "OrganizationControllerConfig": OrganizationControllerConfig,
        "OrganizationInvitationControllerConfig": OrganizationInvitationControllerConfig,
        "ProviderOAuthControllerConfig": ProviderOAuthControllerConfig,
        "RegisterControllerConfig": RegisterControllerConfig,
        "RoleAdminControllerConfig": RoleAdminControllerConfig,
        "SessionDevicesControllerConfig": SessionDevicesControllerConfig,
        "TotpControllerOptions": TotpControllerOptions,
        "TotpUserManagerProtocol": TotpUserManagerProtocol,
        "UsersControllerConfig": UsersControllerConfig,
        "backend_supports_organization_tokens": backend_supports_organization_tokens,
        "create_api_keys_controllers": create_api_keys_controllers,
        "create_auth_controller": create_auth_controller,
        "create_oauth_associate_controller": create_oauth_associate_controller,
        "create_oauth_controller": create_oauth_controller,
        "create_organization_admin_controller": create_organization_admin_controller,
        "create_organization_controller": create_organization_controller,
        "create_organization_invitation_controller": create_organization_invitation_controller,
        "create_provider_oauth_controller": create_provider_oauth_controller,
        "create_register_controller": create_register_controller,
        "create_reset_password_controller": create_reset_password_controller,
        "create_role_admin_controller": create_role_admin_controller,
        "create_session_devices_controller": create_session_devices_controller,
        "create_totp_controller": create_totp_controller,
        "create_users_controller": create_users_controller,
        "create_verify_controller": create_verify_controller,
    }

    for name, expected in expected_public_helpers.items():
        assert getattr(public_extensions, name) is expected


def test_auth_extension_public_facade_rejects_unknown_helper() -> None:
    """The facade only exposes the documented extension-author inventory."""
    private_helper = "PrivateHelper"
    with pytest.raises(AttributeError, match=r"module 'litestar_auth\.extensions' has no attribute 'PrivateHelper'"):
        getattr(public_extensions, private_helper)


def test_auth_extension_protocol_exposes_expected_shape() -> None:
    """The public extension surface is exactly one protocol with validate/register hooks."""
    assert AuthExtension.__annotations__ == {"name": "str"}
    assert not hasattr(AuthExtension, "enabled")
    assert EXTENSION_API_VERSION == (1, 0)

    validate_signature = inspect.signature(AuthExtension.validate)
    register_signature = inspect.signature(AuthExtension.register)

    assert tuple(validate_signature.parameters) == ("self", "context")
    assert validate_signature.parameters["context"].annotation == "AuthExtensionValidationContext"
    assert validate_signature.return_annotation == "None"
    assert tuple(register_signature.parameters) == ("self", "context")
    assert register_signature.parameters["context"].annotation == "AuthExtensionRegistrationContext"
    assert register_signature.return_annotation == "None"

    extension = ExampleExtension()
    assert extension.name == "example"
    extension.validate(cast("AuthExtensionValidationContext", object()))
    extension.register(cast("AuthExtensionRegistrationContext", object()))


def test_auth_cli_extension_protocol_exposes_expected_shape() -> None:
    """The optional CLI protocol is structural and limited to CLI command registration."""
    register_cli_signature = inspect.signature(AuthCliExtension.register_cli)

    assert tuple(register_cli_signature.parameters) == ("self", "cli", "config")
    assert register_cli_signature.parameters["cli"].annotation == "Group"
    assert register_cli_signature.parameters["config"].annotation == "LitestarAuthConfig[Any, Any]"
    assert register_cli_signature.return_annotation == "None"


def test_validate_extensions_accepts_compatible_and_omitted_api_versions() -> None:
    """Extensions can omit requires_api or declare a compatible extension API version."""
    omitted_extension = NamedExtension("omitted")
    none_extension = VersionedContributingExtension(None, name="none")
    compatible_extension = VersionedContributingExtension()
    config = _minimal_config(extensions=(omitted_extension, none_extension, compatible_extension))

    validate_extensions(config)
    context = register_extensions(app_config=AppConfig(), config=config)

    assert none_extension.validated is True
    assert none_extension.registered is True
    assert compatible_extension.validated is True
    assert compatible_extension.registered is True
    assert len(context.contributions.controllers) == VERSIONED_EXTENSION_CONTRIBUTION_COUNT
    assert len(context.contributions.dependencies) == VERSIONED_EXTENSION_CONTRIBUTION_COUNT
    assert len(context.contributions.middleware) == VERSIONED_EXTENSION_CONTRIBUTION_COUNT
    assert len(context.contributions.openapi_security_schemes) == VERSIONED_EXTENSION_CONTRIBUTION_COUNT
    assert len(context.contributions.exception_handlers) == VERSIONED_EXTENSION_CONTRIBUTION_COUNT


def test_resolve_version_gated_extensions_returns_resolved_tuple_in_order() -> None:
    """The reusable version gate preserves the resolved extension tuple and order."""
    omitted_extension = NamedExtension("omitted")
    none_extension = VersionedContributingExtension(None, name="none")
    compatible_extension = VersionedContributingExtension()
    config = _minimal_config(extensions=(omitted_extension, none_extension, compatible_extension))

    extensions = extension_registry_module.resolve_version_gated_extensions(config)

    assert extensions is config.resolve_extensions()
    assert extensions == (omitted_extension, none_extension, compatible_extension)
    assert none_extension.validated is False
    assert compatible_extension.validated is False


def test_validate_extensions_rejects_incompatible_api_before_app_wiring() -> None:
    """Incompatible extension API declarations fail before any registration contribution runs."""
    extension = VersionedContributingExtension((EXTENSION_API_VERSION[0] + 1, 0))
    config = _minimal_config(extensions=(extension,))
    app_config = AppConfig(openapi_config=OpenAPIConfig(title="Extension", version="1.0.0"))
    plugin = LitestarAuth(config)

    with pytest.raises(ConfigurationError, match=r"requires extension API 2\.0, but litestar-auth provides 1\.0"):
        plugin.on_app_init(app_config)

    assert extension.validated is False
    assert extension.registered is False
    assert app_config.route_handlers == []
    assert app_config.dependencies == {}
    assert app_config.middleware == []
    assert app_config.exception_handlers == {}
    assert app_config.on_startup == []
    assert app_config.on_shutdown == []
    assert isinstance(app_config.openapi_config, OpenAPIConfig)
    assert isinstance(app_config.openapi_config.components, Components)
    assert app_config.openapi_config.components.security_schemes is None


@pytest.mark.parametrize("requires_api", [("1", 0), (1,), [1, 0], object()])
def test_validate_extensions_rejects_invalid_api_version_declarations(requires_api: object) -> None:
    """Malformed extension API declarations fail closed before extension validation."""
    extension = VersionedContributingExtension(requires_api)
    config = _minimal_config(extensions=(extension,))

    with pytest.raises(ConfigurationError, match="declares invalid requires_api"):
        validate_extensions(config)

    assert extension.validated is False


def test_resolve_version_gated_extensions_rejects_incompatible_api_with_existing_message() -> None:
    """The reusable version gate raises the existing incompatible-version error."""
    extension = VersionedContributingExtension((EXTENSION_API_VERSION[0] + 1, 0))
    config = _minimal_config(extensions=(extension,))

    with pytest.raises(ConfigurationError, match=r"requires extension API 2\.0, but litestar-auth provides 1\.0"):
        extension_registry_module.resolve_version_gated_extensions(config)

    assert extension.validated is False


def test_resolve_extensions_treats_omitted_enabled_flag_as_enabled() -> None:
    """Extensions that omit enabled remain active for validation and registration."""
    extension: AuthExtension = OmittedEnabledExtension()
    config = _minimal_config(extensions=(extension,))

    validate_extensions(config)
    register_extensions(app_config=AppConfig(), config=config)

    assert config.resolve_extensions() == (extension,)
    assert extension.validated is True
    assert extension.registered is True


def test_resolve_extensions_excludes_disabled_extensions_before_validation_or_registration() -> None:
    """Disabled extensions are absent from the resolved extension tuple and contribute nothing."""
    enabled_extension = VersionedContributingExtension(name="enabled")
    disabled_extension = VersionedContributingExtension(
        (EXTENSION_API_VERSION[0] + 1, 0),
        enabled=False,
        name="disabled",
    )
    config = _minimal_config(extensions=(enabled_extension, disabled_extension))

    validate_extensions(config)
    context = register_extensions(app_config=AppConfig(), config=config)

    assert config.resolve_extensions() == (enabled_extension,)
    assert enabled_extension.validated is True
    assert enabled_extension.registered is True
    assert disabled_extension.validated is False
    assert disabled_extension.registered is False
    assert len(context.contributions.controllers) == 1
    assert len(context.contributions.dependencies) == 1
    assert len(context.contributions.middleware) == 1
    assert len(context.contributions.openapi_security_schemes) == 1
    assert len(context.contributions.exception_handlers) == 1


def test_resolve_extensions_default_skips_entry_point_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Entry-point discovery is opt-in and not touched by default extension resolution."""

    def fail_entry_points() -> object:
        pytest.fail("entry-point discovery must not run when auto_discover_extensions is False")

    monkeypatch.setattr(extension_discovery_module.metadata, "entry_points", fail_entry_points)
    config = _minimal_config()

    assert config.auto_discover_extensions is False
    assert config.resolve_extensions() == ()


def test_auto_discover_extensions_appends_entry_points_in_deterministic_order(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovered extensions are sorted by entry-point name after explicit and internal extensions."""
    alpha = NamedExtension("alpha")
    zeta = NamedExtension("zeta")
    calls = 0

    def entry_points() -> FakeSelectableEntryPoints:
        nonlocal calls
        calls += 1
        return FakeSelectableEntryPoints(
            selected=(
                FakeExtensionEntryPoint("zeta", "example:zeta", zeta),
                FakeExtensionEntryPoint("alpha", "example:alpha", lambda: alpha),
            ),
        )

    monkeypatch.setattr(extension_discovery_module.metadata, "entry_points", entry_points)
    caplog.set_level(logging.INFO, logger=extension_discovery_module.__name__)
    explicit = NamedExtension("explicit")
    config = _minimal_config(
        extensions=(explicit,),
        auto_discover_extensions=True,
        api_keys=ApiKeyConfig(enabled=True, allowed_scopes=("read",)),
    )

    extensions = config.resolve_extensions()

    assert calls == 1
    assert config.resolve_extensions() is extensions
    assert tuple(extension.name for extension in extensions) == ("explicit", "api_keys", "alpha", "zeta")
    assert extensions[2:] == (alpha, zeta)
    assert [record.getMessage() for record in caplog.records if record.name == extension_discovery_module.__name__] == [
        f"Loaded auth extension entry point {EXTENSION_ENTRY_POINT_GROUP}:alpha=example:alpha.",
        f"Loaded auth extension entry point {EXTENSION_ENTRY_POINT_GROUP}:zeta=example:zeta.",
    ]


def test_auto_discover_extensions_supports_modern_selectable_entry_points(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovery supports the current importlib.metadata selectable entry-points API."""
    extension = NamedExtension("selectable")

    def entry_points() -> FakeSelectableEntryPoints:
        return FakeSelectableEntryPoints(
            selected=(FakeExtensionEntryPoint("selectable", "example:selectable", extension),),
        )

    monkeypatch.setattr(extension_discovery_module.metadata, "entry_points", entry_points)
    config = _minimal_config(auto_discover_extensions=True)

    assert config.resolve_extensions() == (extension,)


def test_discovered_extensions_are_filtered_before_version_gate_and_registration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovered disabled extensions use the same enabled filter as configured extensions."""
    enabled_extension = VersionedContributingExtension(name="discovered-enabled")
    disabled_extension = VersionedContributingExtension(
        (EXTENSION_API_VERSION[0] + 1, 0),
        enabled=False,
        name="discovered-disabled",
    )

    def entry_points() -> FakeSelectableEntryPoints:
        return FakeSelectableEntryPoints(
            selected=(
                FakeExtensionEntryPoint("disabled", "example:disabled", disabled_extension),
                FakeExtensionEntryPoint("enabled", "example:enabled", enabled_extension),
            ),
        )

    monkeypatch.setattr(extension_discovery_module.metadata, "entry_points", entry_points)
    config = _minimal_config(auto_discover_extensions=True)

    validate_extensions(config)
    context = register_extensions(app_config=AppConfig(), config=config)

    assert config.resolve_extensions() == (enabled_extension,)
    assert enabled_extension.validated is True
    assert enabled_extension.registered is True
    assert disabled_extension.validated is False
    assert disabled_extension.registered is False
    assert len(context.contributions.controllers) == 1


def test_discovered_incompatible_extension_fails_through_version_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovered extensions do not bypass the extension API compatibility gate."""
    extension = VersionedContributingExtension((EXTENSION_API_VERSION[0] + 1, 0), name="discovered")

    def entry_points() -> FakeSelectableEntryPoints:
        return FakeSelectableEntryPoints(
            selected=(FakeExtensionEntryPoint("discovered", "example:discovered", extension),),
        )

    monkeypatch.setattr(extension_discovery_module.metadata, "entry_points", entry_points)
    config = _minimal_config(auto_discover_extensions=True)

    with pytest.raises(ConfigurationError, match=r"requires extension API 2\.0, but litestar-auth provides 1\.0"):
        validate_extensions(config)

    assert extension.validated is False


def test_discovered_duplicate_extension_name_fails_unique_name_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovered extensions share the same duplicate-name guard as explicit extensions."""

    def entry_points() -> FakeSelectableEntryPoints:
        return FakeSelectableEntryPoints(
            selected=(FakeExtensionEntryPoint("duplicate", "example:duplicate", NamedExtension("alpha")),),
        )

    monkeypatch.setattr(extension_discovery_module.metadata, "entry_points", entry_points)
    config = _minimal_config(extensions=(NamedExtension("alpha"),), auto_discover_extensions=True)

    with pytest.raises(ValueError, match="Duplicate auth extension names are not allowed: alpha"):
        build_extension_validation_context(config)


@pytest.mark.parametrize(
    ("entry_point", "match"),
    [
        (
            FakeExtensionEntryPoint("broken", "example:broken", RuntimeError("boom")),
            "Failed to load auth extension entry point",
        ),
        (
            FakeExtensionEntryPoint("invalid", "example:invalid", object()),
            "did not load a valid AuthExtension",
        ),
        (
            FakeExtensionEntryPoint("factory-broken", "example:factory_broken", _raise_factory_error),
            "Failed to instantiate auth extension entry point",
        ),
        (
            FakeExtensionEntryPoint("factory-invalid", "example:factory_invalid", _create_invalid_factory_target),
            "did not create a valid AuthExtension",
        ),
    ],
)
def test_discovered_malformed_entry_points_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    entry_point: FakeExtensionEntryPoint,
    match: str,
) -> None:
    """Malformed entry points raise ConfigurationError instead of being ignored."""

    def entry_points() -> FakeSelectableEntryPoints:
        return FakeSelectableEntryPoints(selected=(entry_point,))

    monkeypatch.setattr(extension_discovery_module.metadata, "entry_points", entry_points)
    config = _minimal_config(auto_discover_extensions=True)

    with pytest.raises(ConfigurationError, match=match):
        config.resolve_extensions()


@pytest.mark.parametrize(
    "case_name",
    ["none", "user", "oauth", "totp", "api_keys", "organization_admin", "disabled"],
)
def test_resolve_extensions_memoizes_enabled_extension_tuple(case_name: str) -> None:
    """Extension resolution returns the same enabled tuple after first computation."""
    match case_name:
        case "none":
            config = _minimal_config()
            expected_names = ()
        case "user":
            config = _minimal_config(extensions=(NamedExtension("user"),))
            expected_names = ("user",)
        case "oauth":
            config = _minimal_config()
            config.oauth_config = OAuthConfig(
                oauth_providers=[OAuthProviderConfig(name="github", client=object())],
                oauth_redirect_base_url="https://app.example.com/auth",
                oauth_token_encryption_key=OAUTH_TOKEN_ENCRYPTION_KEY,
                oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
            )
            expected_names = ("oauth",)
        case "totp":
            config = _minimal_config(totp_config=TotpConfig(totp_pending_secret="76543210fedcba98" * 4))
            expected_names = ("totp",)
        case "api_keys":
            config = _minimal_config(api_keys=ApiKeyConfig(enabled=True, allowed_scopes=("read",)))
            expected_names = ("api_keys",)
        case "organization_admin":
            config = _minimal_config(
                organization_config=OrganizationConfig(
                    enabled=True,
                    store_factory=cast("Any", lambda _session: object()),
                    include_organization_admin=True,
                    include_organization_invitations=True,
                ),
            )
            expected_names = ("organization_cli", "organization_admin")
        case "disabled":
            config = _minimal_config(
                extensions=(NamedExtension("enabled"), NamedExtension("disabled", enabled=False)),
            )
            expected_names = ("enabled",)
        case _:
            pytest.fail(f"Unhandled extension resolution case: {case_name}")

    extensions = config.resolve_extensions()

    assert config.resolve_extensions() is extensions
    assert tuple(extension.name for extension in extensions) == expected_names


def test_extension_context_protocols_expose_public_capability_surface() -> None:
    """Context interfaces expose the capabilities needed by extension authors."""
    validation_members = set(AuthExtensionValidationContext.__dict__)
    registration_members = set(AuthExtensionRegistrationContext.__dict__)
    assert validation_members >= {
        "backend_names",
        "config",
        "feature_registry",
        "organization_enabled",
        "require_cryptography_fernet",
        "require_redis_asyncio",
        "resolved_defaults",
        "security_requirements",
        "startup_backend_inventory",
        "startup_backends",
        "unsafe_testing",
        "user_manager_class",
        "user_manager_factory",
        "user_model",
        "validate_production_secret",
    }
    assert "app_config" not in AuthExtensionValidationContext.__dict__
    assert registration_members >= {
        "add_controller",
        "add_dependency",
        "add_exception_handler",
        "add_middleware",
        "add_openapi_security_scheme",
        "add_shutdown_hook",
        "add_startup_hook",
        "app_config",
        "dependency_keys",
        "get_local_state",
        "is_auth_route_handler",
        "mark_auth_route_handler",
        "set_local_state",
        "state_for_extension",
    }
    assert AuthExtensionRegistrationContext.__mro__[1] is AuthExtensionValidationContext

    config_signature = inspect.signature(AuthExtensionValidationContext.config.fget)
    feature_registry_signature = inspect.signature(AuthExtensionValidationContext.feature_registry.fget)
    app_config_signature = inspect.signature(AuthExtensionRegistrationContext.app_config.fget)
    add_dependency_signature = inspect.signature(AuthExtensionRegistrationContext.add_dependency)
    security_scheme_signature = inspect.signature(AuthExtensionRegistrationContext.add_openapi_security_scheme)

    assert config_signature.return_annotation == "LitestarAuthConfig[Any, Any]"
    assert feature_registry_signature.return_annotation == "FeatureRegistry[Any, Any]"
    assert app_config_signature.return_annotation == "AppConfig"
    assert add_dependency_signature.parameters["allow_override"].default is False
    assert security_scheme_signature.parameters["scheme"].annotation == "SecurityScheme"


def test_extension_contract_import_does_not_load_heavy_runtime_modules() -> None:
    """The contract module keeps ORM, SQLAlchemy, and concrete feature modules out of import time."""
    proc = _run_isolated(
        "import sys\n"
        "blocked = {\n"
        "    'litestar_auth.models',\n"
        "    'litestar_auth.db.sqlalchemy',\n"
        "    'litestar_auth._plugin.controllers',\n"
        "    'litestar_auth._plugin.database_token',\n"
        "    'litestar_auth._plugin.totp_controller',\n"
        "    'litestar_auth._plugin.oauth_contract',\n"
        "}\n"
        "import litestar_auth._plugin\n"
        "baseline = blocked.intersection(sys.modules)\n"
        "import litestar_auth._plugin.extensions._contracts\n"
        "loaded = blocked.intersection(sys.modules) - baseline\n"
        "assert not loaded, sorted(loaded)\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_extension_public_facade_import_does_not_load_heavy_runtime_modules() -> None:
    """Importing the public facade does not resolve lazy controller or optional-feature modules."""
    proc = _run_isolated(
        "import sys\n"
        "blocked = {\n"
        "    'litestar_auth.models',\n"
        "    'litestar_auth.db.sqlalchemy',\n"
        "    'litestar_auth.contrib.role_admin._controller',\n"
        "    'litestar_auth.contrib.organization_admin._controller',\n"
        "    'litestar_auth.controllers.api_keys',\n"
        "    'litestar_auth.controllers.oauth',\n"
        "    'litestar_auth.controllers.totp',\n"
        "    'litestar_auth.oauth.router',\n"
        "    'litestar_auth._plugin.totp_controller',\n"
        "    'redis.asyncio',\n"
        "    'httpx_oauth',\n"
        "    'cryptography.fernet',\n"
        "}\n"
        "baseline = blocked.intersection(sys.modules)\n"
        "import litestar_auth.extensions\n"
        "loaded = blocked.intersection(sys.modules) - baseline\n"
        "assert not loaded, sorted(loaded)\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_external_style_extension_uses_public_facade_without_private_plugin_imports() -> None:
    """A sample extension can validate/register using only the public authoring facade."""
    proc = _run_isolated(
        "import builtins\n"
        "import sys\n"
        "from typing import Any, cast\n"
        "import litestar_auth.extensions\n"
        "real_import = builtins.__import__\n"
        "def guarded_import(name: str, *args: object, **kwargs: object) -> object:\n"
        "    if name == 'litestar_auth._plugin' or name.startswith('litestar_auth._plugin.'):\n"
        "        raise AssertionError(f'external extension imported private module: {name}')\n"
        "    return real_import(name, *args, **kwargs)\n"
        "sample_namespace: dict[str, object] = {}\n"
        "sample_source = '''\\\n"
        "from litestar_auth.extensions import (\\n"
        "    AuthExtension,\\n"
        "    AuthExtensionRegistrationContext,\\n"
        "    AuthExtensionValidationContext,\\n"
        ")\\n"
        "\\n"
        "class PublicFacadeExtension:\\n"
        "    name = 'public_facade_sample'\\n"
        "    validated_backend_names = ()\\n"
        "    registered_local_state = None\\n"
        "\\n"
        "    def validate(self, context: AuthExtensionValidationContext) -> None:\\n"
        "        self.validated_backend_names = context.backend_names\\n"
        "\\n"
        "    def register(self, context: AuthExtensionRegistrationContext) -> None:\\n"
        "        context.set_local_state(self.name, 'registered', True)\\n"
        "        self.registered_local_state = context.get_local_state(self.name, 'registered')\\n"
        "\\n"
        "extension: AuthExtension = PublicFacadeExtension()\\n"
        "'''\n"
        "builtins.__import__ = guarded_import\n"
        "try:\n"
        "    exec(sample_source, sample_namespace)\n"
        "finally:\n"
        "    builtins.__import__ = real_import\n"
        "from litestar.config.app import AppConfig\n"
        "from litestar_auth.authentication.backend import AuthenticationBackend\n"
        "from litestar_auth.authentication.strategy.base import Strategy\n"
        "from litestar_auth.authentication.transport.bearer import BearerTransport\n"
        "from litestar_auth.plugin import LitestarAuth, LitestarAuthConfig\n"
        "class UserModel:\n"
        "    email = 'user@example.com'\n"
        "    roles = []\n"
        "class DummySessionMaker:\n"
        "    def __call__(self) -> object:\n"
        "        return object()\n"
        "class StaticStrategy(Strategy[UserModel, int]):\n"
        "    async def read_token(self, token: str | None, user_manager: object) -> UserModel | None:\n"
        "        return None\n"
        "    async def write_token(self, user: UserModel) -> str:\n"
        "        return 'token'\n"
        "    async def destroy_token(self, token: str, user: UserModel) -> None:\n"
        "        return None\n"
        "def user_manager_factory(**kwargs: object) -> object:\n"
        "    return object()\n"
        "extension = sample_namespace['extension']\n"
        "backend = AuthenticationBackend(\n"
        "    name='primary',\n"
        "    transport=BearerTransport(),\n"
        "    strategy=StaticStrategy(),\n"
        ")\n"
        "config = LitestarAuthConfig(\n"
        "    backends=[backend],\n"
        "    user_model=UserModel,\n"
        "    user_manager_factory=cast(Any, user_manager_factory),\n"
        "    session_maker=cast(Any, DummySessionMaker()),\n"
        "    extensions=(extension,),\n"
        "    include_register=False,\n"
        "    include_verify=False,\n"
        "    include_reset_password=False,\n"
        "    include_openapi_security=False,\n"
        ")\n"
        "plugin = LitestarAuth(config)\n"
        "plugin.on_app_init(AppConfig())\n"
        "assert extension.validated_backend_names == ('primary',)\n"
        "assert extension.registered_local_state is True\n"
        "assert not {\n"
        "    name\n"
        "    for name in sys.modules\n"
        "    if name == 'litestar_auth.models'\n"
        "    or name.startswith('litestar_auth.models.')\n"
        "    or name == 'litestar_auth.db.sqlalchemy'\n"
        "    or name.startswith('litestar_auth.db.sqlalchemy.')\n"
        "}\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_extension_validation_context_exposes_canonical_config_state() -> None:
    """Validation context surfaces canonical config, defaults, registry, backend, and secret helpers."""
    config = _minimal_config(unsafe_testing=True)
    context = build_extension_validation_context(config)

    assert isinstance(context, ExtensionValidationContext)
    assert context.config is config
    assert context.feature_registry is config.resolve_feature_registry()
    assert context.resolved_defaults == config.resolve_defaults()
    assert context.user_model is ExampleUser
    assert context.user_manager_class is PluginUserManager
    assert context.user_manager_factory is None
    assert context.manager_construction_mode == "class"
    assert context.startup_backend_inventory is config.resolve_feature_registry().backend_inventory
    assert context.startup_backends == config.resolve_startup_backends()
    assert context.backend_names == ("primary",)
    assert context.security_requirements == [{"primary": []}]
    assert context.organization_enabled is False
    assert context.organization_config is config.organization_config
    assert context.organization_model is None
    assert context.tenant_resolver is None
    assert context.unsafe_testing is True
    context.validate_production_secret("weak", label="extension_secret")


def test_extension_validation_context_exposes_optional_dependency_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validation context optional-dependency helpers delegate to canonical loaders."""
    imported: list[tuple[str, object]] = []
    sentinel = object()

    def import_module(name: str) -> object:
        imported.append((name, sentinel))
        return sentinel

    monkeypatch.setattr(optional_deps_module.importlib, "import_module", import_module)
    context = build_extension_validation_context(_minimal_config())

    assert context.require_redis_asyncio(feature_name="extension redis") is sentinel
    assert context.require_cryptography_fernet(install_hint="install cryptography") is sentinel
    assert imported == [("redis.asyncio", sentinel), ("cryptography.fernet", sentinel)]


def test_extension_validation_context_rejects_duplicate_extension_names() -> None:
    """Duplicate extension names fail closed before extension validation runs."""
    config = _minimal_config(extensions=(NamedExtension("alpha"), NamedExtension("alpha")))

    with pytest.raises(ValueError, match="Duplicate auth extension names are not allowed: alpha"):
        build_extension_validation_context(config)


def test_extension_registration_context_rejects_duplicate_extension_names() -> None:
    """Registration context construction uses the same extension-name guard."""
    config = _minimal_config(extensions=(NamedExtension("alpha"), NamedExtension("beta"), NamedExtension("beta")))

    with pytest.raises(ValueError, match="Duplicate auth extension names are not allowed: beta"):
        build_extension_registration_context(app_config=AppConfig(), config=config)


def test_oauth_config_is_normalized_to_internal_extension() -> None:
    """Configured OAuth providers contribute the internal OAuth extension."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[OAuthProviderConfig(name="github", client=object())],
        oauth_redirect_base_url="https://app.example.com/auth",
        oauth_token_encryption_key=OAUTH_TOKEN_ENCRYPTION_KEY,
        oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
    )

    extensions = config.resolve_extensions()

    assert config.extensions == ()
    assert tuple(extension.name for extension in extensions) == ("oauth",)


def test_totp_config_is_normalized_to_internal_extension() -> None:
    """Configured TOTP contributes the internal TOTP extension."""
    config = _minimal_config(totp_config=TotpConfig(totp_pending_secret="76543210fedcba98" * 4))

    extensions = config.resolve_extensions()

    assert config.extensions == ()
    assert tuple(extension.name for extension in extensions) == ("totp",)


def test_api_key_config_is_normalized_to_internal_extension() -> None:
    """Enabled API-key management contributes the internal API-key extension."""
    config = _minimal_config(api_keys=ApiKeyConfig(enabled=True, allowed_scopes=("read",)))

    extensions = config.resolve_extensions()

    assert config.extensions == ()
    assert tuple(extension.name for extension in extensions) == ("api_keys",)


def test_config_internal_extensions_resolve_in_existing_descriptor_order() -> None:
    """All config-derived internal extensions retain their established order and constructor state."""
    explicit = NamedExtension("explicit")
    config = _minimal_config(
        extensions=(explicit,),
        api_keys=ApiKeyConfig(enabled=True, allowed_scopes=("read",)),
        organization_config=OrganizationConfig(
            enabled=True,
            store_factory=cast("Any", lambda _session: object()),
            include_organization_admin=True,
            include_organization_invitations=True,
        ),
        totp_config=TotpConfig(totp_pending_secret="76543210fedcba98" * 4),
    )
    config.oauth_config = OAuthConfig(
        oauth_providers=[OAuthProviderConfig(name="github", client=object())],
        oauth_redirect_base_url="https://app.example.com/auth",
        oauth_token_encryption_key=OAUTH_TOKEN_ENCRYPTION_KEY,
        oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
    )

    extensions = config.resolve_extensions()

    assert extensions[0] is explicit
    assert tuple(extension.name for extension in extensions) == (
        "explicit",
        "oauth",
        "totp",
        "api_keys",
        "organization_cli",
        "organization_admin",
    )
    assert isinstance(extensions[1], _OAuthExtension)
    assert isinstance(extensions[2], _TotpExtension)
    assert isinstance(extensions[3], _ApiKeyExtension)
    assert isinstance(extensions[4], _OrganizationCliExtension)
    organization_admin = extensions[5]
    assert isinstance(organization_admin, OrganizationAdminExtension)
    assert organization_admin.include_invitations is True
    assert organization_admin._include_admin_controller is True
    assert organization_admin._mark_auth_owned is False
    assert organization_admin._use_plugin_openapi_security is True


@pytest.mark.parametrize(
    ("include_admin", "include_invitations", "expected_names"),
    [
        (1, 0, ("organization_cli", "organization_admin")),
        (0, 1, ("organization_admin",)),
        (1, 1, ("organization_cli", "organization_admin")),
    ],
)
def test_organization_flags_resolve_internal_extension_constructor_params(
    include_admin: int,
    include_invitations: int,
    expected_names: tuple[str, ...],
) -> None:
    """Organization flags keep the existing CLI trigger and admin/invitation constructor mapping."""
    admin_enabled = bool(include_admin)
    invitations_enabled = bool(include_invitations)
    config = _minimal_config(
        organization_config=OrganizationConfig(
            enabled=True,
            store_factory=cast("Any", lambda _session: object()),
            include_organization_admin=admin_enabled,
            include_organization_invitations=invitations_enabled,
        ),
    )

    extensions = config.resolve_extensions()

    assert tuple(extension.name for extension in extensions) == expected_names
    organization_admin = extensions[-1]
    assert isinstance(organization_admin, OrganizationAdminExtension)
    assert organization_admin.include_invitations is invitations_enabled
    assert organization_admin._include_admin_controller is admin_enabled
    assert organization_admin._mark_auth_owned is False
    assert organization_admin._use_plugin_openapi_security is True


def test_api_key_config_rejects_explicit_duplicate_extension_name() -> None:
    """The internal API-key extension reserves the stable api_keys extension name."""
    config = _minimal_config(
        extensions=(NamedExtension("api_keys"),),
        api_keys=ApiKeyConfig(enabled=True, allowed_scopes=("read",)),
    )

    with pytest.raises(ValueError, match="Duplicate auth extension names are not allowed: api_keys"):
        build_extension_validation_context(config)


def test_api_key_extension_register_contributes_auth_owned_controllers(monkeypatch: pytest.MonkeyPatch) -> None:
    """The internal API-key extension mounts factory-marked management controllers with plugin options."""
    config = _minimal_config(api_keys=ApiKeyConfig(enabled=True, allowed_scopes=("read",), signing_enabled=True))
    config.users_path = "/members"
    config.totp_stepup_policy = {"api_keys.create": cast("TotpStepUpPolicyMode", "always")}
    context = build_extension_registration_context(app_config=AppConfig(), config=config)
    self_controller = context.mark_auth_route_handler(RouteHandlerSentinel())
    admin_controller = context.mark_auth_route_handler(RouteHandlerSentinel())
    captured: dict[str, object] = {}

    def _create_api_keys_controllers(**kwargs: object) -> list[object]:
        captured.update(kwargs)
        return [self_controller, admin_controller]

    monkeypatch.setattr(api_keys_controllers_module, "create_api_keys_controllers", _create_api_keys_controllers)

    _ApiKeyExtension().register(context)

    assert context.contributions.controllers == [self_controller, admin_controller]
    assert context.is_auth_route_handler(self_controller) is True
    assert context.is_auth_route_handler(admin_controller) is True
    assert captured == {
        "id_parser": config.id_parser,
        "rate_limit_config": config.rate_limit_config,
        "security": context.security_requirements,
        "users_path": "/members",
        "require_step_up_on_create": True,
        "signing_enabled": True,
        "totp_stepup_policy": {"api_keys.create": "always"},
    }


def test_totp_config_rejects_explicit_duplicate_extension_name() -> None:
    """The internal TOTP extension reserves the stable totp extension name."""
    config = _minimal_config(
        extensions=(NamedExtension("totp"),),
        totp_config=TotpConfig(totp_pending_secret="76543210fedcba98" * 4),
    )

    with pytest.raises(ValueError, match="Duplicate auth extension names are not allowed: totp"):
        build_extension_validation_context(config)


def test_totp_extension_register_contributes_non_auth_owned_controller(monkeypatch: pytest.MonkeyPatch) -> None:
    """The internal TOTP extension mounts the plugin controller without changing route ownership."""
    config = _minimal_config(totp_config=TotpConfig(totp_pending_secret="76543210fedcba98" * 4), unsafe_testing=True)
    context = build_extension_registration_context(app_config=AppConfig(), config=config)
    controller = object()
    captured: dict[str, object] = {}

    def _build_totp_controller(config_arg: object, **kwargs: object) -> object:
        captured["config"] = config_arg
        captured.update(kwargs)
        return controller

    monkeypatch.setattr(totp_controller_package, "build_totp_controller", _build_totp_controller)

    _TotpExtension().register(context)

    assert context.contributions.controllers == [controller]
    assert context.is_auth_route_handler(controller) is False
    assert captured == {
        "config": config,
        "backend_inventory": context.startup_backend_inventory,
        "security": context.security_requirements,
    }


def test_oauth_config_rejects_explicit_duplicate_extension_name() -> None:
    """The internal OAuth extension reserves the stable oauth extension name."""
    config = _minimal_config(extensions=(NamedExtension("oauth"),))
    config.oauth_config = OAuthConfig(
        oauth_providers=[OAuthProviderConfig(name="github", client=object())],
        oauth_redirect_base_url="https://app.example.com/auth",
        oauth_token_encryption_key=OAUTH_TOKEN_ENCRYPTION_KEY,
        oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
    )

    with pytest.raises(ValueError, match="Duplicate auth extension names are not allowed: oauth"):
        build_extension_validation_context(config)


def test_oauth_extension_validate_skips_configs_without_providers() -> None:
    """The internal OAuth extension stays inert without a provider inventory."""
    config = _minimal_config()
    context = build_extension_validation_context(config)

    _OAuthExtension().validate(context)


def test_oauth_token_encryption_builder_returns_none_without_oauth_config() -> None:
    """The config-derived OAuth encryption helper preserves the no-config branch."""
    config = _minimal_config()

    assert _build_oauth_token_encryption(config) is None


def test_oauth_token_encryption_builder_supports_keyring_config() -> None:
    """The internal OAuth extension rebuilds keyring-based token encryption from config."""
    config = _minimal_config()
    config.oauth_config = OAuthConfig(
        oauth_providers=[OAuthProviderConfig(name="github", client=object())],
        oauth_redirect_base_url="https://app.example.com/auth",
        oauth_token_encryption_keyring=FernetKeyringConfig(
            active_key_id="active",
            keys={"active": OAUTH_TOKEN_ENCRYPTION_KEY},
        ),
        oauth_flow_cookie_secret=OAUTH_FLOW_COOKIE_SECRET,
    )
    policy = _build_oauth_token_encryption(config)

    assert policy is not None
    assert policy.active_key_id == "active"
    policy.require_configured(context="OAuth providers are configured")


def test_extension_registration_context_exposes_org_dependency_keys_and_backend_inventory() -> None:
    """Registration context exposes plugin dependency keys and organization tenant shape."""
    organization_config = OrganizationConfig(enabled=True, store_factory=cast("Any", lambda _session: object()))
    config = _minimal_config(organization_config=organization_config)
    app_config = AppConfig()

    context = build_extension_registration_context(app_config=app_config, config=config)

    assert isinstance(context, ExtensionRegistrationContext)
    assert context.app_config is app_config
    assert context.dependency_keys.user_manager == "litestar_auth_user_manager"
    assert context.dependency_keys.session == "db_session"
    assert context.dependency_keys.current_organization == "litestar_auth_current_organization"
    assert context.dependency_keys.organization_store == "litestar_auth_organization_store"
    assert context.organization_enabled is True
    assert context.tenant_resolver is organization_config.tenant_resolver
    assert context.startup_backend_inventory is config.resolve_feature_registry().backend_inventory


def test_extension_registration_helpers_accumulate_contributions_without_mutating_app_config() -> None:
    """Registration helpers collect extension contributions for later controlled wiring."""
    context = build_extension_registration_context(app_config=AppConfig(), config=_minimal_config())
    controller = object()
    provider = object()
    middleware = object()
    exception_handler = object()
    scheme = SecurityScheme(type="http", scheme="Bearer")

    def startup_hook() -> None:
        return None

    def shutdown_hook() -> None:
        return None

    context.add_controller(controller)
    context.add_dependency("alpha", "alpha_dependency", provider)
    context.add_middleware(middleware)
    context.add_openapi_security_scheme("alpha", "alphaAuth", scheme)
    context.add_startup_hook(startup_hook)
    context.add_shutdown_hook(shutdown_hook)
    context.add_exception_handler("alpha", ValueError, exception_handler)

    assert context.app_config.route_handlers == []
    assert context.app_config.dependencies == {}
    assert context.app_config.middleware == []
    assert context.app_config.on_startup == []
    assert context.app_config.on_shutdown == []
    assert context.app_config.exception_handlers == {}
    assert context.contributions.controllers == [controller]
    assert context.contributions.dependencies == [
        ExtensionDependencyContribution(
            extension_name="alpha",
            key="alpha_dependency",
            provider=provider,
            allow_override=False,
        ),
    ]
    assert context.contributions.middleware == [middleware]
    assert context.contributions.openapi_security_schemes[0].name == "alphaAuth"
    assert context.contributions.openapi_security_schemes[0].scheme is scheme
    assert context.contributions.startup_hooks == [startup_hook]
    assert context.contributions.shutdown_hooks == [shutdown_hook]
    assert context.contributions.exception_handlers[0].handler is exception_handler


def test_extension_openapi_security_registration_appends_to_component_lists() -> None:
    """Extension OpenAPI scheme wiring preserves existing component-list configs."""
    context = build_extension_registration_context(app_config=AppConfig(), config=_minimal_config())
    scheme = SecurityScheme(type="http", scheme="Bearer")
    app_config = AppConfig(openapi_config=OpenAPIConfig(title="Extension", version="1.0.0", components=[]))

    context.add_openapi_security_scheme("alpha", "alphaAuth", scheme)

    result = register_extension_openapi_security(app_config, contributions=context.contributions)

    assert result == {"alphaAuth": scheme}
    assert isinstance(app_config.openapi_config, OpenAPIConfig)
    assert isinstance(app_config.openapi_config.components, list)
    assert cast("Components", app_config.openapi_config.components[0]).security_schemes == {"alphaAuth": scheme}


def test_extension_openapi_security_registration_preserves_existing_component_object() -> None:
    """Extension OpenAPI scheme wiring preserves an existing singleton Components config."""
    context = build_extension_registration_context(app_config=AppConfig(), config=_minimal_config())
    scheme = SecurityScheme(type="http", scheme="Bearer")
    app_config = AppConfig(openapi_config=OpenAPIConfig(title="Extension", version="1.0.0"))
    assert app_config.openapi_config is not None
    original_components = app_config.openapi_config.components

    context.add_openapi_security_scheme("alpha", "alphaAuth", scheme)

    register_extension_openapi_security(app_config, contributions=context.contributions)

    assert isinstance(app_config.openapi_config, OpenAPIConfig)
    assert app_config.openapi_config.components == [
        Components(security_schemes=cast("Any", {"alphaAuth": scheme})),
        original_components,
    ]


def test_extension_openapi_security_registration_rejects_duplicate_scheme_names() -> None:
    """Duplicate extension OpenAPI scheme names fail closed."""
    context = build_extension_registration_context(app_config=AppConfig(), config=_minimal_config())
    scheme = SecurityScheme(type="http", scheme="Bearer")

    context.add_openapi_security_scheme("alpha", "sharedAuth", scheme)
    context.add_openapi_security_scheme("beta", "sharedAuth", scheme)

    with pytest.raises(
        ValueError,
        match="Auth extension OpenAPI security scheme 'sharedAuth' from extension 'beta' conflicts with extension",
    ):
        register_extension_openapi_security(AppConfig(), contributions=context.contributions)


def test_extension_openapi_security_registration_rejects_core_scheme_name_collision() -> None:
    """Extension OpenAPI schemes cannot reuse core auth scheme names."""
    extension = OpenApiSecurityExtension(extension_name="colliding", scheme_name="primary")
    config = _minimal_config(extensions=(cast("AuthExtension", extension),))

    with pytest.raises(
        ConfigurationError,
        match=(
            "Auth extension OpenAPI security scheme 'primary' from extension 'colliding' conflicts with a core auth "
            "security scheme"
        ),
    ):
        Litestar(plugins=[LitestarAuth(config)])

    assert extension.registered is True


def test_extension_openapi_security_registration_preserves_non_colliding_plugin_order() -> None:
    """Non-colliding extension schemes keep the existing component merge order."""
    extension = OpenApiSecurityExtension(extension_name="extension", scheme_name="extensionAuth")
    config = _minimal_config(extensions=(cast("AuthExtension", extension),))
    app_config = AppConfig(openapi_config=OpenAPIConfig(title="Extension", version="1.0.0"))
    assert app_config.openapi_config is not None
    original_components = app_config.openapi_config.components

    LitestarAuth(config).on_app_init(app_config)

    assert extension.registered is True
    assert isinstance(app_config.openapi_config, OpenAPIConfig)
    assert isinstance(app_config.openapi_config.components, list)
    components = cast("list[Components]", app_config.openapi_config.components)
    assert len(components) == NON_COLLIDING_OPENAPI_COMPONENT_COUNT
    assert list(cast("dict[str, object]", components[0].security_schemes)) == ["primary"]
    assert components[1] is original_components
    assert components[2].security_schemes == {"extensionAuth": extension.scheme}


def test_extension_registration_context_marks_auth_routes_and_namespaces_local_state() -> None:
    """Route ownership markers and local state are isolated by extension name."""
    context = build_extension_registration_context(app_config=AppConfig(), config=_minimal_config())

    def route_handler() -> None:
        return None

    assert context.is_auth_route_handler(route_handler) is False
    assert context.mark_auth_route_handler(route_handler) is route_handler
    assert context.is_auth_route_handler(route_handler) is True

    context.set_local_state("alpha", "counter", ALPHA_COUNTER)
    context.set_local_state("beta", "counter", BETA_COUNTER)
    assert context.get_local_state("alpha", "counter") == ALPHA_COUNTER
    assert context.get_local_state("beta", "counter") == BETA_COUNTER
    assert context.get_local_state("gamma", "counter", "missing") == "missing"
    assert context.state_for_extension("alpha") is context.state_for_extension("alpha")


class EventSubscriberVersionedExtension(VersionedContributingExtension):
    """Versioned extension fixture that also contributes manager hook subscribers."""

    def __init__(
        self,
        requires_api: tuple[int, int] | object = EXTENSION_API_VERSION,
        *,
        enabled: bool = True,
        name: str = "versioned-subscriber",
        events: list[ExtensionManagerHookEvent] | None = None,
    ) -> None:
        """Store event records for version-gated subscriber tests."""
        super().__init__(requires_api, enabled=enabled, name=name)
        self.events = events if events is not None else []

    def manager_hook_subscribers(self) -> tuple[ExtensionManagerHookSubscriber, ...]:
        """Return the versioned extension's manager hook subscriber."""
        return (self._record,)

    async def _record(self, event: ExtensionManagerHookEvent) -> None:
        self.events.append(event)


def test_register_extensions_collects_event_subscriber_extensions() -> None:
    """Enabled event-subscriber extensions contribute manager hook subscribers."""
    events: list[ExtensionManagerHookEvent] = []
    subscriber_extension = EventSubscriberProbeExtension(events)
    config = _minimal_config(extensions=(cast("AuthExtension", subscriber_extension),))

    context = register_extensions(app_config=AppConfig(), config=config)

    assert len(context.contributions.manager_hook_subscribers) == 1
    assert callable(context.contributions.manager_hook_subscribers[0])


def test_register_extensions_skips_disabled_event_subscriber_extensions() -> None:
    """Disabled event-subscriber extensions do not contribute manager hook subscribers."""
    events: list[ExtensionManagerHookEvent] = []
    disabled_extension = EventSubscriberProbeExtension(events, enabled=False)
    config = _minimal_config(extensions=(cast("AuthExtension", disabled_extension),))

    context = register_extensions(app_config=AppConfig(), config=config)

    assert context.contributions.manager_hook_subscribers == []


def test_plugin_skips_incompatible_event_subscriber_extensions() -> None:
    """Incompatible event-subscriber extensions fail before subscribers are wired."""
    events: list[ExtensionManagerHookEvent] = []
    extension = EventSubscriberVersionedExtension((EXTENSION_API_VERSION[0] + 1, 0), events=events)
    config = _minimal_config(extensions=(cast("AuthExtension", extension),))
    plugin = LitestarAuth(config)

    with pytest.raises(ConfigurationError, match=r"requires extension API 2\.0, but litestar-auth provides 1\.0"):
        plugin.on_app_init(AppConfig())

    assert events == []
    assert plugin._manager_hook_subscribers == ()


def _config_with_event_subscriber(
    events: list[ExtensionManagerHookEvent],
    *,
    users: tuple[ExampleUser, ...] = (),
) -> LitestarAuthConfig[ExampleUser, UUID]:
    user_db = InMemoryUserDatabase(list(users))
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-extension")),
    )
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("Any", assert_structural_session_factory(DummySessionMaker())),
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret=VERIFICATION_SECRET,
            reset_password_token_secret=RESET_PASSWORD_SECRET,
            organization_invitation_token_secret=ORGANIZATION_INVITATION_SECRET,
            api_key_hash_secret="1234567890abcdef" * 4,
            id_parser=UUID,
        ),
        extensions=cast("Any", (EventSubscriberProbeExtension(events),)),
        include_users=True,
    )


async def test_plugin_event_subscriber_receives_register_and_login_events() -> None:
    """Event subscribers observe redacted lifecycle events through the plugin manager path."""
    events: list[ExtensionManagerHookEvent] = []
    password_helper = PasswordHelper()
    seeded_user = ExampleUser(
        id=uuid4(),
        email="extension-user@example.com",
        hashed_password=password_helper.hash("user-password"),
        is_verified=True,
    )
    config = _config_with_event_subscriber(events, users=(seeded_user,))
    app = Litestar(plugins=[LitestarAuth(config)])

    async with AsyncTestClient(app=app) as client:
        register_response = await client.post(
            "/auth/register",
            json={"email": "subscriber@example.com", "password": "subscriber-password"},
        )
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "extension-user@example.com", "password": "user-password"},
        )

    assert register_response.status_code == HTTP_CREATED
    assert login_response.status_code == HTTP_CREATED
    assert [event.name for event in events] == ["after_register", "after_login"]
    _register_user, register_token = events[0].args
    assert register_token is None
    (login_user,) = events[1].args
    assert getattr(login_user, "email", None) == "extension-user@example.com"


async def test_plugin_event_subscriber_receives_redacted_update_payloads() -> None:
    """Extension subscribers observe redacted after_update payloads through user-update routes."""
    events: list[ExtensionManagerHookEvent] = []
    password_helper = PasswordHelper()
    admin_user = ExampleUser(
        id=uuid4(),
        email="admin@example.com",
        hashed_password=password_helper.hash("admin-password"),
        is_verified=True,
        roles=["superuser"],
    )
    target_user = ExampleUser(
        id=uuid4(),
        email="target@example.com",
        hashed_password=password_helper.hash("target-password"),
        is_verified=True,
    )
    config = _config_with_event_subscriber(events, users=(admin_user, target_user))
    app = Litestar(plugins=[LitestarAuth(config)])

    async with AsyncTestClient(app=app) as client:
        login_response = await client.post(
            "/auth/login",
            json={"identifier": "admin@example.com", "password": "admin-password"},
        )
        access_token = cast("str", login_response.json()["access_token"])
        headers = {"Authorization": f"Bearer {access_token}"}
        password_update_response = await client.patch(
            f"/users/{target_user.id}",
            headers=headers,
            json={"password": "rotated-password", "current_password": "admin-password"},
        )
        profile_update_response = await client.patch(
            f"/users/{target_user.id}",
            headers=headers,
            json={"is_verified": False, "roles": ["Billing", "ADMIN"], "current_password": "admin-password"},
        )

    assert login_response.status_code == HTTP_CREATED
    assert password_update_response.status_code == HTTP_OK
    assert profile_update_response.status_code == HTTP_OK
    update_events = [event for event in events if event.name == "after_update"]
    assert len(update_events) == UPDATE_EVENT_COUNT
    _password_user, password_update_dict = update_events[0].args
    assert isinstance(password_update_dict, dict)
    assert password_update_dict == {}
    assert "hashed_password" not in password_update_dict
    assert "password" not in password_update_dict
    _profile_user, profile_update_dict = update_events[1].args
    assert isinstance(profile_update_dict, dict)
    assert profile_update_dict == {"is_verified": False, "roles": ["admin", "billing"]}


async def test_plugin_event_subscribers_do_not_accumulate_across_requests() -> None:
    """Each request gets a fresh manager with one subscription per configured subscriber."""
    events: list[ExtensionManagerHookEvent] = []
    password_helper = PasswordHelper()
    seeded_user = ExampleUser(
        id=uuid4(),
        email="extension-user@example.com",
        hashed_password=password_helper.hash("user-password"),
        is_verified=True,
    )
    config = _config_with_event_subscriber(events, users=(seeded_user,))
    app = Litestar(plugins=[LitestarAuth(config)])

    async with AsyncTestClient(app=app) as client:
        first_login = await client.post(
            "/auth/login",
            json={"identifier": "extension-user@example.com", "password": "user-password"},
        )
        second_login = await client.post(
            "/auth/login",
            json={"identifier": "extension-user@example.com", "password": "user-password"},
        )

    assert first_login.status_code == HTTP_CREATED
    assert second_login.status_code == HTTP_CREATED
    assert len(events) == LOGIN_EVENT_COUNT
    assert all(event.name == "after_login" for event in events)


def test_plugin_event_subscribers_are_isolated_between_plugins() -> None:
    """Separate plugin instances do not share event-subscriber wiring state."""
    alpha_events: list[ExtensionManagerHookEvent] = []
    beta_events: list[ExtensionManagerHookEvent] = []
    alpha_plugin = LitestarAuth(
        _minimal_config(extensions=(cast("AuthExtension", EventSubscriberProbeExtension(alpha_events)),)),
    )
    beta_plugin = LitestarAuth(
        _minimal_config(extensions=(cast("AuthExtension", EventSubscriberProbeExtension(beta_events)),)),
    )

    alpha_plugin.on_app_init(AppConfig())
    beta_plugin.on_app_init(AppConfig())

    assert len(alpha_plugin._manager_hook_subscribers) == 1
    assert len(beta_plugin._manager_hook_subscribers) == 1
    assert alpha_plugin._manager_hook_subscribers is not beta_plugin._manager_hook_subscribers
