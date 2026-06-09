"""Unit coverage for the first-party organization-admin AuthExtension."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any, cast
from uuid import UUID

import pytest
from litestar.config.app import AppConfig

import litestar_auth.contrib.organization_admin as organization_admin_module
from litestar_auth._plugin.extensions import build_extension_registration_context, build_extension_validation_context
from litestar_auth._plugin.features import OrganizationConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.contrib.organization_admin import (
    OrganizationAdminControllerConfig,
    OrganizationAdminExtension,
    create_organization_admin_controller,
)
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.guards import is_authenticated, is_superuser
from litestar_auth.manager import UserManagerSecurity
from litestar_auth.plugin import LitestarAuthConfig
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

pytestmark = [pytest.mark.unit, pytest.mark.imports]
_REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFICATION_SECRET = "0123456789abcdef" * 4
RESET_PASSWORD_SECRET = "fedcba9876543210" * 4
ORGANIZATION_INVITATION_SECRET = "c4b7e9a13f6d8c2059ab7e3041f8d6e2" * 2
EXPECTED_INVITATION_CONTROLLER_COUNT = 2


def _run_isolated(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(_REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )


def _minimal_config(
    *,
    organization_config: OrganizationConfig | None = None,
    id_parser: type[UUID] | None = UUID,
    include_invitation_secret: bool = True,
    include_user_manager_security: bool = True,
) -> LitestarAuthConfig[ExampleUser, UUID]:
    user_db = InMemoryUserDatabase([])
    backend = AuthenticationBackend[ExampleUser, UUID](
        name="primary",
        transport=BearerTransport(),
        strategy=cast("Any", InMemoryTokenStrategy(token_prefix="organization-admin-extension")),
    )
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[backend],
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        session_maker=cast("Any", assert_structural_session_factory(DummySessionMaker())),
        user_db_factory=lambda _session: user_db,
        user_manager_security=(
            UserManagerSecurity[UUID](
                verification_token_secret=VERIFICATION_SECRET,
                reset_password_token_secret=RESET_PASSWORD_SECRET,
                organization_invitation_token_secret=(
                    ORGANIZATION_INVITATION_SECRET if include_invitation_secret else None
                ),
            )
            if include_user_manager_security
            else None
        ),
        organization_config=(
            OrganizationConfig(enabled=True, store_factory=cast("Any", lambda _session: object()))
            if organization_config is None
            else organization_config
        ),
        id_parser=id_parser,
    )


def test_organization_admin_package_exports_extension_lazily() -> None:
    """The contrib organization-admin package exposes the extension without widening unrelated surface."""
    assert organization_admin_module.__all__ == (
        "OrganizationAdminControllerConfig",
        "OrganizationAdminExtension",
        "OrganizationInvitationControllerConfig",
        "create_organization_admin_controller",
        "create_organization_invitation_controller",
    )
    assert organization_admin_module.OrganizationAdminExtension is OrganizationAdminExtension


def test_organization_admin_extension_symbol_import_does_not_load_controller_or_orm_modules() -> None:
    """Importing the extension symbol keeps controller and ORM modules behind runtime use."""
    proc = _run_isolated(
        "import sys\n"
        "from litestar_auth.contrib.organization_admin import OrganizationAdminExtension\n"
        "assert OrganizationAdminExtension.__name__ == 'OrganizationAdminExtension'\n"
        "blocked = {\n"
        "    'litestar_auth.contrib.organization_admin._controller',\n"
        "    'litestar_auth.contrib.organization_admin._schemas',\n"
        "    'litestar_auth.contrib.organization_admin._error_responses',\n"
        "    'litestar_auth._plugin.organization_admin',\n"
        "    'litestar_auth._plugin.organization_admin._core',\n"
        "    'litestar_auth.models',\n"
        "    'litestar_auth.db.sqlalchemy',\n"
        "}\n"
        "loaded = blocked.intersection(sys.modules)\n"
        "assert not loaded, sorted(loaded)\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_organization_admin_extension_validate_accepts_enabled_organization_config() -> None:
    """Validation succeeds for organization-enabled configs with the id parser required by the factory."""
    extension = OrganizationAdminExtension()

    extension.validate(build_extension_validation_context(_minimal_config()))


def test_organization_admin_extension_validate_fails_closed_when_organizations_are_disabled() -> None:
    """The extension refuses to mount tenant-aware routes without organization support."""
    config = _minimal_config(organization_config=OrganizationConfig())
    extension = OrganizationAdminExtension()

    with pytest.raises(ConfigurationError, match=r"requires organization_config\.enabled=True"):
        extension.validate(build_extension_validation_context(config))


def test_organization_admin_extension_validate_fails_closed_when_id_parser_is_missing() -> None:
    """The extension reports the controller id-parser prerequisite during validation."""
    config = _minimal_config(id_parser=None)
    extension = OrganizationAdminExtension()

    with pytest.raises(ConfigurationError, match="requires id_parser"):
        extension.validate(build_extension_validation_context(config))


def test_organization_admin_extension_validate_fails_closed_when_store_factory_is_missing() -> None:
    """The extension reports the organization persistence prerequisite during validation."""
    config = _minimal_config(organization_config=OrganizationConfig(enabled=True))
    extension = OrganizationAdminExtension()

    with pytest.raises(ConfigurationError, match=r"requires organization_config\.store_factory"):
        extension.validate(build_extension_validation_context(config))


def test_organization_admin_extension_validate_fails_closed_when_invitation_security_is_missing() -> None:
    """Invitation routes require the manager security bundle only when opted in."""
    config = _minimal_config(include_user_manager_security=False)
    extension = OrganizationAdminExtension(include_invitations=True)

    with pytest.raises(ConfigurationError, match="invitation routes require user_manager_security"):
        extension.validate(build_extension_validation_context(config))


def test_organization_admin_extension_validate_invitation_secret_only_when_opted_in() -> None:
    """Invitation token signing material is required only for the invitee-facing controller."""
    config = _minimal_config(include_invitation_secret=False)

    OrganizationAdminExtension().validate(build_extension_validation_context(config))
    with pytest.raises(ConfigurationError, match="organization_invitation_token_secret"):
        OrganizationAdminExtension(include_invitations=True).validate(build_extension_validation_context(config))


def test_organization_admin_extension_validate_accepts_invitation_prerequisites_when_opted_in() -> None:
    """The invitation validation branch accepts the configured token-signing prerequisites."""
    config = _minimal_config()

    OrganizationAdminExtension(include_invitations=True).validate(build_extension_validation_context(config))


def test_organization_admin_extension_register_contributes_marked_default_controller() -> None:
    """Registration contributes the same default controller shape as manual mounting."""
    config = _minimal_config()
    context = build_extension_registration_context(app_config=AppConfig(), config=config)
    extension = OrganizationAdminExtension()

    extension.register(context)

    assert len(context.contributions.controllers) == 1
    controller = context.contributions.controllers[0]
    manual_controller = create_organization_admin_controller(config=config)
    assert context.is_auth_route_handler(controller) is True
    assert cast("Any", controller).path == manual_controller.path == "/organizations"
    assert cast("Any", controller).guards == manual_controller.guards == [is_superuser]


def test_organization_admin_extension_register_uses_grouped_controller_config_path() -> None:
    """Registration uses the factory's grouped settings path without mixing keyword options."""
    config = _minimal_config()
    context = build_extension_registration_context(app_config=AppConfig(), config=config)
    extension = OrganizationAdminExtension(route_prefix="admin/organizations", guards=[is_authenticated])

    extension.register(context)

    controller = context.contributions.controllers[0]
    equivalent_manual_controller = create_organization_admin_controller(
        controller_config=OrganizationAdminControllerConfig(
            config=config,
            route_prefix="admin/organizations",
            guards=[is_authenticated],
        ),
    )
    controller_context = cast("Any", controller).organization_admin_context
    assert cast("Any", controller).path == equivalent_manual_controller.path == "/admin/organizations"
    assert cast("Any", controller).guards == equivalent_manual_controller.guards == [is_authenticated]
    assert controller_context.id_parser is UUID


def test_organization_admin_extension_register_adds_invitation_controller_only_when_opted_in() -> None:
    """The invitee-facing accept/decline controller is an explicit extension opt-in."""
    config = _minimal_config()
    context = build_extension_registration_context(app_config=AppConfig(), config=config)

    OrganizationAdminExtension(include_invitations=True).register(context)

    assert len(context.contributions.controllers) == EXPECTED_INVITATION_CONTROLLER_COUNT
    admin_controller, invitation_controller = context.contributions.controllers
    assert cast("Any", admin_controller).path == "/organizations"
    assert cast("Any", invitation_controller).path == "/auth"
    assert context.is_auth_route_handler(invitation_controller) is True
    assert cast("Any", invitation_controller).organization_invitation_context.security == [{"primary": []}]


def test_organization_admin_config_flags_resolve_internal_extension_without_mutating_config() -> None:
    """Legacy organization-admin flags are normalized into the extension path at startup."""
    config = _minimal_config(
        organization_config=OrganizationConfig(
            enabled=True,
            store_factory=cast("Any", lambda _session: object()),
            include_organization_invitations=True,
        ),
    )

    extensions = config.resolve_extensions()

    assert config.extensions == ()
    assert len(extensions) == 1
    extension = extensions[0]
    assert isinstance(extension, OrganizationAdminExtension)
    assert extension.name == "organization_admin"
    assert extension._include_admin_controller is False
    assert extension.include_invitations is True


def test_organization_admin_config_flag_collides_with_explicit_extension_name() -> None:
    """A flag-derived extension and explicit extension fail closed through duplicate-name validation."""
    config = _minimal_config(
        organization_config=OrganizationConfig(
            enabled=True,
            store_factory=cast("Any", lambda _session: object()),
            include_organization_admin=True,
        ),
    )
    config.extensions = (OrganizationAdminExtension(),)

    with pytest.raises(ValueError, match="Duplicate auth extension names are not allowed: organization_admin"):
        build_extension_validation_context(config)
