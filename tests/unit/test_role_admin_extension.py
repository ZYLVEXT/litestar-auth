"""Unit coverage for the first-party role-admin AuthExtension."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest
from litestar.config.app import AppConfig

import litestar_auth.contrib.role_admin as role_admin_module
from litestar_auth._plugin.extensions import build_extension_registration_context, build_extension_validation_context
from litestar_auth.contrib.role_admin import RoleAdminControllerConfig, RoleAdminExtension, create_role_admin_controller
from litestar_auth.exceptions import ConfigurationError
from litestar_auth.guards import is_authenticated, is_superuser
from litestar_auth.models import Role, User, UserRole
from tests.unit.test_plugin_role_admin import (
    TrackingSessionMaker,
    _build_missing_roles_attribute_user_model,
    _minimal_config,
)

pytestmark = [pytest.mark.unit, pytest.mark.imports]
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_isolated(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(_REPO_ROOT),
        check=False,
        capture_output=True,
        text=True,
    )


def test_role_admin_package_exports_extension_lazily() -> None:
    """The contrib role-admin package exposes the extension without widening unrelated surface."""
    assert role_admin_module.__all__ == (
        "RoleAdminControllerConfig",
        "RoleAdminExtension",
        "create_role_admin_controller",
    )
    assert role_admin_module.RoleAdminExtension is RoleAdminExtension


def test_role_admin_extension_symbol_import_does_not_load_controller_or_orm_modules() -> None:
    """Importing the extension symbol keeps controller and ORM modules behind runtime use."""
    proc = _run_isolated(
        "import sys\n"
        "from litestar_auth.contrib.role_admin import RoleAdminExtension\n"
        "assert RoleAdminExtension.__name__ == 'RoleAdminExtension'\n"
        "blocked = {\n"
        "    'litestar_auth.contrib.role_admin._controller',\n"
        "    'litestar_auth.contrib.role_admin._controller_handlers',\n"
        "    'litestar_auth.contrib.role_admin._controller_handler_utils',\n"
        "    'litestar_auth.models',\n"
        "    'litestar_auth.db.sqlalchemy',\n"
        "}\n"
        "loaded = blocked.intersection(sys.modules)\n"
        "assert not loaded, sorted(loaded)\n",
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_role_admin_extension_validate_accepts_role_capable_config() -> None:
    """Validation succeeds for the same role-capable config accepted by the manual controller factory."""
    config = _minimal_config(user_model=User, session_maker=TrackingSessionMaker())
    extension = RoleAdminExtension()

    extension.validate(build_extension_validation_context(config))


def test_role_admin_extension_validate_fails_closed_for_missing_role_contract() -> None:
    """Validation rejects configs whose user model cannot back role administration."""
    invalid_user_model = _build_missing_roles_attribute_user_model()
    config = _minimal_config(user_model=invalid_user_model, session_maker=TrackingSessionMaker())
    extension = RoleAdminExtension()

    with pytest.raises(ConfigurationError, match=r"Role admin requires LitestarAuthConfig\.user_model"):
        extension.validate(build_extension_validation_context(config))


def test_role_admin_extension_register_contributes_marked_default_controller() -> None:
    """Registration contributes the same default controller shape as manual mounting."""
    config = _minimal_config(user_model=User, session_maker=TrackingSessionMaker())
    context = build_extension_registration_context(app_config=AppConfig(), config=config)
    extension = RoleAdminExtension()

    extension.register(context)

    assert len(context.contributions.controllers) == 1
    controller = context.contributions.controllers[0]
    manual_controller = create_role_admin_controller(config=config)
    assert context.is_auth_route_handler(controller) is True
    assert cast("Any", controller).path == manual_controller.path == "/roles"
    assert cast("Any", controller).guards == manual_controller.guards == [is_superuser]
    assert cast("Any", controller).role_admin_context.config is config


def test_role_admin_extension_register_uses_grouped_controller_config_path() -> None:
    """Registration uses the factory's grouped settings path without mixing keyword options."""
    config = _minimal_config(user_model=User, session_maker=TrackingSessionMaker())
    context = build_extension_registration_context(app_config=AppConfig(), config=config)
    extension = RoleAdminExtension(route_prefix="admin/roles", guards=[is_authenticated])

    extension.register(context)

    controller = context.contributions.controllers[0]
    equivalent_manual_controller = create_role_admin_controller(
        controller_config=RoleAdminControllerConfig(
            config=config,
            route_prefix="admin/roles",
            guards=[is_authenticated],
        ),
    )
    controller_context = cast("Any", controller).role_admin_context
    assert cast("Any", controller).path == equivalent_manual_controller.path == "/admin/roles"
    assert cast("Any", controller).guards == equivalent_manual_controller.guards == [is_authenticated]
    assert controller_context.model_family.user_model is User
    assert controller_context.model_family.role_model is Role
    assert controller_context.model_family.user_role_model is UserRole
