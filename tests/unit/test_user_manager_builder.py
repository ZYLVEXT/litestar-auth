"""Unit tests for ``litestar_auth._plugin.user_manager_builder`` (extracted manager builders)."""

from __future__ import annotations

import litestar_auth._plugin.config as plugin_config_module
import litestar_auth._plugin.user_manager_builder as user_manager_builder_module


def test_config_reexports_delegate_to_user_manager_builder_module() -> None:
    """Public and internal symbols re-exported from config match the implementation module."""
    assert plugin_config_module.build_user_manager is user_manager_builder_module.build_user_manager
    assert plugin_config_module.resolve_password_validator is user_manager_builder_module.resolve_password_validator
    assert plugin_config_module.resolve_user_manager_factory is user_manager_builder_module.resolve_user_manager_factory
    assert (
        plugin_config_module._build_default_user_manager_contract
        is user_manager_builder_module._build_default_user_manager_contract
    )
