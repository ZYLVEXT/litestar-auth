"""Backward-compatible OAuth validation import shim."""

from __future__ import annotations

from litestar_auth._plugin.validation.oauth import validate_oauth_route_registration_config

__all__ = ("validate_oauth_route_registration_config",)
