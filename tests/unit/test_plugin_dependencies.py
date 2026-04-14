"""Unit tests for auth plugin dependency and exception-handler wiring helpers."""

from __future__ import annotations

import asyncio
import importlib
import inspect
from typing import TYPE_CHECKING, Any, ClassVar, cast, get_type_hints
from uuid import UUID

import pytest
from litestar import Controller
from litestar.config.app import AppConfig
from litestar.datastructures.state import State
from litestar.di import Provide
from litestar.enums import MediaType
from litestar.exceptions import ClientException
from litestar.response import Response

import litestar_auth._plugin.dependencies as dependencies_module
from litestar_auth._plugin import (
    DEFAULT_BACKENDS_DEPENDENCY_KEY,
    DEFAULT_CONFIG_DEPENDENCY_KEY,
    DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
    DEFAULT_USER_MODEL_DEPENDENCY_KEY,
    OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY,
)
from litestar_auth._plugin.config import LitestarAuthConfig, OAuthConfig
from litestar_auth._plugin.dependencies import (
    DependencyProviders,
    _make_backends_dependency_provider,
    _make_db_session_provide,
    _make_user_manager_dependency_provider,
    client_exception_handler,
    register_dependencies,
    register_exception_handlers,
)
from litestar_auth._plugin.scoped_session import SessionFactory
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.transport.bearer import BearerTransport
from litestar_auth.controllers._utils import _mark_litestar_auth_route_handler
from litestar_auth.exceptions import ErrorCode
from litestar_auth.manager import UserManagerSecurity
from tests.e2e.conftest import assert_structural_session_factory
from tests.integration.test_orchestrator import (
    DummySessionMaker,
    ExampleUser,
    InMemoryTokenStrategy,
    InMemoryUserDatabase,
    PluginUserManager,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

pytestmark = pytest.mark.unit
HTTP_BAD_REQUEST = 400
HTTP_IM_A_TEAPOT = 418


def test_plugin_dependencies_module_executes_under_coverage() -> None:
    """Reload the module in-test so coverage records the module body."""
    reloaded_module = importlib.reload(dependencies_module)

    assert reloaded_module.DependencyProviders.__name__ == DependencyProviders.__name__
    assert reloaded_module.client_exception_handler.__name__ == client_exception_handler.__name__


def _minimal_config() -> LitestarAuthConfig[ExampleUser, UUID]:
    """Build a minimal plugin config for dependency-registration tests.

    Returns:
        Plugin config suitable for isolated dependency-wiring assertions.
    """
    user_db = InMemoryUserDatabase([])
    return LitestarAuthConfig[ExampleUser, UUID](
        backends=[
            AuthenticationBackend[ExampleUser, UUID](
                name="primary",
                transport=BearerTransport(),
                strategy=cast("Any", InMemoryTokenStrategy(token_prefix="plugin-dependencies")),
            ),
        ],
        session_maker=cast(
            "async_sessionmaker[AsyncSession]",
            assert_structural_session_factory(DummySessionMaker()),
        ),
        user_model=ExampleUser,
        user_manager_class=PluginUserManager,
        user_db_factory=lambda _session: user_db,
        user_manager_security=UserManagerSecurity[UUID](
            verification_token_secret="verify-secret-12345678901234567890",
            reset_password_token_secret="reset-secret-123456789012345678901",
            id_parser=UUID,
        ),
        user_manager_kwargs={},
        include_users=False,
    )


def _providers() -> DependencyProviders:
    """Create provider callables matching plugin registration behavior.

    Returns:
        Dependency provider bundle matching the plugin's expected shapes.
    """

    def provide_config() -> object:
        return object()

    async def provide_user_manager(db_session: object) -> object:
        await asyncio.sleep(0)
        yield ("manager", db_session)

    def provide_backends() -> tuple[str, ...]:
        return ("primary",)

    def provide_user_model() -> type[ExampleUser]:
        return ExampleUser

    async def provide_oauth_associate_user_manager(db_session: object) -> object:
        await asyncio.sleep(0)
        yield ("oauth-associate", db_session)

    return DependencyProviders(
        config=provide_config,
        user_manager=provide_user_manager,
        backends=provide_backends,
        user_model=provide_user_model,
        oauth_associate_user_manager=provide_oauth_associate_user_manager,
    )


def test_client_exception_handler_formats_json_response() -> None:
    """ClientException values are surfaced in the auth JSON error contract."""
    exc = ClientException(
        detail="bad credentials",
        extra={"code": "AUTH_FAILED"},
        status_code=418,
        headers={"X-Auth": "1"},
    )

    response = client_exception_handler(cast("Any", None), exc)

    assert response.content == {"detail": "bad credentials", "code": "AUTH_FAILED"}
    assert response.status_code == HTTP_IM_A_TEAPOT
    assert response.media_type == MediaType.JSON
    assert response.headers == {"X-Auth": "1"}


def test_client_exception_handler_uses_error_code_unknown_when_extra_omits_code() -> None:
    """Auth JSON responses fall back to ErrorCode.UNKNOWN when no string code is in ClientException.extra."""
    exc = ClientException(detail="unspecified failure", extra={}, status_code=HTTP_BAD_REQUEST)

    response = client_exception_handler(cast("Any", None), exc)

    assert response.content == {"detail": "unspecified failure", "code": ErrorCode.UNKNOWN}
    assert response.status_code == HTTP_BAD_REQUEST


def test_register_exception_handlers_preserves_existing_handlers() -> None:
    """Registering auth handlers keeps existing controller handlers while adding ClientException."""

    def existing_handler(_request: object, _exc: Exception) -> Response[dict[str, str]]:
        """Placeholder handler used to confirm existing handlers are preserved.

        Returns:
            Static JSON response used only for handler identity checks.
        """
        return Response({"detail": "runtime", "code": "RUNTIME"}, media_type=MediaType.JSON)

    @_mark_litestar_auth_route_handler
    class ExistingController(Controller):
        exception_handlers: ClassVar[dict[type[Exception], object] | None] = {RuntimeError: existing_handler}
        path = "/auth"

    register_exception_handlers([ExistingController])
    handlers = cast("dict[type[Exception], object]", ExistingController.exception_handlers)

    assert handlers[RuntimeError] is existing_handler
    assert handlers[ClientException] is dependencies_module.client_exception_handler


def test_register_exception_handlers_preserves_existing_client_exception_handler() -> None:
    """Registering auth handlers does not override controller-local ClientException handlers."""

    def existing_handler(_request: object, _exc: ClientException) -> Response[dict[str, str]]:
        """Return a sentinel response for identity assertions.

        Returns:
            Static JSON response used only for handler identity checks.
        """
        return Response({"detail": "existing", "code": "EXISTING"}, media_type=MediaType.JSON)

    @_mark_litestar_auth_route_handler
    class ExistingController(Controller):
        exception_handlers: ClassVar[dict[type[Exception], object] | None] = {ClientException: existing_handler}
        path = "/auth"

    register_exception_handlers([ExistingController])
    handlers = cast("dict[type[Exception], object]", ExistingController.exception_handlers)

    assert handlers[ClientException] is existing_handler


def test_register_exception_handlers_only_mutates_handlers_it_receives() -> None:
    """Scope is controlled by the exact handler list supplied by the caller."""

    @_mark_litestar_auth_route_handler
    class PluginOwnedController(Controller):
        exception_handlers: ClassVar[dict[type[Exception], object] | None] = None
        path = "/auth"

    class NonAuthController(Controller):
        exception_handlers: ClassVar[dict[type[Exception], object] | None] = None
        path = "/auth-state"

    register_exception_handlers([PluginOwnedController])

    assert PluginOwnedController.exception_handlers is not None
    assert PluginOwnedController.exception_handlers[ClientException] is dependencies_module.client_exception_handler
    assert NonAuthController.exception_handlers is None


def test_make_db_session_provide_reuses_scoped_session_within_scope() -> None:
    """The generated sync provider reuses sessions for structurally compatible factories."""
    session_maker = assert_structural_session_factory(DummySessionMaker())
    provider = _make_db_session_provide(cast("async_sessionmaker[AsyncSession]", session_maker))
    state = State()
    scope: dict[str, object] = {}

    first_session = provider(state, cast("Any", scope))
    second_session = provider(state, cast("Any", scope))
    other_scope_session = provider(state, cast("Any", {}))

    assert first_session is second_session
    assert other_scope_session is not first_session


def test_make_db_session_provide_annotations_are_runtime_resolvable() -> None:
    """Runtime type-hint resolution for the DB-session provider keeps SessionFactory available."""
    hints = get_type_hints(_make_db_session_provide)

    assert hints["session_maker"] is SessionFactory


def test_make_backends_dependency_provider_exposes_configured_di_parameter_name() -> None:
    """Backends providers expose the configured dependency key and accept Litestar-style injection."""
    marker = object()
    seen_sessions: list[object] = []

    def build_backends(session: AsyncSession) -> tuple[AuthenticationBackend[ExampleUser, UUID], ...]:
        seen_sessions.append(session)
        return ()

    provider = _make_backends_dependency_provider(build_backends, "custom_db_session")
    parameter_names = tuple(inspect.signature(provider).parameters)

    assert provider(custom_db_session=marker) == ()
    assert seen_sessions == [marker]
    assert parameter_names == ("custom_db_session",)


def test_make_backends_dependency_provider_rejects_multiple_positional_sessions() -> None:
    """Backends providers fail closed when callers supply more than one positional session."""

    def build_backends(_session: AsyncSession) -> tuple[AuthenticationBackend[ExampleUser, UUID], ...]:
        pytest.fail("build_backends should not run when too many positional dependency inputs are provided")

    provider = _make_backends_dependency_provider(build_backends, "db_session")
    with pytest.raises(TypeError, match="takes 1 positional argument but 2 were given"):
        provider(object(), object())


async def test_make_user_manager_dependency_provider_exposes_configured_di_parameter_name() -> None:
    """User-manager providers expose the configured dependency key and yield the injected manager."""
    marker = object()

    def build_user_manager(session: object) -> object:
        return ("manager", session)

    provider = _make_user_manager_dependency_provider(build_user_manager, "custom_db_session")
    generator = cast("Any", provider(custom_db_session=marker))
    try:
        manager = await anext(generator)
    finally:
        await generator.aclose()

    parameter_names = tuple(inspect.signature(provider).parameters)
    assert manager == ("manager", marker)
    assert parameter_names == ("custom_db_session",)


def test_make_user_manager_dependency_provider_rejects_positional_and_keyword_session() -> None:
    """Providing both the positional session and keyword DI value fails closed."""
    marker = object()

    def build_user_manager(_session: object) -> object:
        pytest.fail("build_user_manager should not run when duplicate dependency inputs are provided")

    provider = _make_user_manager_dependency_provider(build_user_manager, "db_session")
    with pytest.raises(TypeError, match="db_session"):
        provider(marker, db_session=marker)


async def test_make_user_manager_dependency_provider_positional_path_stops_after_single_yield() -> None:
    """The direct positional-call path yields once and then stops cleanly."""
    marker = object()

    def build_user_manager(session: object) -> object:
        return ("manager", session)

    provider = _make_user_manager_dependency_provider(build_user_manager, "db_session")
    generator = provider(marker)

    assert await anext(generator) == ("manager", marker)
    with pytest.raises(StopAsyncIteration):
        await anext(generator)


def test_make_user_manager_dependency_provider_requires_session_dependency() -> None:
    """Calling the provider without the configured dependency key raises TypeError."""

    def build_user_manager(_session: object) -> object:
        pytest.fail("build_user_manager should not run when the dependency is missing")

    provider = _make_user_manager_dependency_provider(build_user_manager, "db_session")
    with pytest.raises(TypeError, match="db_session"):
        provider()


def test_make_user_manager_dependency_provider_rejects_unexpected_keyword_dependencies() -> None:
    """Unexpected keyword dependencies are rejected before building a user manager."""
    marker = object()

    def build_user_manager(_session: object) -> object:
        pytest.fail("build_user_manager should not run for unexpected keyword dependencies")

    provider = _make_user_manager_dependency_provider(build_user_manager, "db_session")
    with pytest.raises(TypeError, match="other_session"):
        provider(other_session=marker)


def test_register_dependencies_raises_for_dependency_key_collisions() -> None:
    """Pre-existing app dependency keys fail closed before auth wiring mutates the app."""
    app_config = AppConfig()
    app_config.dependencies[DEFAULT_CONFIG_DEPENDENCY_KEY] = Provide(lambda: None, sync_to_thread=False)
    config = _minimal_config()

    with pytest.raises(ValueError, match=DEFAULT_CONFIG_DEPENDENCY_KEY):
        register_dependencies(app_config, config, providers=_providers())


async def test_register_dependencies_registers_core_providers_and_autocommit_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Core dependency keys, request-scoped DB DI, and autocommit wiring are all registered."""
    app_config = AppConfig()
    config = _minimal_config()
    autocommit_handler = object()
    monkeypatch.setattr(
        "litestar_auth._plugin.dependencies.async_autocommit_handler_maker",
        lambda: autocommit_handler,
    )

    register_dependencies(app_config, config, providers=_providers())

    assert set(app_config.dependencies) >= {
        DEFAULT_CONFIG_DEPENDENCY_KEY,
        DEFAULT_USER_MANAGER_DEPENDENCY_KEY,
        DEFAULT_BACKENDS_DEPENDENCY_KEY,
        DEFAULT_USER_MODEL_DEPENDENCY_KEY,
        config.db_session_dependency_key,
    }
    assert app_config.before_send == [autocommit_handler]

    db_session_provider = app_config.dependencies[config.db_session_dependency_key]
    assert isinstance(db_session_provider, Provide)
    assert db_session_provider.use_cache is False
    assert db_session_provider.sync_to_thread is False
    scoped_scope: dict[str, object] = {}
    first_session = db_session_provider.dependency(State(), cast("Any", scoped_scope))
    second_session = db_session_provider.dependency(State(), cast("Any", scoped_scope))
    assert first_session is second_session

    user_manager_provider = app_config.dependencies[DEFAULT_USER_MANAGER_DEPENDENCY_KEY]
    assert isinstance(user_manager_provider, Provide)
    assert user_manager_provider.use_cache is False
    generator = user_manager_provider.dependency(db_session=first_session)
    try:
        user_manager = await anext(generator)
    finally:
        await generator.aclose()
    assert user_manager == ("manager", first_session)

    backends_provider = app_config.dependencies[DEFAULT_BACKENDS_DEPENDENCY_KEY]
    assert isinstance(backends_provider, Provide)
    assert backends_provider.use_cache is False
    assert backends_provider.sync_to_thread is False
    assert backends_provider.dependency() == ("primary",)


def test_register_dependencies_adds_oauth_associate_provider_only_when_configured() -> None:
    """OAuth associate DI is registered only when the matching config surface is enabled."""
    absent_app_config = AppConfig()
    absent_config = _minimal_config()

    register_dependencies(absent_app_config, absent_config, providers=_providers())

    assert OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY not in absent_app_config.dependencies

    present_app_config = AppConfig()
    present_config = _minimal_config()
    present_config.oauth_config = OAuthConfig(
        oauth_providers=[("example", object())],
        include_oauth_associate=True,
        oauth_redirect_base_url="https://app.example.com/auth",
        oauth_token_encryption_key="YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    )

    register_dependencies(present_app_config, present_config, providers=_providers())

    assert OAUTH_ASSOCIATE_USER_MANAGER_DEPENDENCY_KEY in present_app_config.dependencies


def test_register_dependencies_skips_db_session_provider_and_autocommit_when_external() -> None:
    """External AsyncSession DI disables plugin-owned session and autocommit registration."""
    app_config = AppConfig()
    config = _minimal_config()
    config.db_session_dependency_provided_externally = True

    register_dependencies(app_config, config, providers=_providers())

    assert config.db_session_dependency_key not in app_config.dependencies
    assert app_config.before_send == []


def test_register_dependencies_wraps_sync_providers_without_sync_to_thread() -> None:
    """Non-generator sync providers are registered as explicit non-threaded Provide instances."""
    app_config = AppConfig()
    config = _minimal_config()

    def provide_config() -> str:
        return "config"

    register_dependencies(
        app_config,
        config,
        providers=DependencyProviders(
            config=provide_config,
            user_manager=_providers().user_manager,
            backends=_providers().backends,
            user_model=_providers().user_model,
            oauth_associate_user_manager=_providers().oauth_associate_user_manager,
        ),
    )

    config_provider = app_config.dependencies[DEFAULT_CONFIG_DEPENDENCY_KEY]
    assert isinstance(config_provider, Provide)
    assert config_provider.use_cache is True
    assert config_provider.sync_to_thread is False
    assert config_provider.dependency() == "config"
