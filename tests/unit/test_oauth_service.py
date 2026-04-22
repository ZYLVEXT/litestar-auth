"""Unit tests for OAuth flow orchestration service."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from litestar.exceptions import ClientException, PermissionDeniedException

import litestar_auth.oauth.service as oauth_service_module
from litestar_auth.exceptions import ErrorCode
from litestar_auth.oauth.client_adapter import OAuthClientAdapter
from litestar_auth.oauth.service import (
    OAuthService,
    _require_account_state,
    _require_oauth_account_store,
    _resolve_account_state_validator,
)
from tests._helpers import ExampleUser
from tests.unit.test_definition_file_coverage import load_reloaded_test_alias

pytestmark = pytest.mark.unit


def _build_manager(*, existing_user: ExampleUser | None = None) -> AsyncMock:
    """Create an async mock manager with an attached async mock user store.

    Returns:
        Async mock manager with the OAuth user-store contract attached.
    """
    mock_user_db = AsyncMock()
    mock_user_db.get_by_email.return_value = existing_user
    oauth_account_store = AsyncMock()
    oauth_account_store.get_by_oauth_account.return_value = None
    manager = AsyncMock()
    manager.user_db = mock_user_db
    manager.oauth_account_store = oauth_account_store
    manager.require_account_state = MagicMock()
    manager.on_after_login = AsyncMock()
    return manager


def test_oauth_service_module_reload_preserves_behavioral_error_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reload coverage keeps helper behavior stable without pinning exception identity."""
    assert oauth_service_module.__file__ is not None
    reloaded_module = load_reloaded_test_alias(
        alias_name="_coverage_alias_oauth_service",
        source_path=Path(oauth_service_module.__file__).resolve(),
        monkeypatch=monkeypatch,
    )
    service = reloaded_module.OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(AsyncMock()),
        trust_provider_email_verified=True,
    )

    with pytest.raises(
        Exception,
        match="trust_provider_email_verified=True requires the OAuth provider to assert",
    ) as exc_info:
        service._require_provider_verification_signal(email_verified=None)

    manager = MagicMock()
    manager.require_account_state.side_effect = reloaded_module.InactiveUserError()

    with pytest.raises(ClientException) as client_exc_info:
        reloaded_module._require_account_state(
            ExampleUser(id=uuid4(), email="inactive@example.com"),
            user_manager=manager,
        )

    assert reloaded_module.OAuthService.__name__ == OAuthService.__name__
    assert reloaded_module.OAuthAuthorization.__name__ == "OAuthAuthorization"
    assert type(exc_info.value).__name__ == "ConfigurationError"
    assert getattr(exc_info.value, "code", None) == ErrorCode.CONFIGURATION_INVALID
    extra = client_exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.LOGIN_USER_INACTIVE
    assert client_exc_info.value.detail == reloaded_module.InactiveUserError.default_message


async def test_authorize_returns_state_and_provider_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Authorize flow generates state and delegates URL construction to the client adapter."""
    oauth_client = AsyncMock()
    oauth_client.get_authorization_url.return_value = "https://provider.example/authorize?state=fixed-state"
    service = OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
    )
    monkeypatch.setattr("litestar_auth.oauth.service.secrets.token_urlsafe", lambda _size: "fixed-state")

    authorization = await service.authorize(
        redirect_uri="https://app.example/callback",
        scopes=["openid", "email"],
    )

    assert authorization.state == "fixed-state"
    assert authorization.authorization_url == "https://provider.example/authorize?state=fixed-state"
    oauth_client.get_authorization_url.assert_awaited_once_with(
        "https://app.example/callback",
        "fixed-state",
        scope="openid email",
    )


async def test_complete_login_bootstraps_user_and_links_account(monkeypatch: pytest.MonkeyPatch) -> None:
    """Callback login creates a verified user when no account or email match exists."""
    oauth_client = AsyncMock()
    oauth_client.get_access_token.return_value = {
        "access_token": "provider-access-token",
        "expires_at": 123,
        "refresh_token": "provider-refresh-token",
    }
    oauth_client.get_id_email.return_value = ("provider-user", "oauth@example.com")
    oauth_client.get_email_verified.return_value = True
    service = OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
        trust_provider_email_verified=True,
    )
    manager = _build_manager()
    created_user = ExampleUser(id=uuid4(), email="oauth@example.com")
    verified_user = ExampleUser(id=created_user.id, email=created_user.email, is_verified=True)
    manager.create.return_value = created_user
    manager.update.return_value = verified_user
    monkeypatch.setattr("litestar_auth.oauth.service.secrets.token_urlsafe", lambda _size: "generated-password")

    user = await service.complete_login(
        code="provider-code",
        redirect_uri="https://app.example/callback",
        user_manager=manager,
    )

    assert user is verified_user
    manager.create.assert_awaited_once_with(
        {"email": "oauth@example.com", "password": "generated-password"},
        safe=True,
    )
    manager.update.assert_awaited_once_with(
        {"is_verified": True},
        created_user,
        allow_privileged=True,
    )
    manager.require_account_state.assert_called_once_with(verified_user, require_verified=False)
    manager.oauth_account_store.upsert_oauth_account.assert_awaited_once_with(
        verified_user,
        oauth_name="github",
        account_id="provider-user",
        account_email="oauth@example.com",
        access_token="provider-access-token",
        expires_at=123,
        refresh_token="provider-refresh-token",
    )


async def test_complete_login_rejects_existing_email_without_association() -> None:
    """Existing email without associate-by-email preserves the stable client error."""
    existing_user = ExampleUser(id=uuid4(), email="existing@example.com")
    manager = _build_manager(existing_user=existing_user)
    oauth_client = AsyncMock()
    oauth_client.get_access_token.return_value = {"access_token": "provider-access-token"}
    oauth_client.get_id_email.return_value = ("provider-user", "existing@example.com")
    oauth_client.get_email_verified.return_value = True
    service = OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
    )

    with pytest.raises(ClientException) as exc_info:
        await service.complete_login(
            code="provider-code",
            redirect_uri="https://app.example/callback",
            user_manager=manager,
        )

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_USER_ALREADY_EXISTS
    manager.oauth_account_store.upsert_oauth_account.assert_not_awaited()


def test_require_provider_verification_signal_rejects_missing_signal_in_strict_mode() -> None:
    """Strict verification mode requires a provider verification signal."""
    service = OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(AsyncMock()),
        trust_provider_email_verified=True,
    )

    with pytest.raises(
        Exception,
        match="trust_provider_email_verified=True requires the OAuth provider to assert",
    ) as exc_info:
        service._require_provider_verification_signal(email_verified=None)

    assert type(exc_info.value).__name__ == "ConfigurationError"
    assert getattr(exc_info.value, "code", None) == ErrorCode.CONFIGURATION_INVALID


async def test_resolve_candidate_user_prefers_existing_oauth_link() -> None:
    """Linked provider accounts bypass the user-db email lookup."""
    linked_user = ExampleUser(id=uuid4(), email="linked@example.com")
    manager = _build_manager()
    manager.oauth_account_store.get_by_oauth_account.return_value = linked_user
    service = OAuthService(provider_name="github", client=OAuthClientAdapter(AsyncMock()))

    user, existing_by_email = await service._resolve_candidate_user(
        user_manager=manager,
        oauth_account_store=manager.oauth_account_store,
        account_id="provider-user",
        account_email="linked@example.com",
    )

    assert user is linked_user
    assert existing_by_email is None
    manager.user_db.get_by_email.assert_not_awaited()


async def test_materialize_or_validate_user_creates_new_user_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """The service delegates new-user materialization to the OAuth bootstrap helper."""
    manager = _build_manager()
    service = OAuthService(provider_name="github", client=OAuthClientAdapter(AsyncMock()))
    created_user = ExampleUser(id=uuid4(), email="new@example.com")
    create_user_from_oauth = AsyncMock(return_value=created_user)
    monkeypatch.setattr(service, "_create_user_from_oauth", create_user_from_oauth)

    user = await service._materialize_or_validate_user(
        user_manager=manager,
        user=None,
        existing_by_email=None,
        account_email="new@example.com",
        email_verified=True,
    )

    assert user is created_user
    create_user_from_oauth.assert_awaited_once_with(
        user_manager=manager,
        account_email="new@example.com",
        email_verified=True,
    )


async def test_materialize_or_validate_user_returns_existing_link_without_email_match() -> None:
    """Linked users are returned directly when there is no email collision."""
    linked_user = ExampleUser(id=uuid4(), email="linked@example.com")
    manager = _build_manager()
    service = OAuthService(provider_name="github", client=OAuthClientAdapter(AsyncMock()))

    user = await service._materialize_or_validate_user(
        user_manager=manager,
        user=linked_user,
        existing_by_email=None,
        account_email="linked@example.com",
        email_verified=True,
    )

    assert user is linked_user


async def test_materialize_or_validate_user_validates_email_link_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Existing email matches invoke the configured linking policy validator."""
    existing_user = ExampleUser(id=uuid4(), email="existing@example.com")
    manager = _build_manager()
    service = OAuthService(provider_name="github", client=OAuthClientAdapter(AsyncMock()))
    validate_existing_email_link_policy = MagicMock()
    monkeypatch.setattr(service, "_validate_existing_email_link_policy", validate_existing_email_link_policy)

    user = await service._materialize_or_validate_user(
        user_manager=manager,
        user=existing_user,
        existing_by_email=existing_user,
        account_email="existing@example.com",
        email_verified=True,
    )

    assert user is existing_user
    validate_existing_email_link_policy.assert_called_once_with(email_verified=True)


def test_require_account_state_rejects_user_without_guarded_protocol_on_attribute_fallback() -> None:
    """OAuth account-state fallback requires :class:`~litestar_auth.types.GuardedUserProtocol`."""

    class _MinimalUser:
        __slots__ = ("id",)

        def __init__(self) -> None:
            self.id = UUID(int=0)

    manager = MagicMock()
    manager.require_account_state = "not-callable"

    with pytest.raises(PermissionDeniedException) as exc_info:
        _require_account_state(_MinimalUser(), user_manager=manager)

    assert "account state" in (exc_info.value.detail or "").lower()


def test_require_account_state_maps_unverified_user_error() -> None:
    """Unverified-user failures are translated to the stable client-facing code."""
    manager = MagicMock()
    manager.require_account_state.side_effect = oauth_service_module.UnverifiedUserError()

    with pytest.raises(ClientException) as exc_info:
        _require_account_state(ExampleUser(id=uuid4(), email="user@example.com"), user_manager=manager)

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.LOGIN_USER_NOT_VERIFIED


def test_require_account_state_rejects_inactive_guarded_user_without_validator() -> None:
    """Guarded users still hit inactive-user mapping when no validator is configured."""
    manager = MagicMock()
    manager.require_account_state = None

    with pytest.raises(ClientException) as exc_info:
        _require_account_state(
            ExampleUser(id=uuid4(), email="inactive@example.com", is_active=False),
            user_manager=manager,
        )

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.LOGIN_USER_INACTIVE


def test_require_account_state_allows_active_guarded_user_without_validator() -> None:
    """Active guarded users pass the attribute-based fallback when no validator exists."""
    manager = MagicMock()
    manager.require_account_state = None

    _require_account_state(
        ExampleUser(id=uuid4(), email="active@example.com", is_active=True),
        user_manager=manager,
    )


async def test_complete_login_maps_inactive_user_to_client_error() -> None:
    """Account-state failures still surface the stable inactive-user client error."""
    inactive_user = ExampleUser(id=uuid4(), email="inactive@example.com", is_active=False)
    manager = _build_manager()
    manager.oauth_account_store.get_by_oauth_account.return_value = inactive_user
    manager.require_account_state.side_effect = oauth_service_module.InactiveUserError()
    oauth_client = AsyncMock()
    oauth_client.get_access_token.return_value = {"access_token": "provider-access-token"}
    oauth_client.get_id_email.return_value = ("provider-user", "inactive@example.com")
    oauth_client.get_email_verified.return_value = True
    service = OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
    )

    with pytest.raises(ClientException) as exc_info:
        await service.complete_login(
            code="provider-code",
            redirect_uri="https://app.example/callback",
            user_manager=manager,
        )

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.LOGIN_USER_INACTIVE
    manager.oauth_account_store.upsert_oauth_account.assert_not_awaited()


def test_validate_existing_email_link_policy_rejects_association_without_provider_trust() -> None:
    """Association by email is rejected unless provider verification is trusted."""
    service = OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(AsyncMock()),
        associate_by_email=True,
    )

    with pytest.raises(ClientException) as exc_info:
        service._validate_existing_email_link_policy(email_verified=True)

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_USER_ALREADY_EXISTS


def test_validate_existing_email_link_policy_rejects_unverified_email_in_trusted_mode() -> None:
    """Trusted association still requires an explicit verified-email signal."""
    service = OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(AsyncMock()),
        associate_by_email=True,
        trust_provider_email_verified=True,
    )

    with pytest.raises(ClientException) as exc_info:
        service._validate_existing_email_link_policy(email_verified=False)

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_EMAIL_NOT_VERIFIED


def test_validate_existing_email_link_policy_rejects_when_association_disabled() -> None:
    """Existing email collisions remain rejected when association by email is disabled."""
    service = OAuthService(provider_name="github", client=OAuthClientAdapter(AsyncMock()))

    with pytest.raises(ClientException) as exc_info:
        service._validate_existing_email_link_policy(email_verified=True)

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_USER_ALREADY_EXISTS


def test_validate_existing_email_link_policy_allows_verified_association() -> None:
    """Verified emails can be linked when the provider signal is trusted."""
    service = OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(AsyncMock()),
        associate_by_email=True,
        trust_provider_email_verified=True,
    )

    service._validate_existing_email_link_policy(email_verified=True)


async def test_associate_account_rejects_cross_user_link() -> None:
    """Associate flow preserves the stable linked-account client error for cross-user collisions."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    other_user = ExampleUser(id=uuid4(), email="other@example.com")
    manager = _build_manager()
    manager.oauth_account_store.get_by_oauth_account.return_value = other_user
    oauth_client = AsyncMock()
    oauth_client.get_access_token.return_value = {"access_token": "provider-access-token"}
    oauth_client.get_id_email.return_value = ("provider-user", "user@example.com")
    service = OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
    )

    with pytest.raises(ClientException) as exc_info:
        await service.associate_account(
            user=user,
            code="provider-code",
            redirect_uri="https://app.example/callback",
            user_manager=manager,
        )

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED
    manager.oauth_account_store.upsert_oauth_account.assert_not_awaited()


@pytest.mark.parametrize(
    ("current_user_id", "existing_owner_id"),
    [
        pytest.param(None, None, id="both-none"),
        pytest.param(uuid4(), None, id="existing-owner-none"),
        pytest.param(None, uuid4(), id="current-user-none"),
    ],
)
async def test_associate_account_rejects_when_either_id_is_none(
    *,
    current_user_id: UUID | None,
    existing_owner_id: UUID | None,
) -> None:
    """Associate flow never treats ``id=None`` as a match, even when both sides are None."""
    user = MagicMock()
    user.id = current_user_id
    existing_owner = MagicMock()
    existing_owner.id = existing_owner_id
    manager = _build_manager()
    manager.oauth_account_store.get_by_oauth_account.return_value = existing_owner
    oauth_client = AsyncMock()
    oauth_client.get_access_token.return_value = {"access_token": "provider-access-token"}
    oauth_client.get_id_email.return_value = ("provider-user", "user@example.com")
    service = OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
    )

    with pytest.raises(ClientException) as exc_info:
        await service.associate_account(
            user=user,
            code="provider-code",
            redirect_uri="https://app.example/callback",
            user_manager=manager,
        )

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED
    manager.oauth_account_store.upsert_oauth_account.assert_not_awaited()


async def test_associate_account_links_provider_for_current_user() -> None:
    """Associate flow persists the provider account when there is no cross-user collision."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager()
    oauth_client = AsyncMock()
    oauth_client.get_access_token.return_value = {
        "access_token": "provider-access-token",
        "expires_at": 456,
        "refresh_token": "provider-refresh-token",
    }
    oauth_client.get_id_email.return_value = ("provider-user", "user@example.com")
    service = OAuthService(provider_name="github", client=OAuthClientAdapter(oauth_client))

    await service.associate_account(
        user=user,
        code="provider-code",
        redirect_uri="https://app.example/callback",
        user_manager=manager,
    )

    manager.oauth_account_store.upsert_oauth_account.assert_awaited_once_with(
        user,
        oauth_name="github",
        account_id="provider-user",
        account_email="user@example.com",
        access_token="provider-access-token",
        expires_at=456,
        refresh_token="provider-refresh-token",
    )


async def test_associate_account_maps_store_link_conflict_to_client_error() -> None:
    """Store-level linked-account conflicts keep the stable client-facing error."""
    user = ExampleUser(id=uuid4(), email="user@example.com")
    manager = _build_manager()
    manager.oauth_account_store.upsert_oauth_account.side_effect = oauth_service_module.OAuthAccountAlreadyLinkedError(
        provider="github",
        account_id="provider-user",
        existing_user_id=user.id,
    )
    oauth_client = AsyncMock()
    oauth_client.get_access_token.return_value = {
        "access_token": "provider-access-token",
        "expires_at": None,
        "refresh_token": None,
    }
    oauth_client.get_id_email.return_value = ("provider-user", "user@example.com")
    service = OAuthService(provider_name="github", client=OAuthClientAdapter(oauth_client))

    with pytest.raises(ClientException) as exc_info:
        await service.associate_account(
            user=user,
            code="provider-code",
            redirect_uri="https://app.example/callback",
            user_manager=manager,
        )

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_ACCOUNT_ALREADY_LINKED


async def test_complete_login_requires_explicit_oauth_account_store() -> None:
    """OAuth service fails loudly when the manager is missing the split OAuth store boundary."""
    manager = _build_manager()
    manager.oauth_account_store = None
    oauth_client = AsyncMock()
    oauth_client.get_access_token.return_value = {"access_token": "provider-access-token"}
    oauth_client.get_id_email.return_value = ("provider-user", "oauth@example.com")
    oauth_client.get_email_verified.return_value = True
    service = OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
    )

    with pytest.raises(TypeError, match="oauth_account_store"):
        await service.complete_login(
            code="provider-code",
            redirect_uri="https://app.example/callback",
            user_manager=manager,
        )


def test_require_oauth_account_store_returns_explicit_store() -> None:
    """OAuth-account store helper returns the configured store contract."""
    manager = _build_manager()

    assert _require_oauth_account_store(manager) is manager.oauth_account_store


def test_resolve_account_state_validator_returns_callable_only() -> None:
    """Only callable account-state validators are exposed."""
    callable_manager = MagicMock()
    callable_validator = MagicMock()
    callable_manager.require_account_state = callable_validator
    non_callable_manager = MagicMock()
    non_callable_manager.require_account_state = "not-callable"

    assert _resolve_account_state_validator(callable_manager) is callable_validator
    assert _resolve_account_state_validator(non_callable_manager) is None
