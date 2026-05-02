"""Unit tests for OAuth flow orchestration service."""

from __future__ import annotations

from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest
from litestar.exceptions import ClientException, PermissionDeniedException

import litestar_auth.oauth._pkce as pkce_module
import litestar_auth.oauth.service as oauth_service_module
from litestar_auth.db import OAuthAccountData
from litestar_auth.exceptions import AuthenticationError, ErrorCode
from litestar_auth.oauth.client_adapter import OAuthClientAdapter
from tests._helpers import ExampleUser
from tests.unit.test_definition_file_coverage import load_reloaded_test_alias

pytestmark = pytest.mark.unit
_PKCE_UNRESERVED_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PKCE_MIN_VERIFIER_LENGTH = 43
_PKCE_MAX_VERIFIER_LENGTH = 128
_FIXED_PKCE_VERIFIER = "A" * 64


class _RecordingOAuthClientAdapter:
    """Capture authorization URL calls made by the service."""

    def __init__(self, *, authorization_url: str = "https://provider.example/authorize") -> None:
        self.authorization_url = authorization_url
        self.authorization_calls: list[dict[str, object]] = []

    async def get_authorization_url(
        self,
        *,
        redirect_uri: str,
        state: str,
        scopes: list[str] | None = None,
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
    ) -> str:
        """Record authorization material and return a stable provider URL.

        Returns:
            Configured provider authorization URL.
        """
        self.authorization_calls.append(
            {
                "redirect_uri": redirect_uri,
                "state": state,
                "scopes": scopes,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
            },
        )
        return self.authorization_url


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

    assert reloaded_module.OAuthService.__name__ == oauth_service_module.OAuthService.__name__
    assert reloaded_module.OAuthAuthorization.__name__ == "OAuthAuthorization"
    assert type(exc_info.value).__name__ == "ConfigurationError"
    assert getattr(exc_info.value, "code", None) == ErrorCode.CONFIGURATION_INVALID
    extra = client_exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.LOGIN_USER_INACTIVE
    assert client_exc_info.value.detail == reloaded_module.InactiveUserError.default_message


def test_pkce_module_reload_preserves_generation_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reload coverage keeps the extracted PKCE primitives exercised under coverage."""
    assert pkce_module.__file__ is not None
    reloaded_module = load_reloaded_test_alias(
        alias_name="_coverage_alias_oauth_pkce",
        source_path=Path(pkce_module.__file__).resolve(),
        monkeypatch=monkeypatch,
    )
    monkeypatch.setattr(reloaded_module.secrets, "token_urlsafe", lambda _size: _FIXED_PKCE_VERIFIER)

    pkce = reloaded_module._generate_pkce_material()

    assert pkce.__class__.__name__ == "PkceMaterial"
    assert pkce.code_verifier == _FIXED_PKCE_VERIFIER
    assert pkce.code_challenge == "1T7aemN8mcx_tWbZbp-hCb8VxHhBCj9etNTE4mzQgfY"
    assert pkce.code_challenge_method == "S256"


def test_generate_pkce_code_verifier_uses_unreserved_alphabet() -> None:
    """Generated PKCE verifiers use the RFC 7636 unreserved URI alphabet."""
    code_verifier = pkce_module._generate_pkce_code_verifier()

    assert _PKCE_MIN_VERIFIER_LENGTH <= len(code_verifier) <= _PKCE_MAX_VERIFIER_LENGTH
    assert set(code_verifier) <= _PKCE_UNRESERVED_ALPHABET


def test_generate_pkce_code_verifier_rejects_invalid_entropy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifier generation fails closed if the entropy source returns invalid material."""
    monkeypatch.setattr("litestar_auth.oauth._pkce.secrets.token_urlsafe", lambda _size: "!")

    with pytest.raises(RuntimeError, match="PKCE code verifier"):
        pkce_module._generate_pkce_code_verifier()


def test_build_pkce_code_challenge_matches_rfc7636_appendix_b() -> None:
    """S256 challenge generation matches the RFC 7636 Appendix B vector."""
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

    code_challenge = pkce_module._build_pkce_code_challenge(code_verifier)

    assert code_challenge == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert "=" not in code_challenge
    assert set(code_challenge) <= _PKCE_UNRESERVED_ALPHABET


async def test_authorize_returns_state_verifier_and_provider_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Authorize flow generates state and PKCE material before delegating URL construction."""
    oauth_client = _RecordingOAuthClientAdapter(
        authorization_url="https://provider.example/authorize?state=fixed-state",
    )
    service = oauth_service_module.OAuthService(
        provider_name="github",
        client=cast("OAuthClientAdapter", oauth_client),
    )
    monkeypatch.setattr(
        "litestar_auth.oauth.service.secrets.token_urlsafe",
        lambda _size: "fixed-state",
    )
    monkeypatch.setattr(
        "litestar_auth.oauth.service._generate_pkce_material",
        lambda: pkce_module.PkceMaterial(
            code_verifier=_FIXED_PKCE_VERIFIER,
            code_challenge="1T7aemN8mcx_tWbZbp-hCb8VxHhBCj9etNTE4mzQgfY",
            code_challenge_method="S256",
        ),
    )

    authorization = await service.authorize(
        redirect_uri="https://app.example/callback",
        scopes=["openid", "email"],
    )

    assert authorization.state == "fixed-state"
    assert authorization.code_verifier == _FIXED_PKCE_VERIFIER
    assert authorization.authorization_url == "https://provider.example/authorize?state=fixed-state"
    assert oauth_client.authorization_calls == [
        {
            "redirect_uri": "https://app.example/callback",
            "state": "fixed-state",
            "scopes": ["openid", "email"],
            "code_challenge": "1T7aemN8mcx_tWbZbp-hCb8VxHhBCj9etNTE4mzQgfY",
            "code_challenge_method": "S256",
        },
    ]


async def test_authorize_generates_distinct_pkce_material_per_call() -> None:
    """Each authorization flow receives fresh PKCE verifier and challenge material."""
    oauth_client = _RecordingOAuthClientAdapter()
    service = oauth_service_module.OAuthService(provider_name="github", client=cast("OAuthClientAdapter", oauth_client))

    first_authorization = await service.authorize(redirect_uri="https://app.example/callback")
    second_authorization = await service.authorize(redirect_uri="https://app.example/callback")

    assert first_authorization.code_verifier != second_authorization.code_verifier
    first_call = oauth_client.authorization_calls[0]
    second_call = oauth_client.authorization_calls[1]
    assert first_call["code_challenge"] != second_call["code_challenge"]
    assert first_call["code_challenge_method"] == "S256"
    assert second_call["code_challenge_method"] == "S256"


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
    service = oauth_service_module.OAuthService(
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
        code_verifier="pkce-code-verifier",
        user_manager=manager,
    )

    assert user is verified_user
    oauth_client.get_access_token.assert_awaited_once_with(
        "provider-code",
        "https://app.example/callback",
        code_verifier="pkce-code-verifier",
    )
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
        account=OAuthAccountData(
            oauth_name="github",
            account_id="provider-user",
            account_email="oauth@example.com",
            access_token="provider-access-token",
            expires_at=123,
            refresh_token="provider-refresh-token",
        ),
    )


async def test_complete_login_rejects_existing_email_without_association() -> None:
    """Existing email without associate-by-email preserves the stable client error."""
    existing_user = ExampleUser(id=uuid4(), email="existing@example.com")
    manager = _build_manager(existing_user=existing_user)
    oauth_client = AsyncMock()
    oauth_client.get_access_token.return_value = {"access_token": "provider-access-token"}
    oauth_client.get_id_email.return_value = ("provider-user", "existing@example.com")
    oauth_client.get_email_verified.return_value = True
    service = oauth_service_module.OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
    )

    with pytest.raises(ClientException) as exc_info:
        await service.complete_login(
            code="provider-code",
            redirect_uri="https://app.example/callback",
            code_verifier="pkce-code-verifier",
            user_manager=manager,
        )

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_USER_ALREADY_EXISTS
    manager.oauth_account_store.upsert_oauth_account.assert_not_awaited()


def test_require_provider_verification_signal_rejects_missing_signal_in_strict_mode() -> None:
    """Strict verification mode requires a provider verification signal."""
    service = oauth_service_module.OAuthService(
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
    service = oauth_service_module.OAuthService(provider_name="github", client=OAuthClientAdapter(AsyncMock()))

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
    service = oauth_service_module.OAuthService(provider_name="github", client=OAuthClientAdapter(AsyncMock()))
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
    service = oauth_service_module.OAuthService(provider_name="github", client=OAuthClientAdapter(AsyncMock()))

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
    service = oauth_service_module.OAuthService(provider_name="github", client=OAuthClientAdapter(AsyncMock()))
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
        oauth_service_module._require_account_state(_MinimalUser(), user_manager=manager)

    assert "account state" in (exc_info.value.detail or "").lower()


def test_require_account_state_maps_unverified_user_error() -> None:
    """Unverified-user failures are translated to the stable client-facing code."""
    manager = MagicMock()
    manager.require_account_state.side_effect = oauth_service_module.UnverifiedUserError()

    with pytest.raises(ClientException) as exc_info:
        oauth_service_module._require_account_state(
            ExampleUser(id=uuid4(), email="user@example.com"),
            user_manager=manager,
        )

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.LOGIN_USER_NOT_VERIFIED


def test_require_account_state_rejects_inactive_guarded_user_without_validator() -> None:
    """Guarded users still hit inactive-user mapping when no validator is configured."""
    manager = MagicMock()
    manager.require_account_state = None

    with pytest.raises(ClientException) as exc_info:
        oauth_service_module._require_account_state(
            ExampleUser(id=uuid4(), email="inactive@example.com", is_active=False),
            user_manager=manager,
        )

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.LOGIN_USER_INACTIVE


def test_require_account_state_allows_active_guarded_user_without_validator() -> None:
    """Active guarded users pass the attribute-based fallback when no validator exists."""
    manager = MagicMock()
    manager.require_account_state = None

    oauth_service_module._require_account_state(
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
    service = oauth_service_module.OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
    )

    with pytest.raises(ClientException) as exc_info:
        await service.complete_login(
            code="provider-code",
            redirect_uri="https://app.example/callback",
            code_verifier="pkce-code-verifier",
            user_manager=manager,
        )

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.LOGIN_USER_INACTIVE
    manager.oauth_account_store.upsert_oauth_account.assert_not_awaited()


def test_validate_existing_email_link_policy_rejects_association_without_provider_trust() -> None:
    """Association by email is rejected unless provider verification is trusted."""
    service = oauth_service_module.OAuthService(
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
    service = oauth_service_module.OAuthService(
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
    service = oauth_service_module.OAuthService(provider_name="github", client=OAuthClientAdapter(AsyncMock()))

    with pytest.raises(ClientException) as exc_info:
        service._validate_existing_email_link_policy(email_verified=True)

    extra = exc_info.value.extra
    assert (extra.get("code") if isinstance(extra, dict) else None) == ErrorCode.OAUTH_USER_ALREADY_EXISTS


def test_validate_existing_email_link_policy_allows_verified_association() -> None:
    """Verified emails can be linked when the provider signal is trusted."""
    service = oauth_service_module.OAuthService(
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
    service = oauth_service_module.OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
    )

    with pytest.raises(ClientException) as exc_info:
        await service.associate_account(
            user=user,
            code="provider-code",
            redirect_uri="https://app.example/callback",
            code_verifier="pkce-code-verifier",
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
    service = oauth_service_module.OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
    )

    with pytest.raises(ClientException) as exc_info:
        await service.associate_account(
            user=user,
            code="provider-code",
            redirect_uri="https://app.example/callback",
            code_verifier="pkce-code-verifier",
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
    service = oauth_service_module.OAuthService(provider_name="github", client=OAuthClientAdapter(oauth_client))

    await service.associate_account(
        user=user,
        code="provider-code",
        redirect_uri="https://app.example/callback",
        code_verifier="pkce-code-verifier",
        user_manager=manager,
    )

    oauth_client.get_access_token.assert_awaited_once_with(
        "provider-code",
        "https://app.example/callback",
        code_verifier="pkce-code-verifier",
    )
    manager.oauth_account_store.upsert_oauth_account.assert_awaited_once_with(
        user,
        account=OAuthAccountData(
            oauth_name="github",
            account_id="provider-user",
            account_email="user@example.com",
            access_token="provider-access-token",
            expires_at=456,
            refresh_token="provider-refresh-token",
        ),
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
    service = oauth_service_module.OAuthService(provider_name="github", client=OAuthClientAdapter(oauth_client))

    with pytest.raises(ClientException) as exc_info:
        await service.associate_account(
            user=user,
            code="provider-code",
            redirect_uri="https://app.example/callback",
            code_verifier="pkce-code-verifier",
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
    service = oauth_service_module.OAuthService(
        provider_name="github",
        client=OAuthClientAdapter(oauth_client),
    )

    with pytest.raises(TypeError, match="oauth_account_store"):
        await service.complete_login(
            code="provider-code",
            redirect_uri="https://app.example/callback",
            code_verifier="pkce-code-verifier",
            user_manager=manager,
        )


@pytest.mark.parametrize("code_verifier", ["", "   "])
async def test_complete_login_rejects_empty_code_verifier(code_verifier: str) -> None:
    """Login token exchange requires recoverable PKCE verifier material."""
    manager = _build_manager()
    oauth_client = AsyncMock()
    service = oauth_service_module.OAuthService(provider_name="github", client=OAuthClientAdapter(oauth_client))

    with pytest.raises(AuthenticationError, match="PKCE code verifier"):
        await service.complete_login(
            code="provider-code",
            redirect_uri="https://app.example/callback",
            code_verifier=code_verifier,
            user_manager=manager,
        )

    oauth_client.get_access_token.assert_not_awaited()


@pytest.mark.parametrize("code_verifier", ["", "   "])
async def test_associate_account_rejects_empty_code_verifier(code_verifier: str) -> None:
    """Associate token exchange requires recoverable PKCE verifier material."""
    manager = _build_manager()
    oauth_client = AsyncMock()
    service = oauth_service_module.OAuthService(provider_name="github", client=OAuthClientAdapter(oauth_client))

    with pytest.raises(AuthenticationError, match="PKCE code verifier"):
        await service.associate_account(
            user=ExampleUser(id=uuid4(), email="user@example.com"),
            code="provider-code",
            redirect_uri="https://app.example/callback",
            code_verifier=code_verifier,
            user_manager=manager,
        )

    oauth_client.get_access_token.assert_not_awaited()


def test_require_oauth_account_store_returns_explicit_store() -> None:
    """OAuth-account store helper returns the configured store contract."""
    manager = _build_manager()

    assert oauth_service_module._require_oauth_account_store(manager) is manager.oauth_account_store
