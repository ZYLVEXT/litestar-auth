"""Payment HTTP Message Signature verifier."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from authweave_core import SecurityOperation, SecurityOutcome, observe_security
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from http_message_signatures import (
    HTTPMessageVerifier,
    HTTPSignatureKeyResolver,
    InvalidSignature,
    algorithms,
    http_sfv,
)
from http_message_signatures.structures import CaseInsensitiveDict

from authweave_http_signatures.digest import verify_content_digest
from authweave_http_signatures.errors import HttpSignatureFailureCode, HttpSignatureVerificationError
from authweave_http_signatures.models import VerifiedHttpSignature

if TYPE_CHECKING:
    from authweave_core import AuthenticationContext, SecurityObserver, TraceCorrelation

    from authweave_http_signatures.binding import SignatureKeyBinding
    from authweave_http_signatures.models import HttpMessageView, PaymentSignaturePolicy
    from authweave_http_signatures.nonce import SignatureNonceGuard


@dataclass
class _MessageAdapter:
    method: str
    url: str = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)


class _PublicKeyResolver(HTTPSignatureKeyResolver):
    def __init__(self, keys: Mapping[str, Ed25519PublicKey]) -> None:
        self._keys = keys

    def resolve_public_key(self, key_id: str) -> Ed25519PublicKey:
        try:
            return self._keys[key_id]
        except KeyError as exc:
            msg = "unknown key id"
            raise KeyError(msg) from exc

    def resolve_private_key(self, key_id: str) -> Ed25519PublicKey:
        raise KeyError(key_id)


class _ProfileHTTPMessageVerifier(HTTPMessageVerifier):
    """Delegate parsing/crypto while AuthWeave owns request-local time policy."""

    def validate_created_and_expires(
        self,
        sig_input: Any,
        max_age: timedelta | None = None,
    ) -> None:
        """Skip the upstream process-global wall clock check.

        AuthWeave validates required ``created``/``expires``, lifetime, expiry,
        future time, and configured skew immediately after signature verification.
        """
        _ = self, sig_input, max_age


class PaymentHttpSignatureVerifier:
    """Verify Content-Digest + RFC 9421 signature for profile v1."""

    __slots__ = ("_bindings", "_nonce_guard", "_observer", "_policy", "_public_keys", "_time_source")

    def __init__(
        self,
        *,
        policy: PaymentSignaturePolicy,
        public_keys: Mapping[str, Ed25519PublicKey],
        bindings: Mapping[str, SignatureKeyBinding],
        nonce_guard: SignatureNonceGuard,
        time_source: Callable[[], datetime] | None = None,
        observer: SecurityObserver | None = None,
    ) -> None:
        """Bind profile policy, public keys, ownership, and nonce store."""
        if not public_keys or not bindings:
            msg = "public keys and bindings are required"
            raise ValueError(msg)
        self._policy = policy
        self._public_keys = dict(public_keys)
        self._bindings = dict(bindings)
        self._nonce_guard = nonce_guard
        self._time_source = time_source or (lambda: datetime.now(UTC))
        self._observer = observer

    async def verify(
        self,
        view: HttpMessageView,
        *,
        context: AuthenticationContext,
        links: Sequence[TraceCorrelation] = (),
    ) -> VerifiedHttpSignature:
        """Verify digest, signature, key binding, and nonce fail-closed.

        Returns:
            A secret-free verified integrity envelope retaining the exact body.

        Raises:
            HttpSignatureVerificationError: On any integrity failure.
        """
        with observe_security(
            self._observer,
            SecurityOperation.VERIFY_HTTP_SIGNATURE,
            profile=self._policy.profile_tag,
            credential_kind="http_message_signature",
            links=links,
        ) as observation:
            try:
                result = await self._verify(view, context=context)
            except HttpSignatureVerificationError as exc:
                outcome = (
                    SecurityOutcome.UNAVAILABLE
                    if exc.code is HttpSignatureFailureCode.STORE_UNAVAILABLE
                    else SecurityOutcome.INVALID
                )
                observation.set_outcome(outcome, reason_code=exc.code.value)
                raise
            observation.set_outcome(SecurityOutcome.VERIFIED)
            return result

    async def _verify(self, view: HttpMessageView, *, context: AuthenticationContext) -> VerifiedHttpSignature:
        self._check_body_and_encoding(view)
        self._check_query(view.target_uri)
        content_type = self._require_header(view, "content-type")
        if content_type.lower() not in {item.lower() for item in self._policy.json_media_types}:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.CONTENT_TYPE_REJECTED)
        idempotency_key = self._require_header(view, "idempotency-key")
        digest = self._require_header(view, "content-digest")
        verify_content_digest(header_value=digest, body=view.body)
        if self._policy.require_authorization_component:
            self._require_header(view, "authorization")
        signature_input = self._require_header(view, "signature-input")
        signature = self._require_header(view, "signature")
        self._assert_single_profile_signature(signature_input=signature_input, signature=signature)
        headers = CaseInsensitiveDict(dict(view.headers_dict().items()))
        adapter = _MessageAdapter(method=view.method, url=view.target_uri, headers=headers)
        verifier = _ProfileHTTPMessageVerifier(
            signature_algorithm=algorithms.ED25519,
            key_resolver=_PublicKeyResolver(self._public_keys),
        )
        try:
            results = verifier.verify(
                adapter,
                max_age=timedelta(seconds=self._policy.max_signature_lifetime_seconds),
                expect_tag=self._policy.profile_tag,
                expect_label=self._policy.signature_label,
            )
        except InvalidSignature as exc:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.SIGNATURE_INVALID) from exc
        except Exception as exc:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED) from exc
        if len(results) != 1:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED)
        result = results[0]
        params = dict(result.parameters)
        key_id = params.get("keyid")
        nonce = params.get("nonce")
        created = params.get("created")
        expires = params.get("expires")
        tag = params.get("tag")
        if not isinstance(key_id, str) or not isinstance(nonce, str) or tag != self._policy.profile_tag:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.PROFILE_MISMATCH)
        created_i = _structured_field_integer(created)
        expires_i = _structured_field_integer(expires)
        if created_i is None or expires_i is None:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED)
        now = int(self._time_source().timestamp())
        if created_i > now + self._policy.max_clock_skew_seconds:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.NOT_YET_VALID)
        if expires_i <= now - self._policy.max_clock_skew_seconds:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.SIGNATURE_EXPIRED)
        if expires_i <= created_i or expires_i - created_i > self._policy.max_signature_lifetime_seconds:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED)
        covered = tuple(
            key.strip('"') for key in result.covered_components if str(key).strip('"') != "@signature-params"
        )
        if covered != self._policy.covered_components:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.PROFILE_MISMATCH)
        binding = self._bindings.get(key_id)
        if binding is None:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.KEY_BINDING_MISMATCH)
        binding.assert_matches(context)
        await self._nonce_guard.consume(key_id=key_id, nonce=nonce, observer=self._observer)
        return VerifiedHttpSignature(
            key_id=key_id,
            nonce=nonce,
            profile_tag=self._policy.profile_tag,
            created=created_i,
            expires=expires_i,
            idempotency_key=idempotency_key,
            content_type=content_type,
            body=view.body,
        )

    def _check_body_and_encoding(self, view: HttpMessageView) -> None:
        if len(view.body) > self._policy.max_body_bytes:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.BODY_TOO_LARGE)
        encoding = view.header("content-encoding")
        if encoding is not None and encoding.lower() not in {"", "identity"}:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.CONTENT_ENCODING_REJECTED)

    def _check_query(self, target_uri: str) -> None:
        if self._policy.allow_query:
            return
        if urlsplit(target_uri).query:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.QUERY_REJECTED)

    def _assert_single_profile_signature(self, *, signature_input: str, signature: str) -> None:
        """Require exactly one SF dictionary member equal to the profile label.

        Upstream parsers collapse duplicate keys; count top-level members so
        ``label=..., label=...`` cannot silently overwrite.
        """
        label = self._policy.signature_label
        if _sf_dictionary_member_count(signature_input) != 1 or _sf_dictionary_member_count(signature) != 1:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED)
        try:
            input_node = http_sfv.Dictionary()
            input_node.parse(signature_input.encode("ascii"))
            signature_node = http_sfv.Dictionary()
            signature_node.parse(signature.encode("ascii"))
        except Exception as exc:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED) from exc
        if list(input_node.keys()) != [label] or list(signature_node.keys()) != [label]:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.PROFILE_MISMATCH)

    @staticmethod
    def _require_header(view: HttpMessageView, name: str) -> str:
        try:
            value = view.header(name)
        except ValueError as exc:
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.MALFORMED) from exc
        if value is None or not value.strip():
            raise HttpSignatureVerificationError(HttpSignatureFailureCode.MISSING_COMPONENT)
        return value


def _sf_dictionary_member_count(raw: str) -> int:
    """Count RFC 8941 dictionary members separated by top-level commas."""
    text = raw.strip()
    if not text:
        return 0
    depth = 0
    in_string = False
    escape = False
    members = 1
    for char in text:
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "(":
            depth += 1
        elif char == ")" and depth:
            depth -= 1
        elif char == "," and depth == 0:
            members += 1
    return members


def _structured_field_integer(value: object) -> int | None:
    """Accept only RFC 8941 Integer values, excluding Python ``bool``."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None
