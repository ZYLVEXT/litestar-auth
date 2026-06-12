"""Shared concurrency limits for expensive authentication work.

Password hashing and recovery-code hashing use memory-hard Argon2 work. The
shared password-operation worker limiter caps concurrent operations per event
loop (one loop per process for typical servers); worst-case Argon2 memory is
roughly ``PASSWORD_WORKER_THREAD_LIMIT * Argon2 memory cost`` per loop. With
the bundled default pwdlib policy, that is the resolved limit times about
64 MiB. The limiter is loop-scoped because AnyIO capacity limiters hold
loop-bound waiter events and must not be shared across event loops.
"""

from __future__ import annotations

import secrets
from os import environ
from threading import Lock as ThreadLock
from typing import TYPE_CHECKING
from weakref import WeakKeyDictionary

from anyio import CapacityLimiter
from anyio.lowlevel import RunVar
from anyio.to_thread import run_sync as _run_sync_in_worker_thread

from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Callable

    from litestar_auth.password import PasswordHelper

_DEFAULT_PASSWORD_WORKER_THREAD_LIMIT = 8
_PASSWORD_WORKER_THREAD_LIMIT_ENV_VAR = "LITESTAR_AUTH_PASSWORD_WORKER_THREAD_LIMIT"  # noqa: S105


def _resolve_password_worker_thread_limit(raw_limit: str | None) -> int:
    """Resolve the password worker-thread cap from optional environment input.

    Returns:
        Positive worker-thread limit.

    Raises:
        ConfigurationError: If the configured limit is not a positive integer.
    """
    if raw_limit is None:
        return _DEFAULT_PASSWORD_WORKER_THREAD_LIMIT

    msg = f"{_PASSWORD_WORKER_THREAD_LIMIT_ENV_VAR} must be a positive integer; got {raw_limit!r}."
    try:
        limit = int(raw_limit)
    except ValueError as exc:
        raise ConfigurationError(msg) from exc

    if limit < 1:
        raise ConfigurationError(msg)
    return limit


# Maximum concurrent memory-hard password operations inside one process. Bounds
# worst-case Argon2 memory to this limit times the configured memory cost
# (pwdlib's bundled Argon2 hasher defaults to 64 MiB per operation).
PASSWORD_WORKER_THREAD_LIMIT = _resolve_password_worker_thread_limit(
    environ.get(_PASSWORD_WORKER_THREAD_LIMIT_ENV_VAR),
)

# Loop-scoped limiter: asyncio-backed CapacityLimiter waiters are Events bound
# to the event loop that created them, so one limiter must never serve two loops.
_PASSWORD_OP_LIMITER: RunVar[CapacityLimiter] = RunVar("litestar_auth_password_op_limiter")
_DUMMY_HASH_CACHE: WeakKeyDictionary[PasswordHelper, str] = WeakKeyDictionary()
_DUMMY_HASH_CACHE_GUARD = ThreadLock()


def _password_op_limiter() -> CapacityLimiter:
    """Return the current event loop's password-operation capacity limiter.

    Returns:
        The loop-scoped limiter, created on first use within the running loop.
    """
    try:
        return _PASSWORD_OP_LIMITER.get()
    except LookupError:
        limiter = CapacityLimiter(PASSWORD_WORKER_THREAD_LIMIT)
        _PASSWORD_OP_LIMITER.set(limiter)
        return limiter


def build_dummy_hash(password_helper: PasswordHelper) -> str:
    """Return a freshly salted dummy password hash for timing equalization."""
    return password_helper.hash(secrets.token_urlsafe(32))


def _cached_dummy_hash(password_helper: PasswordHelper) -> str | None:
    """Return a cached dummy hash without keeping the helper alive."""
    with _DUMMY_HASH_CACHE_GUARD:
        return _DUMMY_HASH_CACHE.get(password_helper)


def _cache_dummy_hash(password_helper: PasswordHelper, dummy_hash: str) -> None:
    """Store the helper-scoped dummy hash after worker-thread construction."""
    with _DUMMY_HASH_CACHE_GUARD:
        _DUMMY_HASH_CACHE[password_helper] = dummy_hash


async def run_password_op_in_worker_thread[T](func: Callable[..., T], *args: object) -> T:
    """Run memory-hard password work in AnyIO's worker pool with a dedicated cap.

    Returns:
        The callable result.
    """
    return await _run_sync_in_worker_thread(func, *args, limiter=_password_op_limiter())


async def get_cached_dummy_hash(password_helper: PasswordHelper) -> str:
    """Return the per-helper dummy hash used to equalize unknown-secret checks."""
    cached_hash = _cached_dummy_hash(password_helper)
    if cached_hash is not None:
        return cached_hash

    dummy_hash = await run_password_op_in_worker_thread(build_dummy_hash, password_helper)
    _cache_dummy_hash(password_helper, dummy_hash)
    return dummy_hash
