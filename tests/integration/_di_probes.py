"""Shared Litestar DI probe annotations for integration tests.

Litestar 2.22+ requires explicit parameter markers for query/path/DI in many cases.
Integration probes additionally avoid typing pitfalls discovered in this suite:

- Do not annotate handlers with ``LitestarAuthConfig[User, ID]`` inside
  ``Annotated[..., Dependency()]``; msgspec signature evaluation can raise
  ``NameError`` for PEP 695 type parameters.
- Prefer ``@runtime_checkable`` protocols or ``object`` for fake DB sessions when
  the handler only forwards the session to assertions.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Protocol, runtime_checkable
from uuid import UUID

from litestar.params import Dependency

from litestar_auth.authentication.backend import AuthenticationBackend
from tests.integration.test_orchestrator import ExampleUser, PluginUserManager

LitestarAuthUserManagerProbe = Annotated[PluginUserManager, Dependency()]
LitestarAuthBackendsProbe = Annotated[Sequence[AuthenticationBackend[ExampleUser, UUID]], Dependency()]
LitestarAuthUserModelProbe = Annotated[type[ExampleUser], Dependency()]
LitestarAuthConfigProbe = object


@runtime_checkable
class SessionIdentityProbe(Protocol):
    """Minimal session shape used by lifecycle contract probes."""

    session_id: int


DbSessionIdentityProbe = Annotated[SessionIdentityProbe, Dependency()]
