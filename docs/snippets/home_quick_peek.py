"""Home-page quick peek: plugin wiring (placeholders). Included via pymdownx.snippets."""

from litestar import Litestar
from litestar_auth import LitestarAuth, LitestarAuthConfig
from litestar_auth.authentication.backend import AuthenticationBackend
from litestar_auth.authentication.strategy import JWTStrategy
from litestar_auth.authentication.transport import BearerTransport

config = LitestarAuthConfig(
    backends=(
        AuthenticationBackend(
            name="jwt",
            transport=BearerTransport(),
            strategy=JWTStrategy(secret="...", subject_decoder=YourIdType),
        ),
    ),
    user_model=YourUser,
    user_manager_class=YourUserManager,
    session_maker=async_session_factory,
)
app = Litestar(plugins=[LitestarAuth(config)])
