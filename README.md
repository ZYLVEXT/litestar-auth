# litestar-auth

Authentication and authorization for [Litestar](https://litestar.dev/) applications: registration, login, email verification, password reset, OAuth2, TOTP (2FA), route guards, and optional rate limiting—wired as a Litestar **plugin** with **transport + strategy** backends.

**Documentation:** [https://zylvext.github.io/litestar-auth/](https://zylvext.github.io/litestar-auth/)

## Install

```bash
uv add litestar-auth
# or: pip install litestar-auth
```

Optional extras: `redis`, `oauth`, `totp`, or `all` — see the [installation guide](docs/install.md).

## Quickstart

Follow [docs/quickstart.md](docs/quickstart.md) for a minimal Bearer + JWT setup with the default SQLAlchemy user model.

## Repository

Contributing, local docs build, and verification commands are described in [docs/contributing.md](docs/contributing.md).
