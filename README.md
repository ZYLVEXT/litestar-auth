# litestar-auth

Authentication and authorization for [Litestar](https://litestar.dev/) applications: registration, login, email verification, password reset, OAuth2, TOTP (2FA), route guards, and optional rate limiting—wired as a Litestar **plugin** with **transport + strategy** backends.

---

<p align="center">

  <a href="https://github.com/ZYLVEXT/litestar-auth/actions/workflows/1_test.yml" target="_blank">
    <img src="https://github.com/ZYLVEXT/litestar-auth/actions/workflows/1_test.yml/badge.svg?branch=main" alt="Test Passing"/>
  </a>

  <a href="https://codecov.io/gh/ZYLVEXT/litestar-auth" target="_blank">
    <img src="https://codecov.io/gh/ZYLVEXT/litestar-auth/branch/main/graph/badge.svg" alt="Coverage"/>
  </a>

  <a href="https://www.pepy.tech/projects/litestar-auth" target="_blank">
    <img src="https://static.pepy.tech/personalized-badge/litestar-auth?period=month&units=international_system&left_color=grey&right_color=green&left_text=downloads/month" alt="Downloads"/>
  </a>

  <a href="https://pypi.org/project/litestar-auth" target="_blank">
    <img src="https://img.shields.io/pypi/v/litestar-auth.svg?label=PyPI" alt="Package version"/>
  </a>

  <a href="https://pypi.org/project/litestar-auth" target="_blank">
    <img src="https://img.shields.io/pypi/pyversions/litestar-auth.svg" alt="Supported Python versions"/>
  </a>

  <a href="https://github.com/ZYLVEXT/litestar-auth/blob/main/LICENSE" target="_blank">
    <img src="https://img.shields.io/github/license/ZYLVEXT/litestar-auth.svg" alt="License"/>
  </a>

  <a href="https://zylvext.github.io/litestar-auth/" target="_blank">
    <img src="https://img.shields.io/badge/docs-online-green.svg" alt="Documentation"/>
  </a>

</p>

---

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
