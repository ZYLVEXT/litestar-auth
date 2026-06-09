# External Extension Demo

This example is the in-repo authoring template for an externally distributed
`litestar-auth` extension package. The extension code lives in `extension.py` and imports extension
contracts only from `litestar_auth.extensions`, which is the supported public facade for out-of-tree
extension authors.

The demo package name is `examples.demo_external_extension` because it ships in this repository.
Real extension distributions should use the `litestar_auth_ext_*` naming convention, for example
`litestar_auth_ext_audit`.

## Run The Demo

```bash
LITESTAR_AUTH_DEMO_EXTERNAL_EXTENSION_INSECURE=1 uv run python -m examples.demo_external_extension
```

Or run the ASGI app directly:

```bash
LITESTAR_AUTH_DEMO_EXTERNAL_EXTENSION_INSECURE=1 uv run uvicorn examples.demo_external_extension.app:app --host 127.0.0.1 --port 8000
```

The contributed route is:

```text
GET /demo/external-extension/status
```

## Explicit Registration

Applications can register an extension instance directly:

```python
from litestar_auth import LitestarAuthConfig
from litestar_auth.models import User
from litestar_auth_ext_audit import AuditExtension

config = LitestarAuthConfig(
    user_model=User,
    extensions=(AuditExtension(),),
)
```

This demo uses the same explicit path in `app.py`:

```python
LitestarAuthConfig(
    ...,
    extensions=(demo_external_extension,),
)
```

## Entry-Point Registration

External distributions can also expose an extension object, class, or zero-argument factory from the
canonical `litestar_auth.extensions` entry-point group:

```toml
[project]
name = "litestar_auth_ext_audit"

[project.entry-points."litestar_auth.extensions"]
audit = "litestar_auth_ext_audit:AuditExtension"
```

Applications opt into discovery explicitly:

```python
config = LitestarAuthConfig(
    user_model=User,
    auto_discover_extensions=True,
)
```

This repository intentionally does not declare that entry point in `pyproject.toml`; doing so would
make the example self-discoverable instead of modeling how a separately shipped extension package is
installed.
