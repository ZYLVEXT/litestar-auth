# Cookbook: API keys

This recipe enables user-owned API keys for a Litestar app, protects one route with a scope, and shows the two supported
client credential forms.

## Server setup

```python
from litestar import Litestar, get

from litestar_auth import ApiKeyConfig, LitestarAuth, LitestarAuthConfig
from litestar_auth.guards import has_scope, requires_api_key
from litestar_auth.manager import UserManagerSecurity


@get("/reports", guards=[requires_api_key, has_scope("reports:read")])
async def reports() -> dict[str, bool]:
    return {"ok": True}


config = LitestarAuthConfig(
    user_model=User,
    user_manager_class=UserManager,
    session_maker=session_maker,
    backends=[jwt_backend],
    api_keys=ApiKeyConfig(
        enabled=True,
        allowed_scopes=("reports:read", "reports:write"),
        max_keys_per_user=5,
    ),
    user_manager_security=UserManagerSecurity(
        api_key_hash_secret="generate-a-distinct-32-byte-secret",
        verification_token_secret="generate-a-different-secret",
        reset_password_token_secret="generate-another-secret",
    ),
)

app = Litestar(route_handlers=[reports], plugins=[LitestarAuth(config)])
```

## Create the key

```bash
curl -X POST "https://api.example.com/api-keys" \
  -H "Authorization: Bearer $USER_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "reports export",
    "current_password": "'"$CURRENT_PASSWORD"'",
    "scopes": ["reports:read"]
  }'
```

The raw `api_key` appears only in this create response. Store it in the client secret manager and display only the
returned metadata later.

## Call the scoped route

```bash
curl "https://api.example.com/reports" \
  -H "Authorization: Bearer $API_KEY"
```

or:

```bash
curl "https://api.example.com/reports" \
  -H "X-API-Key: $API_KEY"
```

## Revoke a key

```bash
curl -X DELETE "https://api.example.com/api-keys/$KEY_ID" \
  -H "Authorization: Bearer $USER_ACCESS_TOKEN"
```

Create, update, and revoke operations require `requires_password_session`, so an API key cannot maintain the user's key
inventory by itself.
