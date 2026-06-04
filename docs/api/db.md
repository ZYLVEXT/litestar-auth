# Database adapters

The **`litestar_auth.db`** package exposes only the abstract persistence contracts and their lightweight data payloads: **`BaseUserStore`**, **`BaseOAuthAccountStore`**, **`BaseApiKeyStore`**, **`BaseOrganizationStore`**, **`OAuthAccountData`**, **`ApiKeyData`**, **`OrganizationData`**, **`MembershipData`**, and **`OrganizationInvitationData`**. These protocols describe how the user manager and optional feature surfaces talk to your storage layer without tying the library to a particular ORM.

The concrete **SQLAlchemy** implementations live in a dedicated submodule: import **`SQLAlchemyUserDatabase`**, **`SQLAlchemyApiKeyStore`**, and **`SQLAlchemyOrganizationStore`** from **`litestar_auth.db.sqlalchemy`**. They are **not** re-exported from `litestar_auth.db` on purpose—eagerly importing the adapter would register SQLAlchemy mappers and break the lazy-import boundary described in the project guide. Use the submodule when you are ready to wire real tables.

For end-to-end ORM setup (session maker, models, plugin config), see [User and manager](../configuration/user_and_manager.md), [Backends](../configuration/backends.md), and [Organizations](../configuration/organizations.md); the [Configuration index](../configuration.md) lists every split reference page. For customizing the user table while keeping OAuth accounts on the bundled model, see [Custom user + OAuth](../cookbook/custom_user_oauth.md).

```python
from litestar_auth.db.sqlalchemy import SQLAlchemyUserDatabase
from litestar_auth.db.sqlalchemy import SQLAlchemyApiKeyStore
from litestar_auth.db.sqlalchemy import SQLAlchemyOrganizationStore
```

## Organization persistence

Use `BaseOrganizationStore[ORG, MEMBERSHIP, INVITATION, ID]` for custom organization backends. The protocol
supports organization create/get/get-by-slug operations, exact membership add/get/list/remove
operations, atomic membership remove/role-update operations that preserve at least one privileged member,
listing organizations for a user, and email-scoped invitation create/get/list/revoke/consume
operations that store only a hashed token reference. Membership, user-organization, and pending-invitation list
methods are paginated store calls: they accept keyword-only `offset` and `limit` arguments and return
`(items, total)`, where `total` is the count of the full filtered result set.

```python
from litestar_auth.db import BaseOrganizationStore, MembershipData, OrganizationData, OrganizationInvitationData
```

Use `SQLAlchemyOrganizationStore` when the bundled SQLAlchemy adapter matches your model family:

```python
from sqlalchemy.ext.asyncio import AsyncSession

from litestar_auth.db.sqlalchemy import SQLAlchemyOrganizationStore
from litestar_auth.models import Organization, OrganizationInvitation, OrganizationMembership


def create_store(session: AsyncSession) -> SQLAlchemyOrganizationStore:
    return SQLAlchemyOrganizationStore(
        session,
        organization_model=Organization,
        membership_model=OrganizationMembership,
        invitation_model=OrganizationInvitation,
    )
```

The adapter requires explicit `organization_model` and `membership_model` arguments. Invitation methods additionally
require `invitation_model`, and fail with `TypeError` when it is omitted. Organization
models remain lazy exports from `litestar_auth.models`; they are not exposed by `litestar_auth.db`.

::: litestar_auth.db
