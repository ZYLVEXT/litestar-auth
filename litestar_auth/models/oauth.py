"""OAuth account ORM model (import without loading :class:`~litestar_auth.models.user.User`).

Import :class:`OAuthAccount` from this submodule when you reuse the library OAuth table
contract with a **custom** user model mapped to ``user`` — loading
``litestar_auth.models.user`` would register the reference :class:`~litestar_auth.models.user.User`
mapper and can conflict with your app model on the same table.
"""

from __future__ import annotations

from advanced_alchemy.base import UUIDBase

from litestar_auth.models.mixins import OAuthAccountMixin


class OAuthAccount(OAuthAccountMixin, UUIDBase):
    """OAuth account linked to a local user.

    Provider identity (oauth_name, account_id) is globally unique: one provider
    identity can only be linked to one local user. Enforced at the persistence
    layer via UniqueConstraint and upsert logic.

    The ``user`` relationship targets the declarative class named ``User`` in the
    same registry (the bundled :class:`~litestar_auth.models.user.User` or your
    replacement). The default inverse side lives in
    :class:`~litestar_auth.models.mixins.UserAuthRelationshipMixin`.
    Configure ``foreign_keys`` / ``overlaps`` on subclasses if you remap
    relationships (see the custom user + OAuth cookbook).
    """

    __tablename__ = "oauth_account"
