"""Opt-in contrib package.

The root ``litestar_auth`` package does not import contrib modules eagerly.
Import individual contrib packages explicitly to opt into those surfaces.
"""

__all__: tuple[str, ...] = ()
