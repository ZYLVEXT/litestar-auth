# Organizations and invitations

`litestar_auth.contrib.organization_admin.OrganizationAdmin` is the backend-neutral operations
service for organization, membership, and invitation workflows. It depends only on the public
`litestar_auth.db.BaseOrganizationStore` protocol.

## Atomic invitation acceptance

Invitation acceptance is one persistence operation. Every organization store must implement
`finalize_invitation_acceptance(...)` so consuming a pending invitation and creating membership
either both succeed or both roll back. Split `consume_invitation` then `add_membership` is not
supported: a failed membership insert must not leave a consumed invitation stranded.

Applications normally call `admin.accept_invitation(...)`. Custom registration flows may call the
public store operation after their own authenticated token and invitee checks.

Invitation tokens are challenge JWTs with audience `litestar-auth:organization-invitation`. They
are not browser sessions. See [credentials and tokens](../credentials.md).

## Roles

Import `normalize_role_name` or `normalize_roles` from `litestar_auth.roles` for the canonical
flat-role representation (trim, NFKC, lowercase, dedupe, stable sort).

Organization administration defaults to the configured superuser role plus human authentication.
Custom authorization uses `OrganizationAdminAuthorizationPolicy`. An empty guard sequence is
rejected so the admin surface cannot be published by accident.

## Related

- [Architecture](../architecture.md)
- [Security posture](../security.md)
- [Migrate 7.x → 8](../migration-v8.md)
