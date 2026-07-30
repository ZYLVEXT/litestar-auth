CREATE TABLE authweave_workload_application (
    id varchar(128) PRIMARY KEY,
    status varchar(16) NOT NULL CHECK (status IN ('active', 'disabled')),
    environment varchar(32) NOT NULL,
    owner_ref varchar(128) NOT NULL,
    safe_metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX ix_authweave_workload_application_status
    ON authweave_workload_application (status);
CREATE INDEX ix_authweave_workload_application_environment
    ON authweave_workload_application (environment);
CREATE INDEX ix_authweave_workload_application_owner_ref
    ON authweave_workload_application (owner_ref);

CREATE TABLE authweave_workload_principal (
    id varchar(128) PRIMARY KEY,
    application_id varchar(128) NOT NULL
        REFERENCES authweave_workload_application (id) ON DELETE CASCADE,
    issuer varchar(2048) NOT NULL,
    subject varchar(512) NOT NULL,
    kind varchar(64) NOT NULL CHECK (kind <> 'human'),
    status varchar(16) NOT NULL CHECK (status IN ('active', 'disabled')),
    safe_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT uq_authweave_workload_principal_identity UNIQUE (issuer, subject)
);

CREATE INDEX ix_authweave_workload_principal_application_id
    ON authweave_workload_principal (application_id);
CREATE INDEX ix_authweave_workload_principal_status
    ON authweave_workload_principal (status);

CREATE TABLE authweave_workload_credential (
    id varchar(128) PRIMARY KEY,
    principal_id varchar(128) NOT NULL
        REFERENCES authweave_workload_principal (id) ON DELETE CASCADE,
    status varchar(16) NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    certificate_thumbprint varchar(43) NOT NULL UNIQUE,
    trust_anchor varchar(128) NOT NULL,
    scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
    audiences jsonb NOT NULL DEFAULT '[]'::jsonb,
    environment varchar(32) NOT NULL,
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    subject_dn varchar(2048) NOT NULL,
    issuer_dn varchar(2048) NOT NULL,
    serial_number varchar(2048) NOT NULL,
    rotation_of varchar(128)
        REFERENCES authweave_workload_credential (id) ON DELETE SET NULL,
    revoked_at timestamptz,
    revocation_reason varchar(128),
    last_used_at timestamptz,
    safe_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CHECK (not_before < expires_at),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CHECK ((status = 'revoked') = (revocation_reason IS NOT NULL))
);

CREATE INDEX ix_authweave_workload_credential_principal_id
    ON authweave_workload_credential (principal_id);
CREATE INDEX ix_authweave_workload_credential_status
    ON authweave_workload_credential (status);
CREATE INDEX ix_authweave_workload_credential_expires_at
    ON authweave_workload_credential (expires_at);
CREATE INDEX ix_authweave_workload_credential_principal_status
    ON authweave_workload_credential (principal_id, status);
