CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    user_id UUID NOT NULL,
    kind TEXT NOT NULL,
    state JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CONSTRAINT webauthn_challenges_kind_check
        CHECK (kind IN ('registration', 'authentication')),
    CONSTRAINT webauthn_challenges_user_organization_fk
        FOREIGN KEY (user_id, organization_id)
        REFERENCES users(id, organization_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS webauthn_challenges_user_pending_idx
    ON webauthn_challenges (organization_id, user_id, kind, expires_at)
    WHERE consumed_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS mfa_credentials_active_webauthn_credential_id_unique
    ON mfa_credentials (organization_id, (secret_metadata->>'credential_id'))
    WHERE kind = 'web_authn'
      AND secret_metadata->>'status' = 'active'
      AND secret_metadata ? 'credential_id';
