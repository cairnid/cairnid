ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS account_tokens (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS account_tokens_active_hash_idx
    ON account_tokens(token_hash, kind)
    WHERE consumed_at IS NULL;

CREATE INDEX IF NOT EXISTS account_tokens_org_kind_email_idx
    ON account_tokens(organization_id, kind, email, created_at DESC);

CREATE INDEX IF NOT EXISTS account_tokens_user_idx
    ON account_tokens(user_id, created_at DESC)
    WHERE user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS email_outbox (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    recipient_email TEXT NOT NULL,
    subject TEXT NOT NULL,
    body_text TEXT NOT NULL,
    template TEXT NOT NULL,
    action_path TEXT,
    delivery_token_ciphertext BYTEA,
    delivery_token_nonce BYTEA,
    status TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    sent_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS email_outbox_status_created_idx
    ON email_outbox(status, created_at);

CREATE INDEX IF NOT EXISTS email_outbox_org_recipient_idx
    ON email_outbox(organization_id, recipient_email, created_at DESC);
