CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ,
    UNIQUE (organization_id, email)
);

CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (organization_id, slug)
);

CREATE TABLE IF NOT EXISTS memberships (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS oidc_clients (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT,
    name TEXT NOT NULL,
    redirect_uris JSONB NOT NULL,
    post_logout_redirect_uris JSONB NOT NULL,
    allowed_scopes JSONB NOT NULL,
    grant_types JSONB NOT NULL,
    public_client BOOLEAN NOT NULL,
    require_pkce BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    acr TEXT NOT NULL,
    amr JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS consent_grants (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    scopes JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code_hash TEXT PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID NOT NULL REFERENCES auth_sessions(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes JSONB NOT NULL,
    nonce TEXT,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS access_tokens (
    token_hash TEXT PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    scopes JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    family_id UUID NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    scopes JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS refresh_tokens_family_id_idx ON refresh_tokens(family_id);

CREATE TABLE IF NOT EXISTS signing_keys (
    kid TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL,
    public_jwk JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS mfa_credentials (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    secret_metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_kind TEXT NOT NULL,
    actor_id UUID,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    metadata JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_events_org_created_idx ON audit_events(organization_id, created_at DESC);
