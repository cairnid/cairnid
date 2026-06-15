CREATE TABLE IF NOT EXISTS consent_policy_templates (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    grant_mode TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, slug)
);

CREATE INDEX IF NOT EXISTS consent_policy_templates_org_created_id_idx
    ON consent_policy_templates(organization_id, created_at DESC, id DESC);

ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS consent_policy_template_id UUID;

ALTER TABLE oidc_clients
    ADD CONSTRAINT oidc_clients_consent_policy_template_fk
    FOREIGN KEY (organization_id, consent_policy_template_id)
    REFERENCES consent_policy_templates(organization_id, id);

CREATE INDEX IF NOT EXISTS oidc_clients_org_consent_policy_template_idx
    ON oidc_clients(organization_id, consent_policy_template_id)
    WHERE consent_policy_template_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS consent_authorizations (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    user_id UUID NOT NULL,
    session_id UUID NOT NULL,
    client_id UUID NOT NULL,
    authorization_request_hash TEXT NOT NULL,
    scopes JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (session_id, user_id, organization_id)
        REFERENCES auth_sessions(id, user_id, organization_id)
        ON DELETE CASCADE,
    FOREIGN KEY (client_id, organization_id)
        REFERENCES oidc_clients(id, organization_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS consent_authorizations_pending_lookup_idx
    ON consent_authorizations(organization_id, session_id, client_id, authorization_request_hash, expires_at)
    WHERE consumed_at IS NULL;
