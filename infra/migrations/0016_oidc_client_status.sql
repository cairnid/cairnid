ALTER TABLE oidc_clients
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
    ADD CONSTRAINT oidc_clients_status_check CHECK (status IN ('active', 'disabled'));

CREATE INDEX IF NOT EXISTS oidc_clients_org_status_created_idx
    ON oidc_clients(organization_id, status, created_at DESC, id DESC);
