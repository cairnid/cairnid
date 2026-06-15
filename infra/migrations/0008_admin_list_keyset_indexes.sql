CREATE INDEX IF NOT EXISTS users_org_created_id_idx
    ON users(organization_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS groups_org_created_id_idx
    ON groups(organization_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS memberships_org_group_created_user_idx
    ON memberships(organization_id, group_id, created_at DESC, user_id DESC);

CREATE INDEX IF NOT EXISTS oidc_clients_org_created_id_idx
    ON oidc_clients(organization_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS audit_events_org_created_id_idx
    ON audit_events(organization_id, created_at DESC, id DESC);
