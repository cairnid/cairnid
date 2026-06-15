CREATE INDEX IF NOT EXISTS oidc_clients_org_public_created_id_idx
    ON oidc_clients(organization_id, public_client, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS oidc_clients_org_lower_client_id_prefix_idx
    ON oidc_clients(organization_id, (lower(client_id)) text_pattern_ops, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS oidc_clients_org_lower_name_prefix_idx
    ON oidc_clients(organization_id, (lower(name)) text_pattern_ops, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS oidc_clients_grant_types_gin_idx
    ON oidc_clients USING GIN (grant_types);

CREATE INDEX IF NOT EXISTS oidc_clients_allowed_scopes_gin_idx
    ON oidc_clients USING GIN (allowed_scopes);
