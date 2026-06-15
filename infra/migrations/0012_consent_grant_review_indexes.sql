CREATE INDEX IF NOT EXISTS consent_grants_org_client_active_created_id_idx
    ON consent_grants(organization_id, client_id, created_at DESC, id DESC)
    WHERE revoked_at IS NULL;
