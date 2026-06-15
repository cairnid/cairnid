CREATE INDEX IF NOT EXISTS consent_grants_org_user_created_id_idx
    ON consent_grants(organization_id, user_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS consent_grants_org_user_active_created_id_idx
    ON consent_grants(organization_id, user_id, created_at DESC, id DESC)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS consent_grants_org_user_revoked_created_id_idx
    ON consent_grants(organization_id, user_id, created_at DESC, id DESC)
    WHERE revoked_at IS NOT NULL;
