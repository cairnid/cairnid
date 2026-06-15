ALTER TABLE users
    ADD COLUMN IF NOT EXISTS scim_external_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS users_org_scim_external_id_unique_idx
    ON users (organization_id, scim_external_id)
    WHERE scim_external_id IS NOT NULL;
