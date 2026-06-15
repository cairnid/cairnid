CREATE INDEX IF NOT EXISTS users_org_status_created_id_idx
    ON users(organization_id, status, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS users_org_lower_email_prefix_idx
    ON users(organization_id, (lower(email)) text_pattern_ops, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS users_org_lower_display_name_prefix_idx
    ON users(organization_id, (lower(display_name)) text_pattern_ops, created_at DESC, id DESC);
