ALTER TABLE auth_sessions
    ADD COLUMN IF NOT EXISTS created_ip_address TEXT,
    ADD COLUMN IF NOT EXISTS created_user_agent TEXT;

CREATE INDEX IF NOT EXISTS auth_sessions_active_user_created_idx
    ON auth_sessions (organization_id, user_id, created_at DESC, id DESC)
    WHERE revoked_at IS NULL;
