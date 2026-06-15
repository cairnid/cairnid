ALTER TABLE access_tokens
    ADD COLUMN IF NOT EXISTS refresh_family_id UUID;

CREATE INDEX IF NOT EXISTS access_tokens_refresh_family_id_idx
    ON access_tokens(refresh_family_id)
    WHERE refresh_family_id IS NOT NULL;
