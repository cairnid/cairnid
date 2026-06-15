ALTER TABLE signing_keys
    ADD COLUMN IF NOT EXISTS private_key_ciphertext BYTEA,
    ADD COLUMN IF NOT EXISTS private_key_nonce BYTEA,
    ADD COLUMN IF NOT EXISTS signing_active BOOLEAN NOT NULL DEFAULT FALSE;

CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_single_active_idx
    ON signing_keys(signing_active)
    WHERE signing_active = TRUE;

CREATE INDEX IF NOT EXISTS signing_keys_active_jwks_idx
    ON signing_keys(signing_active DESC, created_at DESC)
    WHERE retired_at IS NULL;
