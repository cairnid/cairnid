CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    key TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    attempts BIGINT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    blocked_until TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS rate_limit_buckets_purpose_updated_idx
    ON rate_limit_buckets(purpose, updated_at DESC);

CREATE INDEX IF NOT EXISTS rate_limit_buckets_blocked_until_idx
    ON rate_limit_buckets(blocked_until)
    WHERE blocked_until IS NOT NULL;
