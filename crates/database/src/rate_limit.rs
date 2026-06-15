use super::rows::RateLimitBucketRow;
use super::{Database, DatabaseError, RateLimitBucket};
use time::{Duration, OffsetDateTime};

impl Database {
    pub async fn get_rate_limit_bucket(
        &self,
        key: &str,
    ) -> Result<Option<RateLimitBucket>, DatabaseError> {
        let row = sqlx::query_as::<_, RateLimitBucketRow>(
            r#"
            SELECT key, purpose, attempts, window_start, blocked_until, updated_at
            FROM rate_limit_buckets
            WHERE key = $1
            "#,
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    pub async fn record_rate_limit_failure(
        &self,
        key: &str,
        purpose: &str,
        now: OffsetDateTime,
        window: Duration,
        max_attempts: i64,
        block_for: Duration,
    ) -> Result<RateLimitBucket, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let existing = sqlx::query_as::<_, RateLimitBucketRow>(
            r#"
            SELECT key, purpose, attempts, window_start, blocked_until, updated_at
            FROM rate_limit_buckets
            WHERE key = $1
            FOR UPDATE
            "#,
        )
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?
        .map(RateLimitBucket::from);

        let mut bucket = match existing {
            Some(mut bucket) if bucket.window_start + window > now => {
                bucket.attempts += 1;
                bucket.updated_at = now;
                bucket
            }
            _ => RateLimitBucket {
                key: key.to_owned(),
                purpose: purpose.to_owned(),
                attempts: 1,
                window_start: now,
                blocked_until: None,
                updated_at: now,
            },
        };

        if bucket.attempts >= max_attempts {
            bucket.blocked_until = Some(now + block_for);
        }

        sqlx::query(
            r#"
            INSERT INTO rate_limit_buckets (
                key, purpose, attempts, window_start, blocked_until, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (key) DO UPDATE SET
                purpose = EXCLUDED.purpose,
                attempts = EXCLUDED.attempts,
                window_start = EXCLUDED.window_start,
                blocked_until = EXCLUDED.blocked_until,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(&bucket.key)
        .bind(&bucket.purpose)
        .bind(bucket.attempts)
        .bind(bucket.window_start)
        .bind(bucket.blocked_until)
        .bind(bucket.updated_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(bucket)
    }

    pub async fn clear_rate_limit_bucket(&self, key: &str) -> Result<(), DatabaseError> {
        sqlx::query("DELETE FROM rate_limit_buckets WHERE key = $1")
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
