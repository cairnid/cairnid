use crate::rows::EmailOutboxRow;
use crate::{Database, DatabaseError};
use time::OffsetDateTime;
use uuid::Uuid;

impl Database {
    pub async fn claim_email_outbox_messages(
        &self,
        limit: i64,
        at: OffsetDateTime,
        stale_sending_before: OffsetDateTime,
    ) -> Result<Vec<cairn_domain::EmailOutboxMessage>, DatabaseError> {
        let rows = sqlx::query_as::<_, EmailOutboxRow>(
            r#"
            WITH selected AS (
                SELECT id
                FROM email_outbox
                WHERE (
                    status IN ('queued', 'retry')
                    AND (next_attempt_at IS NULL OR next_attempt_at <= $1)
                  )
                  OR (
                    status = 'sending'
                    AND updated_at <= $3
                  )
                ORDER BY created_at
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            )
            UPDATE email_outbox
            SET status = 'sending',
                attempts = attempts + 1,
                last_error = NULL,
                updated_at = $1
            FROM selected
            WHERE email_outbox.id = selected.id
            RETURNING email_outbox.id, email_outbox.organization_id, email_outbox.recipient_email,
                email_outbox.subject, email_outbox.body_text, email_outbox.template,
                email_outbox.action_path, email_outbox.delivery_token_ciphertext,
                email_outbox.delivery_token_nonce, email_outbox.status, email_outbox.attempts,
                email_outbox.last_error, email_outbox.provider_message_id,
                email_outbox.metadata, email_outbox.created_at, email_outbox.updated_at,
                email_outbox.next_attempt_at, email_outbox.sent_at
            "#,
        )
        .bind(at)
        .bind(limit)
        .bind(stale_sending_before)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(EmailOutboxRow::into_message).collect())
    }

    pub async fn mark_email_outbox_sent(
        &self,
        id: Uuid,
        provider_message_id: Option<&str>,
        at: OffsetDateTime,
    ) -> Result<bool, DatabaseError> {
        let result = sqlx::query(
            r#"
            UPDATE email_outbox
            SET status = 'sent',
                sent_at = $2,
                updated_at = $2,
                provider_message_id = $3,
                last_error = NULL,
                next_attempt_at = NULL
            WHERE id = $1 AND status = 'sending'
            "#,
        )
        .bind(id)
        .bind(at)
        .bind(provider_message_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_email_outbox_retry(
        &self,
        id: Uuid,
        last_error: &str,
        next_attempt_at: OffsetDateTime,
        at: OffsetDateTime,
    ) -> Result<bool, DatabaseError> {
        let result = sqlx::query(
            r#"
            UPDATE email_outbox
            SET status = 'retry',
                last_error = $2,
                next_attempt_at = $3,
                updated_at = $4
            WHERE id = $1 AND status = 'sending'
            "#,
        )
        .bind(id)
        .bind(last_error)
        .bind(next_attempt_at)
        .bind(at)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    pub async fn mark_email_outbox_failed(
        &self,
        id: Uuid,
        last_error: &str,
        at: OffsetDateTime,
    ) -> Result<bool, DatabaseError> {
        let result = sqlx::query(
            r#"
            UPDATE email_outbox
            SET status = 'failed',
                last_error = $2,
                next_attempt_at = NULL,
                updated_at = $3
            WHERE id = $1 AND status = 'sending'
            "#,
        )
        .bind(id)
        .bind(last_error)
        .bind(at)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }
}
