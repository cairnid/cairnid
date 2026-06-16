use crate::{Database, DatabaseError, EmailOutboxQueueSummary, LifecycleEmailEvidenceMessage};
use time::OffsetDateTime;
use uuid::Uuid;

impl Database {
    pub async fn email_outbox_queue_summary(
        &self,
        at: OffsetDateTime,
        stale_sending_before: OffsetDateTime,
    ) -> Result<EmailOutboxQueueSummary, DatabaseError> {
        Ok(sqlx::query_as::<_, EmailOutboxQueueSummary>(
            r#"
            SELECT
                COUNT(*) FILTER (WHERE status = 'queued') AS queued,
                COUNT(*) FILTER (WHERE status = 'retry') AS retry,
                COUNT(*) FILTER (
                    WHERE status = 'retry'
                      AND (next_attempt_at IS NULL OR next_attempt_at <= $1)
                ) AS retry_due,
                COUNT(*) FILTER (WHERE status = 'sending') AS sending,
                COUNT(*) FILTER (
                    WHERE status = 'sending'
                      AND updated_at <= $2
                ) AS stale_sending,
                COUNT(*) FILTER (WHERE status = 'failed') AS failed,
                COUNT(*) FILTER (WHERE status = 'sent') AS sent,
                COUNT(*) FILTER (
                    WHERE status IN ('queued', 'retry', 'sending', 'failed')
                ) AS unfinished,
                MIN(created_at) FILTER (
                    WHERE status IN ('queued', 'retry', 'sending', 'failed')
                ) AS oldest_unfinished_at,
                MIN(next_attempt_at) FILTER (
                    WHERE status = 'retry'
                      AND next_attempt_at > $1
                ) AS next_retry_at
            FROM email_outbox
            "#,
        )
        .bind(at)
        .bind(stale_sending_before)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn list_lifecycle_email_evidence_messages(
        &self,
        organization_id: Uuid,
        required_kinds: &[String],
    ) -> Result<Vec<LifecycleEmailEvidenceMessage>, DatabaseError> {
        if required_kinds.is_empty() {
            return Ok(Vec::new());
        }

        sqlx::query_as::<_, LifecycleEmailEvidenceMessage>(
            r#"
            WITH ranked AS (
                SELECT
                    metadata->>'kind' AS kind,
                    template,
                    action_path IS NOT NULL AS action_url_present,
                    provider_message_id,
                    sent_at,
                    ROW_NUMBER() OVER (
                        PARTITION BY metadata->>'kind'
                        ORDER BY sent_at DESC, updated_at DESC, id DESC
                    ) AS rank
                FROM email_outbox
                WHERE organization_id = $1
                  AND status = 'sent'
                  AND sent_at IS NOT NULL
                  AND metadata->>'kind' = ANY($2::text[])
            )
            SELECT kind, template, action_url_present, provider_message_id, sent_at
            FROM ranked
            WHERE rank = 1
            ORDER BY kind ASC
            "#,
        )
        .bind(organization_id)
        .bind(required_kinds)
        .fetch_all(&self.pool)
        .await
        .map_err(Into::into)
    }
}
