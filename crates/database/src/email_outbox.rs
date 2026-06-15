mod delivery;
mod evidence;

use crate::{Database, DatabaseError};
use cairn_domain::EmailOutboxMessage;
use sqlx::{Executor, Postgres, Transaction, types::Json};

impl Database {
    pub async fn insert_email_outbox_message(
        &self,
        message: &EmailOutboxMessage,
    ) -> Result<(), DatabaseError> {
        insert_email_outbox_message_record(&self.pool, message).await
    }

    pub(super) async fn insert_email_outbox_message_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        message: &EmailOutboxMessage,
    ) -> Result<(), DatabaseError> {
        insert_email_outbox_message_record(&mut **tx, message).await
    }
}

async fn insert_email_outbox_message_record<'e, E>(
    executor: E,
    message: &EmailOutboxMessage,
) -> Result<(), DatabaseError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO email_outbox (
            id, organization_id, recipient_email, subject, body_text, template,
            action_path, delivery_token_ciphertext, delivery_token_nonce,
            status, attempts, last_error, provider_message_id, metadata,
            created_at, updated_at, next_attempt_at, sent_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
        "#,
    )
    .bind(message.id)
    .bind(message.organization_id)
    .bind(&message.recipient_email)
    .bind(&message.subject)
    .bind(&message.body_text)
    .bind(&message.template)
    .bind(&message.action_path)
    .bind(&message.delivery_token_ciphertext)
    .bind(&message.delivery_token_nonce)
    .bind(&message.status)
    .bind(message.attempts)
    .bind(&message.last_error)
    .bind(&message.provider_message_id)
    .bind(Json(&message.metadata))
    .bind(message.created_at)
    .bind(message.updated_at)
    .bind(message.next_attempt_at)
    .bind(message.sent_at)
    .execute(executor)
    .await?;
    Ok(())
}
