use super::insert_account_token_record;
use crate::{Database, DatabaseError};
use cairn_domain::{AccountToken, EmailOutboxMessage};

impl Database {
    pub async fn insert_account_token_and_email_outbox_message(
        &self,
        token: &AccountToken,
        message: &EmailOutboxMessage,
    ) -> Result<(), DatabaseError> {
        let mut tx = self.pool.begin().await?;

        insert_account_token_record(&mut *tx, token).await?;
        Self::insert_email_outbox_message_in_tx(&mut tx, message).await?;

        tx.commit().await?;
        Ok(())
    }
}
