use crate::codec::{account_token_kind_to_str, user_status_to_str};
use crate::{
    Database, DatabaseError, PasswordRecoveryInput, PasswordRecoveryMutation,
    PasswordRecoveryOutcome,
};
use cairn_domain::{AccountTokenKind, UserStatus};

impl Database {
    pub async fn consume_password_recovery_token_and_reset_user_password(
        &self,
        input: PasswordRecoveryInput<'_>,
    ) -> Result<PasswordRecoveryOutcome, DatabaseError> {
        let PasswordRecoveryInput {
            organization_id,
            user_id,
            token_id,
            password_hash,
            notification,
            at,
        } = input;

        let mut tx = self.pool.begin().await?;
        let consumed = sqlx::query(
            r#"
            UPDATE account_tokens
            SET consumed_at = $1
            WHERE id = $2
              AND organization_id = $3
              AND user_id = $4
              AND kind = $5
              AND consumed_at IS NULL
              AND expires_at > $1
              AND EXISTS (
                  SELECT 1
                  FROM users
                  WHERE users.organization_id = account_tokens.organization_id
                    AND users.id = $4
                    AND users.email = account_tokens.email
                    AND users.status = $6
                    AND users.password_hash IS NOT NULL
              )
            "#,
        )
        .bind(at)
        .bind(token_id)
        .bind(organization_id)
        .bind(user_id)
        .bind(account_token_kind_to_str(
            AccountTokenKind::PasswordRecovery,
        ))
        .bind(user_status_to_str(UserStatus::Active))
        .execute(&mut *tx)
        .await?;

        if consumed.rows_affected() != 1 {
            return Ok(PasswordRecoveryOutcome::NotFound);
        }

        let updated = sqlx::query(
            r#"
            UPDATE users
            SET password_hash = $1, email_verified = TRUE, updated_at = $2
            WHERE organization_id = $3 AND id = $4
              AND status = $5
              AND password_hash IS NOT NULL
              AND email = (
                  SELECT email
                  FROM account_tokens
                  WHERE id = $6
              )
            "#,
        )
        .bind(password_hash)
        .bind(at)
        .bind(organization_id)
        .bind(user_id)
        .bind(user_status_to_str(UserStatus::Active))
        .bind(token_id)
        .execute(&mut *tx)
        .await?;

        if updated.rows_affected() != 1 {
            return Ok(PasswordRecoveryOutcome::NotFound);
        }

        let other_account_tokens_consumed = sqlx::query(
            r#"
            UPDATE account_tokens
            SET consumed_at = $1
            WHERE organization_id = $2
              AND user_id = $3
              AND kind = $4
              AND id <> $5
              AND consumed_at IS NULL
              AND expires_at > $1
            "#,
        )
        .bind(at)
        .bind(organization_id)
        .bind(user_id)
        .bind(account_token_kind_to_str(
            AccountTokenKind::PasswordRecovery,
        ))
        .bind(token_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        let sessions_revoked = sqlx::query(
            r#"
            UPDATE auth_sessions
            SET revoked_at = COALESCE(revoked_at, $1)
            WHERE organization_id = $2
              AND user_id = $3
              AND revoked_at IS NULL
            "#,
        )
        .bind(at)
        .bind(organization_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        let access_tokens_revoked = sqlx::query(
            r#"
            UPDATE access_tokens
            SET revoked_at = COALESCE(revoked_at, $1)
            WHERE organization_id = $2
              AND user_id = $3
              AND revoked_at IS NULL
            "#,
        )
        .bind(at)
        .bind(organization_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        let refresh_tokens_revoked = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = COALESCE(revoked_at, $1)
            WHERE organization_id = $2
              AND user_id = $3
              AND revoked_at IS NULL
            "#,
        )
        .bind(at)
        .bind(organization_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if let Some(message) = notification {
            debug_assert_eq!(message.organization_id, organization_id);
            Self::insert_email_outbox_message_in_tx(&mut tx, message).await?;
        }

        tx.commit().await?;
        Ok(PasswordRecoveryOutcome::Applied(Box::new(
            PasswordRecoveryMutation {
                sessions_revoked,
                access_tokens_revoked,
                refresh_tokens_revoked,
                account_tokens_consumed: 1 + other_account_tokens_consumed,
                notification_email_outbox_id: notification.map(|message| message.id),
            },
        )))
    }
}
