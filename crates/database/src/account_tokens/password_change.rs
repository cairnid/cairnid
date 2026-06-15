use crate::codec::account_token_kind_to_str;
use crate::{
    Database, DatabaseError, PasswordChangeInput, PasswordChangeMutation, PasswordChangeOutcome,
};
use cairn_domain::AccountTokenKind;
use sqlx::types::Json;
use uuid::Uuid;

impl Database {
    pub async fn change_user_password_and_rotate_session(
        &self,
        input: PasswordChangeInput<'_>,
    ) -> Result<PasswordChangeOutcome, DatabaseError> {
        let PasswordChangeInput {
            organization_id,
            user_id,
            password_hash,
            new_session,
            request_context,
            notification,
            at,
        } = input;
        debug_assert_eq!(new_session.organization_id, organization_id);
        debug_assert_eq!(new_session.user_id, user_id);

        let mut tx = self.pool.begin().await?;
        let Some(_) = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id
            FROM users
            WHERE organization_id = $1 AND id = $2
            FOR UPDATE
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
        else {
            tx.commit().await?;
            return Ok(PasswordChangeOutcome::NotFound);
        };

        sqlx::query(
            r#"
            UPDATE users
            SET password_hash = $1, updated_at = $2
            WHERE organization_id = $3 AND id = $4
            "#,
        )
        .bind(password_hash)
        .bind(at)
        .bind(organization_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

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

        sqlx::query(
            r#"
            INSERT INTO auth_sessions (
                id, organization_id, user_id, acr, amr, created_at, expires_at, revoked_at,
                created_ip_address, created_user_agent
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(new_session.id)
        .bind(new_session.organization_id)
        .bind(new_session.user_id)
        .bind(&new_session.acr)
        .bind(Json(&new_session.amr))
        .bind(new_session.created_at)
        .bind(new_session.expires_at)
        .bind(new_session.revoked_at)
        .bind(request_context.ip_address)
        .bind(request_context.user_agent)
        .execute(&mut *tx)
        .await?;

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

        let account_tokens_consumed = sqlx::query(
            r#"
            UPDATE account_tokens
            SET consumed_at = COALESCE(consumed_at, $1)
            WHERE organization_id = $2
              AND user_id = $3
              AND kind = $4
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
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if let Some(message) = notification {
            debug_assert_eq!(message.organization_id, organization_id);
            Self::insert_email_outbox_message_in_tx(&mut tx, message).await?;
        }

        tx.commit().await?;
        Ok(PasswordChangeOutcome::Applied(Box::new(
            PasswordChangeMutation {
                session: new_session.clone(),
                sessions_revoked,
                access_tokens_revoked,
                refresh_tokens_revoked,
                account_tokens_consumed,
                notification_email_outbox_id: notification.map(|message| message.id),
            },
        )))
    }
}
