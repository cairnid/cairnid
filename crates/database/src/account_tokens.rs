mod delivery;
mod password_change;
mod password_recovery;

use crate::codec::{account_token_kind_to_str, user_status_to_str};
use crate::rows::AccountTokenRow;
use crate::{Database, DatabaseError};
use cairn_domain::{AccountToken, AccountTokenKind, UserId, UserStatus};
use sqlx::{Executor, Postgres, types::Json};
use time::OffsetDateTime;
use uuid::Uuid;

impl Database {
    pub async fn insert_account_token(&self, token: &AccountToken) -> Result<(), DatabaseError> {
        insert_account_token_record(&self.pool, token).await
    }

    pub async fn get_account_token_by_hash(
        &self,
        token_hash: &str,
        kind: AccountTokenKind,
    ) -> Result<Option<AccountToken>, DatabaseError> {
        let row = sqlx::query_as::<_, AccountTokenRow>(
            r#"
            SELECT id, organization_id, kind, user_id, email, token_hash, created_by_user_id,
                   created_at, expires_at, consumed_at, metadata
            FROM account_tokens
            WHERE token_hash = $1 AND kind = $2
            "#,
        )
        .bind(token_hash)
        .bind(account_token_kind_to_str(kind))
        .fetch_optional(&self.pool)
        .await?;

        row.map(AccountTokenRow::try_into_token).transpose()
    }

    pub async fn consume_account_token(
        &self,
        id: Uuid,
        at: OffsetDateTime,
    ) -> Result<bool, DatabaseError> {
        let result = sqlx::query(
            r#"
            UPDATE account_tokens
            SET consumed_at = $1
            WHERE id = $2
              AND consumed_at IS NULL
              AND expires_at > $1
            "#,
        )
        .bind(at)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    pub async fn consume_account_token_and_set_user_email_verified(
        &self,
        token_id: Uuid,
        user_id: UserId,
        at: OffsetDateTime,
    ) -> Result<bool, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let consumed = sqlx::query(
            r#"
            UPDATE account_tokens
            SET consumed_at = $1
            WHERE id = $2
              AND user_id = $3
              AND kind = $4
              AND consumed_at IS NULL
              AND expires_at > $1
              AND EXISTS (
                  SELECT 1
                  FROM users
                  WHERE users.organization_id = account_tokens.organization_id
                    AND users.id = $3
                    AND users.email = account_tokens.email
                    AND users.status = $5
              )
            "#,
        )
        .bind(at)
        .bind(token_id)
        .bind(user_id)
        .bind(account_token_kind_to_str(
            AccountTokenKind::EmailVerification,
        ))
        .bind(user_status_to_str(UserStatus::Active))
        .execute(&mut *tx)
        .await?;

        if consumed.rows_affected() != 1 {
            return Ok(false);
        }

        let updated = sqlx::query(
            r#"
            UPDATE users
            SET email_verified = TRUE, updated_at = $1
            WHERE id = $2
              AND status = $3
              AND email = (
                  SELECT email
                  FROM account_tokens
                  WHERE id = $4
              )
            "#,
        )
        .bind(at)
        .bind(user_id)
        .bind(user_status_to_str(UserStatus::Active))
        .bind(token_id)
        .execute(&mut *tx)
        .await?;

        if updated.rows_affected() != 1 {
            return Ok(false);
        }

        tx.commit().await?;
        Ok(true)
    }

    pub async fn consume_account_token_and_set_user_password(
        &self,
        token_id: Uuid,
        user_id: UserId,
        password_hash: &str,
        email_verified: bool,
        revoke_sessions: bool,
        at: OffsetDateTime,
    ) -> Result<bool, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let consumed = sqlx::query(
            r#"
            UPDATE account_tokens
            SET consumed_at = $1
            WHERE id = $2
              AND user_id = $3
              AND kind = $4
              AND consumed_at IS NULL
              AND expires_at > $1
              AND EXISTS (
                  SELECT 1
                  FROM users
                  WHERE users.organization_id = account_tokens.organization_id
                    AND users.id = $3
                    AND users.email = account_tokens.email
                    AND users.status = $5
                    AND users.password_hash IS NULL
              )
            "#,
        )
        .bind(at)
        .bind(token_id)
        .bind(user_id)
        .bind(account_token_kind_to_str(AccountTokenKind::Invitation))
        .bind(user_status_to_str(UserStatus::Active))
        .execute(&mut *tx)
        .await?;

        if consumed.rows_affected() != 1 {
            return Ok(false);
        }

        let updated = sqlx::query(
            r#"
            UPDATE users
            SET password_hash = $1, email_verified = $2, updated_at = $3
            WHERE id = $4
              AND status = $5
              AND password_hash IS NULL
              AND email = (
                  SELECT email
                  FROM account_tokens
                  WHERE id = $6
              )
            "#,
        )
        .bind(password_hash)
        .bind(email_verified)
        .bind(at)
        .bind(user_id)
        .bind(user_status_to_str(UserStatus::Active))
        .bind(token_id)
        .execute(&mut *tx)
        .await?;

        if updated.rows_affected() != 1 {
            return Ok(false);
        }

        if revoke_sessions {
            sqlx::query(
                r#"
                UPDATE auth_sessions
                SET revoked_at = COALESCE(revoked_at, $1)
                WHERE user_id = $2
                "#,
            )
            .bind(at)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(true)
    }
}

async fn insert_account_token_record<'e, E>(
    executor: E,
    token: &AccountToken,
) -> Result<(), DatabaseError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO account_tokens (
            id, organization_id, kind, user_id, email, token_hash, created_by_user_id,
            created_at, expires_at, consumed_at, metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(token.id)
    .bind(token.organization_id)
    .bind(account_token_kind_to_str(token.kind))
    .bind(token.user_id)
    .bind(&token.email)
    .bind(&token.token_hash)
    .bind(token.created_by_user_id)
    .bind(token.created_at)
    .bind(token.expires_at)
    .bind(token.consumed_at)
    .bind(Json(&token.metadata))
    .execute(executor)
    .await?;
    Ok(())
}
