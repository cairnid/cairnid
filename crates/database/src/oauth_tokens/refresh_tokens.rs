use super::{insert_access_token_record, insert_refresh_token_record};
use crate::rows::RefreshTokenRow;
use crate::{AccessTokenRecord, Database, DatabaseError};
use cairn_domain::RefreshToken;
use time::OffsetDateTime;
use uuid::Uuid;

impl Database {
    pub async fn insert_refresh_token(&self, token: &RefreshToken) -> Result<(), DatabaseError> {
        insert_refresh_token_record(&self.pool, token).await
    }

    pub async fn get_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshToken>, DatabaseError> {
        let row = sqlx::query_as::<_, RefreshTokenRow>(
            r#"
            SELECT id, token_hash, family_id, organization_id, user_id, client_id, scopes,
                   created_at, expires_at, rotated_at, revoked_at
            FROM refresh_tokens
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    pub async fn mark_refresh_token_rotated(
        &self,
        token_hash: &str,
        at: OffsetDateTime,
    ) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE refresh_tokens SET rotated_at = $1 WHERE token_hash = $2")
            .bind(at)
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn rotate_refresh_token_and_insert_tokens(
        &self,
        token_hash: &str,
        access_token: &AccessTokenRecord,
        refresh_token: Option<&RefreshToken>,
        at: OffsetDateTime,
    ) -> Result<bool, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let rotated = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET rotated_at = $1
            WHERE token_hash = $2
              AND rotated_at IS NULL
              AND revoked_at IS NULL
              AND expires_at > $1
            "#,
        )
        .bind(at)
        .bind(token_hash)
        .execute(&mut *tx)
        .await?;

        if rotated.rows_affected() != 1 {
            return Ok(false);
        }

        insert_access_token_record(&mut *tx, access_token).await?;
        if let Some(refresh_token) = refresh_token {
            insert_refresh_token_record(&mut *tx, refresh_token).await?;
        }

        tx.commit().await?;
        Ok(true)
    }

    pub async fn revoke_refresh_token_family_and_access_tokens(
        &self,
        family_id: Uuid,
        at: OffsetDateTime,
    ) -> Result<(), DatabaseError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, $1) WHERE family_id = $2",
        )
        .bind(at)
        .bind(family_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            UPDATE access_tokens
            SET revoked_at = COALESCE(revoked_at, $1)
            WHERE refresh_family_id = $2
            "#,
        )
        .bind(at)
        .bind(family_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
