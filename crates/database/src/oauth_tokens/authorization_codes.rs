use super::{insert_access_token_record, insert_refresh_token_record};
use crate::codec::pkce_method_to_str;
use crate::rows::AuthorizationCodeRow;
use crate::{AccessTokenRecord, Database, DatabaseError};
use cairn_domain::{AuthorizationCode, RefreshToken};
use sqlx::types::Json;
use time::OffsetDateTime;

impl Database {
    pub async fn insert_authorization_code(
        &self,
        code: &AuthorizationCode,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO authorization_codes (
                code_hash, organization_id, user_id, session_id, client_id, redirect_uri,
                scopes, nonce, code_challenge, code_challenge_method,
                created_at, expires_at, used_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            "#,
        )
        .bind(&code.code_hash)
        .bind(code.organization_id)
        .bind(code.user_id)
        .bind(code.session_id)
        .bind(code.client_id)
        .bind(&code.redirect_uri)
        .bind(Json(&code.scopes))
        .bind(&code.nonce)
        .bind(&code.code_challenge)
        .bind(pkce_method_to_str(code.code_challenge_method))
        .bind(code.created_at)
        .bind(code.expires_at)
        .bind(code.used_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_authorization_code(
        &self,
        code_hash: &str,
    ) -> Result<Option<AuthorizationCode>, DatabaseError> {
        let row = sqlx::query_as::<_, AuthorizationCodeRow>(
            r#"
            SELECT code_hash, organization_id, user_id, session_id, client_id, redirect_uri,
                   scopes, nonce, code_challenge, code_challenge_method,
                   created_at, expires_at, used_at
            FROM authorization_codes
            WHERE code_hash = $1
            "#,
        )
        .bind(code_hash)
        .fetch_optional(&self.pool)
        .await?;

        row.map(AuthorizationCodeRow::try_into_code).transpose()
    }

    pub async fn mark_authorization_code_used(
        &self,
        code_hash: &str,
        at: OffsetDateTime,
    ) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE authorization_codes SET used_at = $1 WHERE code_hash = $2")
            .bind(at)
            .bind(code_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn consume_authorization_code_and_insert_tokens(
        &self,
        code_hash: &str,
        access_token: &AccessTokenRecord,
        refresh_token: Option<&RefreshToken>,
        at: OffsetDateTime,
    ) -> Result<bool, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let consumed = sqlx::query(
            r#"
            UPDATE authorization_codes
            SET used_at = $1
            WHERE code_hash = $2
              AND used_at IS NULL
              AND expires_at > $1
            "#,
        )
        .bind(at)
        .bind(code_hash)
        .execute(&mut *tx)
        .await?;

        if consumed.rows_affected() != 1 {
            return Ok(false);
        }

        insert_access_token_record(&mut *tx, access_token).await?;
        if let Some(refresh_token) = refresh_token {
            insert_refresh_token_record(&mut *tx, refresh_token).await?;
        }

        tx.commit().await?;
        Ok(true)
    }
}
