use super::insert_access_token_record;
use crate::rows::AccessTokenRow;
use crate::{AccessTokenRecord, Database, DatabaseError};
use time::OffsetDateTime;

impl Database {
    pub async fn insert_access_token(
        &self,
        token: &AccessTokenRecord,
    ) -> Result<(), DatabaseError> {
        insert_access_token_record(&self.pool, token).await
    }

    pub async fn get_access_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<AccessTokenRecord>, DatabaseError> {
        let row = sqlx::query_as::<_, AccessTokenRow>(
            r#"
            SELECT token_hash, organization_id, user_id, client_id, scopes, refresh_family_id,
                   created_at, expires_at, revoked_at
            FROM access_tokens
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    pub async fn revoke_access_token(
        &self,
        token_hash: &str,
        at: OffsetDateTime,
    ) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE access_tokens SET revoked_at = $1 WHERE token_hash = $2")
            .bind(at)
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
