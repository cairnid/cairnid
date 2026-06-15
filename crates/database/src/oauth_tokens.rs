mod access_tokens;
mod authorization_codes;
mod refresh_tokens;

use crate::{AccessTokenRecord, DatabaseError};
use cairn_domain::RefreshToken;
use sqlx::{Executor, Postgres, types::Json};

async fn insert_access_token_record<'e, E>(
    executor: E,
    token: &AccessTokenRecord,
) -> Result<(), DatabaseError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO access_tokens (
            token_hash, organization_id, user_id, client_id, scopes, refresh_family_id,
            created_at, expires_at, revoked_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(&token.token_hash)
    .bind(token.organization_id)
    .bind(token.user_id)
    .bind(token.client_id)
    .bind(Json(&token.scopes))
    .bind(token.refresh_family_id)
    .bind(token.created_at)
    .bind(token.expires_at)
    .bind(token.revoked_at)
    .execute(executor)
    .await?;
    Ok(())
}

async fn insert_refresh_token_record<'e, E>(
    executor: E,
    token: &RefreshToken,
) -> Result<(), DatabaseError>
where
    E: Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (
            id, token_hash, family_id, organization_id, user_id, client_id, scopes,
            created_at, expires_at, rotated_at, revoked_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(token.id)
    .bind(&token.token_hash)
    .bind(token.family_id)
    .bind(token.organization_id)
    .bind(token.user_id)
    .bind(token.client_id)
    .bind(Json(&token.scopes))
    .bind(token.created_at)
    .bind(token.expires_at)
    .bind(token.rotated_at)
    .bind(token.revoked_at)
    .execute(executor)
    .await?;
    Ok(())
}
