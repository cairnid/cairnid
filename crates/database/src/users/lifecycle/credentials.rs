use crate::DatabaseError;
use cairn_domain::{OrganizationId, UserId};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

pub(in crate::users::lifecycle) async fn revoke_user_runtime_credentials(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    user_id: UserId,
    at: OffsetDateTime,
) -> Result<(), DatabaseError> {
    sqlx::query(
        r#"
        UPDATE auth_sessions
        SET revoked_at = COALESCE(revoked_at, $1)
        WHERE organization_id = $2 AND user_id = $3
        "#,
    )
    .bind(at)
    .bind(organization_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE access_tokens
        SET revoked_at = COALESCE(revoked_at, $1)
        WHERE organization_id = $2 AND user_id = $3
        "#,
    )
    .bind(at)
    .bind(organization_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = COALESCE(revoked_at, $1)
        WHERE organization_id = $2 AND user_id = $3
        "#,
    )
    .bind(at)
    .bind(organization_id)
    .bind(user_id)
    .execute(&mut **tx)
    .await?;

    Ok(())
}
