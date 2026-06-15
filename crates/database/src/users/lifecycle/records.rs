use crate::{DatabaseError, rows::UserRow};
use cairn_domain::{OrganizationId, User, UserId};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::users::lifecycle) async fn locked_user_for_update(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    user_id: UserId,
) -> Result<Option<User>, DatabaseError> {
    let row = sqlx::query_as::<_, UserRow>(
        r#"
        SELECT id, organization_id, email, scim_external_id, email_verified, display_name,
               password_hash, status, created_at, updated_at, last_login_at
        FROM users
        WHERE organization_id = $1 AND id = $2
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;

    row.map(UserRow::try_into_user).transpose()
}

pub(in crate::users::lifecycle) async fn user_email_is_taken(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    user_id: UserId,
    email: &str,
) -> Result<bool, DatabaseError> {
    let owner: Option<Uuid> = sqlx::query_scalar(
        r#"
        SELECT id
        FROM users
        WHERE organization_id = $1 AND email = $2 AND id <> $3
        "#,
    )
    .bind(organization_id)
    .bind(email)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(owner.is_some())
}

pub(in crate::users::lifecycle) async fn user_scim_external_id_is_taken(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    user_id: UserId,
    external_id: &str,
) -> Result<bool, DatabaseError> {
    let owner: Option<Uuid> = sqlx::query_scalar(
        r#"
        SELECT id
        FROM users
        WHERE organization_id = $1 AND scim_external_id = $2 AND id <> $3
        "#,
    )
    .bind(organization_id)
    .bind(external_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(owner.is_some())
}
