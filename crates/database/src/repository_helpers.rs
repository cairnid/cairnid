use super::DatabaseError;
use super::codec::{membership_role_to_str, user_status_to_str};
use cairn_domain::{GroupId, MembershipRole, OrganizationId, UserId, UserStatus};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

pub(super) fn prefix_search_pattern(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("{}%", value.to_ascii_lowercase()))
}

pub(super) async fn all_users_exist_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    user_ids: &[UserId],
) -> Result<bool, DatabaseError> {
    if user_ids.is_empty() {
        return Ok(true);
    }

    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(DISTINCT id)
        FROM users
        WHERE organization_id = $1
          AND id = ANY($2::uuid[])
        "#,
    )
    .bind(organization_id)
    .bind(user_ids)
    .fetch_one(&mut **tx)
    .await?;

    Ok(count == user_ids.len() as i64)
}

pub(super) async fn insert_scim_group_member_ids_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    group_id: GroupId,
    user_ids: &[UserId],
    created_at: OffsetDateTime,
) -> Result<(), DatabaseError> {
    if user_ids.is_empty() {
        return Ok(());
    }

    sqlx::query(
        r#"
        INSERT INTO memberships (organization_id, user_id, group_id, role, created_at)
        SELECT $1, selected.user_id, $2, $3, $4
        FROM UNNEST($5::uuid[]) AS selected(user_id)
        ON CONFLICT (user_id, group_id) DO UPDATE SET
            role = EXCLUDED.role
        "#,
    )
    .bind(organization_id)
    .bind(group_id)
    .bind(membership_role_to_str(MembershipRole::Member))
    .bind(created_at)
    .bind(user_ids)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

pub(super) async fn active_group_owner_count_excluding_user_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    group_id: GroupId,
    excluded_user_id: UserId,
) -> Result<i64, DatabaseError> {
    let count = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM memberships
        INNER JOIN users
            ON users.id = memberships.user_id
           AND users.organization_id = memberships.organization_id
        WHERE memberships.organization_id = $1
          AND memberships.group_id = $2
          AND memberships.user_id <> $3
          AND memberships.role = $4
          AND users.status = $5
        "#,
    )
    .bind(organization_id)
    .bind(group_id)
    .bind(excluded_user_id)
    .bind(membership_role_to_str(MembershipRole::Owner))
    .bind(user_status_to_str(UserStatus::Active))
    .fetch_one(&mut **tx)
    .await?;

    Ok(count)
}
