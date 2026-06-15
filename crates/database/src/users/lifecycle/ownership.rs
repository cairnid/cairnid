use crate::{
    DatabaseError, codec::membership_role_to_str,
    repository_helpers::active_group_owner_count_excluding_user_in_transaction,
};
use cairn_domain::{GroupId, MembershipRole, OrganizationId, UserId, UserStatus};
use sqlx::{Postgres, Transaction};

pub(in crate::users::lifecycle) async fn deactivation_would_remove_last_owner(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    user_id: UserId,
    current_status: UserStatus,
    next_status: UserStatus,
    protected_owner_group_slug: &str,
) -> Result<bool, DatabaseError> {
    if current_status != UserStatus::Active || next_status == UserStatus::Active {
        return Ok(false);
    }

    let Some(group_id) =
        protected_owner_group_id_for_update(tx, organization_id, protected_owner_group_slug)
            .await?
    else {
        return Ok(false);
    };

    if !user_is_group_owner(tx, organization_id, group_id, user_id).await? {
        return Ok(false);
    }

    Ok(active_group_owner_count_excluding_user_in_transaction(
        tx,
        organization_id,
        group_id,
        user_id,
    )
    .await?
        == 0)
}

async fn protected_owner_group_id_for_update(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    protected_owner_group_slug: &str,
) -> Result<Option<GroupId>, DatabaseError> {
    let group_id = sqlx::query_scalar(
        r#"
        SELECT id
        FROM groups
        WHERE organization_id = $1 AND slug = $2
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .bind(protected_owner_group_slug)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(group_id)
}

async fn user_is_group_owner(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    group_id: GroupId,
    user_id: UserId,
) -> Result<bool, DatabaseError> {
    let user_is_owner = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM memberships
            WHERE organization_id = $1
              AND group_id = $2
              AND user_id = $3
              AND role = $4
        )
        "#,
    )
    .bind(organization_id)
    .bind(group_id)
    .bind(user_id)
    .bind(membership_role_to_str(MembershipRole::Owner))
    .fetch_one(&mut **tx)
    .await?;

    Ok(user_is_owner)
}
