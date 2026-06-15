use crate::codec::{membership_role_to_str, user_status_to_str};
use crate::repository_helpers::active_group_owner_count_excluding_user_in_transaction;
use crate::rows::GroupRow;
use crate::{Database, DatabaseError, MembershipMutationOutcome};
use cairn_domain::{GroupId, Membership, MembershipRole, OrganizationId, UserId, UserStatus};
use sqlx::{Postgres, Transaction};

impl Database {
    pub async fn create_membership(&self, membership: &Membership) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO memberships (organization_id, user_id, group_id, role, created_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(membership.organization_id)
        .bind(membership.user_id)
        .bind(membership.group_id)
        .bind(membership_role_to_str(membership.role))
        .bind(membership.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_group_membership(
        &self,
        membership: &Membership,
        protected_owner_group_slug: &str,
    ) -> Result<MembershipMutationOutcome, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let Some(group) =
            locked_group_in_transaction(&mut tx, membership.organization_id, membership.group_id)
                .await?
        else {
            return Ok(MembershipMutationOutcome::NotFound);
        };

        if !user_exists_in_transaction(&mut tx, membership.organization_id, membership.user_id)
            .await?
        {
            return Ok(MembershipMutationOutcome::NotFound);
        }

        let existing_role = locked_membership_role_in_transaction(
            &mut tx,
            membership.organization_id,
            membership.group_id,
            membership.user_id,
        )
        .await?;

        if group.slug == protected_owner_group_slug
            && membership.role != MembershipRole::Owner
            && existing_role.as_deref() == Some(membership_role_to_str(MembershipRole::Owner))
            && would_remove_last_active_owner_in_transaction(
                &mut tx,
                membership.organization_id,
                membership.group_id,
                membership.user_id,
            )
            .await?
        {
            return Ok(MembershipMutationOutcome::WouldRemoveLastOwner);
        }

        sqlx::query(
            r#"
            INSERT INTO memberships (organization_id, user_id, group_id, role, created_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id, group_id) DO UPDATE SET
                role = EXCLUDED.role
            "#,
        )
        .bind(membership.organization_id)
        .bind(membership.user_id)
        .bind(membership.group_id)
        .bind(membership_role_to_str(membership.role))
        .bind(membership.created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(MembershipMutationOutcome::Applied)
    }

    pub async fn delete_group_membership(
        &self,
        organization_id: OrganizationId,
        group_id: GroupId,
        user_id: UserId,
        protected_owner_group_slug: &str,
    ) -> Result<MembershipMutationOutcome, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let Some(group) = locked_group_in_transaction(&mut tx, organization_id, group_id).await?
        else {
            return Ok(MembershipMutationOutcome::NotFound);
        };

        let Some(existing_role) =
            locked_membership_role_in_transaction(&mut tx, organization_id, group_id, user_id)
                .await?
        else {
            return Ok(MembershipMutationOutcome::NotFound);
        };

        if group.slug == protected_owner_group_slug
            && existing_role == membership_role_to_str(MembershipRole::Owner)
            && would_remove_last_active_owner_in_transaction(
                &mut tx,
                organization_id,
                group_id,
                user_id,
            )
            .await?
        {
            return Ok(MembershipMutationOutcome::WouldRemoveLastOwner);
        }

        sqlx::query(
            r#"
            DELETE FROM memberships
            WHERE organization_id = $1 AND group_id = $2 AND user_id = $3
            "#,
        )
        .bind(organization_id)
        .bind(group_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(MembershipMutationOutcome::Applied)
    }
}

async fn locked_group_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    group_id: GroupId,
) -> Result<Option<GroupRow>, DatabaseError> {
    let row = sqlx::query_as::<_, GroupRow>(
        r#"
        SELECT id, organization_id, slug, scim_external_id, display_name, created_at
        FROM groups
        WHERE organization_id = $1 AND id = $2
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .bind(group_id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(row)
}

async fn user_exists_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    user_id: UserId,
) -> Result<bool, DatabaseError> {
    let exists = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM users
            WHERE organization_id = $1 AND id = $2
        )
        "#,
    )
    .bind(organization_id)
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;

    Ok(exists)
}

async fn locked_membership_role_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    group_id: GroupId,
    user_id: UserId,
) -> Result<Option<String>, DatabaseError> {
    let role = sqlx::query_scalar(
        r#"
        SELECT role
        FROM memberships
        WHERE organization_id = $1 AND group_id = $2 AND user_id = $3
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .bind(group_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(role)
}

async fn would_remove_last_active_owner_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    group_id: GroupId,
    user_id: UserId,
) -> Result<bool, DatabaseError> {
    let target_is_active_owner: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM memberships
            INNER JOIN users
                ON users.id = memberships.user_id
               AND users.organization_id = memberships.organization_id
            WHERE memberships.organization_id = $1
              AND memberships.group_id = $2
              AND memberships.user_id = $3
              AND memberships.role = $4
              AND users.status = $5
        )
        "#,
    )
    .bind(organization_id)
    .bind(group_id)
    .bind(user_id)
    .bind(membership_role_to_str(MembershipRole::Owner))
    .bind(user_status_to_str(UserStatus::Active))
    .fetch_one(&mut **tx)
    .await?;

    let other_active_owner_count = active_group_owner_count_excluding_user_in_transaction(
        tx,
        organization_id,
        group_id,
        user_id,
    )
    .await?;

    Ok(target_is_active_owner && other_active_owner_count == 0)
}
