use crate::repository_helpers::{
    all_users_exist_in_transaction, insert_scim_group_member_ids_in_transaction,
};
use crate::rows::GroupRow;
use crate::{Database, DatabaseError, ScimGroupMutationOutcome, ScimGroupReplaceInput};
use cairn_domain::{Group, GroupId, OrganizationId, UserId};
use sqlx::{Postgres, Transaction};

impl Database {
    pub async fn create_scim_group(
        &self,
        group: &Group,
        member_user_ids: &[UserId],
    ) -> Result<ScimGroupMutationOutcome, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        if group_slug_exists_in_transaction(&mut tx, group.organization_id, &group.slug).await? {
            return Ok(ScimGroupMutationOutcome::SlugAlreadyExists);
        }

        if let Some(external_id) = group.scim_external_id.as_deref()
            && group_external_id_exists_in_transaction(
                &mut tx,
                group.organization_id,
                external_id,
                None,
            )
            .await?
        {
            return Ok(ScimGroupMutationOutcome::ExternalIdAlreadyExists);
        }

        if !all_users_exist_in_transaction(&mut tx, group.organization_id, member_user_ids).await? {
            return Ok(ScimGroupMutationOutcome::MemberNotFound);
        }

        sqlx::query(
            r#"
            INSERT INTO groups (id, organization_id, slug, scim_external_id, display_name, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(group.id)
        .bind(group.organization_id)
        .bind(&group.slug)
        .bind(&group.scim_external_id)
        .bind(&group.display_name)
        .bind(group.created_at)
        .execute(&mut *tx)
        .await?;

        insert_scim_group_member_ids_in_transaction(
            &mut tx,
            group.organization_id,
            group.id,
            member_user_ids,
            group.created_at,
        )
        .await?;

        tx.commit().await?;
        Ok(ScimGroupMutationOutcome::Applied(group.clone()))
    }

    pub async fn replace_scim_group(
        &self,
        input: ScimGroupReplaceInput<'_>,
    ) -> Result<ScimGroupMutationOutcome, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let Some(existing_group) =
            locked_group_in_transaction(&mut tx, input.organization_id, input.group_id).await?
        else {
            return Ok(ScimGroupMutationOutcome::NotFound);
        };

        if existing_group.slug == input.protected_group_slug {
            return Ok(ScimGroupMutationOutcome::WouldModifyProtectedGroup);
        }

        if let Some(external_id) = input.scim_external_id
            && group_external_id_exists_in_transaction(
                &mut tx,
                input.organization_id,
                external_id,
                Some(input.group_id),
            )
            .await?
        {
            return Ok(ScimGroupMutationOutcome::ExternalIdAlreadyExists);
        }

        if !all_users_exist_in_transaction(&mut tx, input.organization_id, input.member_user_ids)
            .await?
        {
            return Ok(ScimGroupMutationOutcome::MemberNotFound);
        }

        let updated_group = sqlx::query_as::<_, GroupRow>(
            r#"
            UPDATE groups
            SET display_name = $1,
                scim_external_id = $2
            WHERE organization_id = $3 AND id = $4
            RETURNING id, organization_id, slug, scim_external_id, display_name, created_at
            "#,
        )
        .bind(input.display_name)
        .bind(input.scim_external_id)
        .bind(input.organization_id)
        .bind(input.group_id)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            DELETE FROM memberships
            WHERE organization_id = $1
              AND group_id = $2
              AND NOT (user_id = ANY($3::uuid[]))
            "#,
        )
        .bind(input.organization_id)
        .bind(input.group_id)
        .bind(input.member_user_ids)
        .execute(&mut *tx)
        .await?;

        insert_scim_group_member_ids_in_transaction(
            &mut tx,
            input.organization_id,
            input.group_id,
            input.member_user_ids,
            input.at,
        )
        .await?;

        tx.commit().await?;
        Ok(ScimGroupMutationOutcome::Applied(updated_group.into()))
    }

    pub async fn delete_scim_group(
        &self,
        organization_id: OrganizationId,
        group_id: GroupId,
        protected_group_slug: &str,
    ) -> Result<ScimGroupMutationOutcome, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let Some(group) = locked_group_in_transaction(&mut tx, organization_id, group_id).await?
        else {
            return Ok(ScimGroupMutationOutcome::NotFound);
        };

        if group.slug == protected_group_slug {
            return Ok(ScimGroupMutationOutcome::WouldModifyProtectedGroup);
        }

        sqlx::query(
            r#"
            DELETE FROM groups
            WHERE organization_id = $1 AND id = $2
            "#,
        )
        .bind(organization_id)
        .bind(group_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(ScimGroupMutationOutcome::Applied(group.into()))
    }
}

async fn group_slug_exists_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    slug: &str,
) -> Result<bool, DatabaseError> {
    let exists = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM groups
            WHERE organization_id = $1 AND slug = $2
        )
        "#,
    )
    .bind(organization_id)
    .bind(slug)
    .fetch_one(&mut **tx)
    .await?;

    Ok(exists)
}

async fn group_external_id_exists_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    external_id: &str,
    excluded_group_id: Option<GroupId>,
) -> Result<bool, DatabaseError> {
    let exists = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM groups
            WHERE organization_id = $1
              AND scim_external_id = $2
              AND ($3::uuid IS NULL OR id <> $3)
        )
        "#,
    )
    .bind(organization_id)
    .bind(external_id)
    .bind(excluded_group_id)
    .fetch_one(&mut **tx)
    .await?;

    Ok(exists)
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
