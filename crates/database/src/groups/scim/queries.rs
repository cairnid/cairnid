use crate::rows::{GroupRow, ScimGroupMemberRow};
use crate::{Database, DatabaseError, ScimGroupListFilter, ScimGroupMember};
use cairn_domain::{Group, GroupId, OrganizationId};

impl Database {
    pub async fn list_scim_groups_page_filtered(
        &self,
        organization_id: OrganizationId,
        filter: &ScimGroupListFilter,
        start_index: i64,
        count: i64,
    ) -> Result<(i64, Vec<Group>), DatabaseError> {
        let offset = start_index.saturating_sub(1);
        let total_results: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM groups
            WHERE organization_id = $1
              AND ($2::text IS NULL OR display_name = $2)
              AND ($3::text IS NULL OR scim_external_id = $3)
            "#,
        )
        .bind(organization_id)
        .bind(filter.display_name_eq.as_deref())
        .bind(filter.external_id_eq.as_deref())
        .fetch_one(&self.pool)
        .await?;

        let rows = sqlx::query_as::<_, GroupRow>(
            r#"
            SELECT id, organization_id, slug, scim_external_id, display_name, created_at
            FROM groups
            WHERE organization_id = $1
              AND ($2::text IS NULL OR display_name = $2)
              AND ($3::text IS NULL OR scim_external_id = $3)
            ORDER BY created_at DESC, id DESC
            OFFSET $4
            LIMIT $5
            "#,
        )
        .bind(organization_id)
        .bind(filter.display_name_eq.as_deref())
        .bind(filter.external_id_eq.as_deref())
        .bind(offset)
        .bind(count)
        .fetch_all(&self.pool)
        .await?;

        Ok((total_results, rows.into_iter().map(Into::into).collect()))
    }

    pub async fn list_scim_group_members_for_groups(
        &self,
        organization_id: OrganizationId,
        group_ids: &[GroupId],
    ) -> Result<Vec<ScimGroupMember>, DatabaseError> {
        if group_ids.is_empty() {
            return Ok(Vec::new());
        }

        let rows = sqlx::query_as::<_, ScimGroupMemberRow>(
            r#"
            SELECT
                memberships.group_id,
                memberships.user_id,
                users.email,
                users.display_name,
                memberships.role,
                memberships.created_at
            FROM memberships
            INNER JOIN users
                ON users.id = memberships.user_id
               AND users.organization_id = memberships.organization_id
            WHERE memberships.organization_id = $1
              AND memberships.group_id = ANY($2::uuid[])
            ORDER BY memberships.group_id ASC, users.email ASC, memberships.user_id ASC
            "#,
        )
        .bind(organization_id)
        .bind(group_ids)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(ScimGroupMemberRow::try_into_member)
            .collect()
    }
}
