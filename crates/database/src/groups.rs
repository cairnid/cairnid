mod break_glass;
mod memberships;
mod scim;

use super::rows::GroupRow;
use super::{Database, DatabaseError, ListCursor};
use cairn_domain::{Group, GroupId, OrganizationId};

impl Database {
    pub async fn create_group(&self, group: &Group) -> Result<(), DatabaseError> {
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_group_by_slug(
        &self,
        organization_id: OrganizationId,
        slug: &str,
    ) -> Result<Option<Group>, DatabaseError> {
        let row = sqlx::query_as::<_, GroupRow>(
            r#"
            SELECT id, organization_id, slug, scim_external_id, display_name, created_at
            FROM groups
            WHERE organization_id = $1 AND slug = $2
            "#,
        )
        .bind(organization_id)
        .bind(slug)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    pub async fn get_group(
        &self,
        organization_id: OrganizationId,
        group_id: GroupId,
    ) -> Result<Option<Group>, DatabaseError> {
        let row = sqlx::query_as::<_, GroupRow>(
            r#"
            SELECT id, organization_id, slug, scim_external_id, display_name, created_at
            FROM groups
            WHERE organization_id = $1 AND id = $2
            "#,
        )
        .bind(organization_id)
        .bind(group_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    pub async fn find_group_by_scim_external_id(
        &self,
        organization_id: OrganizationId,
        external_id: &str,
    ) -> Result<Option<Group>, DatabaseError> {
        let row = sqlx::query_as::<_, GroupRow>(
            r#"
            SELECT id, organization_id, slug, scim_external_id, display_name, created_at
            FROM groups
            WHERE organization_id = $1 AND scim_external_id = $2
            "#,
        )
        .bind(organization_id)
        .bind(external_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    pub async fn list_groups(
        &self,
        organization_id: OrganizationId,
        limit: i64,
    ) -> Result<Vec<Group>, DatabaseError> {
        self.list_groups_page(organization_id, None, limit).await
    }

    pub async fn list_groups_page(
        &self,
        organization_id: OrganizationId,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<Group>, DatabaseError> {
        let rows = sqlx::query_as::<_, GroupRow>(
            r#"
            SELECT id, organization_id, slug, scim_external_id, display_name, created_at
            FROM groups
            WHERE organization_id = $1
              AND (
                  $2::timestamptz IS NULL
                  OR created_at < $2
                  OR (created_at = $2 AND id < $3)
              )
            ORDER BY created_at DESC, id DESC
            LIMIT $4
            "#,
        )
        .bind(organization_id)
        .bind(after.map(|cursor| cursor.created_at))
        .bind(after.map(|cursor| cursor.tie_breaker_id))
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }
}
