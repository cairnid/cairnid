use crate::rows::MembershipRow;
use crate::{Database, DatabaseError, ListCursor};
use cairn_domain::{GroupId, Membership, OrganizationId, UserId};

impl Database {
    pub async fn list_group_memberships(
        &self,
        organization_id: OrganizationId,
        group_id: GroupId,
        limit: i64,
    ) -> Result<Vec<Membership>, DatabaseError> {
        self.list_group_memberships_page(organization_id, group_id, None, limit)
            .await
    }

    pub async fn list_group_memberships_page(
        &self,
        organization_id: OrganizationId,
        group_id: GroupId,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<Membership>, DatabaseError> {
        let rows = sqlx::query_as::<_, MembershipRow>(
            r#"
            SELECT organization_id, user_id, group_id, role, created_at
            FROM memberships
            WHERE organization_id = $1 AND group_id = $2
              AND (
                  $3::timestamptz IS NULL
                  OR created_at < $3
                  OR (created_at = $3 AND user_id < $4)
              )
            ORDER BY created_at DESC, user_id DESC
            LIMIT $5
            "#,
        )
        .bind(organization_id)
        .bind(group_id)
        .bind(after.map(|cursor| cursor.created_at))
        .bind(after.map(|cursor| cursor.tie_breaker_id))
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(MembershipRow::try_into_membership)
            .collect()
    }

    pub async fn get_group_membership(
        &self,
        organization_id: OrganizationId,
        group_id: GroupId,
        user_id: UserId,
    ) -> Result<Option<Membership>, DatabaseError> {
        let row = sqlx::query_as::<_, MembershipRow>(
            r#"
            SELECT organization_id, user_id, group_id, role, created_at
            FROM memberships
            WHERE organization_id = $1 AND group_id = $2 AND user_id = $3
            "#,
        )
        .bind(organization_id)
        .bind(group_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(MembershipRow::try_into_membership).transpose()
    }

    pub async fn list_user_group_slugs(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
    ) -> Result<Vec<String>, DatabaseError> {
        let rows = sqlx::query_scalar::<_, String>(
            r#"
            SELECT groups.slug
            FROM memberships
            INNER JOIN groups
                ON groups.id = memberships.group_id
               AND groups.organization_id = memberships.organization_id
            WHERE memberships.organization_id = $1
              AND memberships.user_id = $2
            ORDER BY groups.slug
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }
}
