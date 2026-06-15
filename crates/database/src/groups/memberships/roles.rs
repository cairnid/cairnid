use crate::codec::membership_role_to_str;
use crate::{Database, DatabaseError};
use cairn_domain::{MembershipRole, OrganizationId, UserId};

impl Database {
    pub async fn user_has_group_role(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        group_slug: &str,
        roles: &[MembershipRole],
    ) -> Result<bool, DatabaseError> {
        if roles.is_empty() {
            return Ok(false);
        }

        let role_values = roles
            .iter()
            .map(|role| membership_role_to_str(*role).to_owned())
            .collect::<Vec<_>>();
        let has_role: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM memberships
                INNER JOIN groups
                    ON groups.id = memberships.group_id
                   AND groups.organization_id = memberships.organization_id
                WHERE memberships.organization_id = $1
                  AND memberships.user_id = $2
                  AND groups.slug = $3
                  AND memberships.role = ANY($4::text[])
            )
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(group_slug)
        .bind(role_values)
        .fetch_one(&self.pool)
        .await?;

        Ok(has_role)
    }
}
