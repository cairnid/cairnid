use crate::codec::{
    audit_actor_kind_to_str, membership_role_from_str, membership_role_to_str, user_status_to_str,
};
use crate::rows::{GroupRow, UserRow};
use crate::{BreakGlassAdminRecovery, Database, DatabaseError};
use cairn_domain::{
    AuditActorKind, AuditEvent, Group, MembershipRole, OrganizationId, UserId, UserStatus,
};
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

impl Database {
    pub async fn break_glass_grant_admin_owner(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        admin_group: &Group,
        at: OffsetDateTime,
        audit_event: &AuditEvent,
    ) -> Result<Option<BreakGlassAdminRecovery>, DatabaseError> {
        debug_assert_eq!(admin_group.organization_id, organization_id);
        debug_assert_eq!(audit_event.organization_id, organization_id);
        debug_assert_eq!(audit_event.actor_kind, AuditActorKind::System);

        let mut tx = self.pool.begin().await?;
        let organization_exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
                .bind(organization_id)
                .fetch_optional(&mut *tx)
                .await?;

        if organization_exists.is_none() {
            return Err(DatabaseError::NotFound);
        }

        let Some(user_row) = sqlx::query_as::<_, UserRow>(
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
        .fetch_optional(&mut *tx)
        .await?
        else {
            tx.commit().await?;
            return Ok(None);
        };
        let user = user_row.try_into_user()?;

        let group_row = sqlx::query_as::<_, GroupRow>(
            r#"
            SELECT id, organization_id, slug, scim_external_id, display_name, created_at
            FROM groups
            WHERE organization_id = $1 AND slug = $2
            FOR UPDATE
            "#,
        )
        .bind(organization_id)
        .bind(&admin_group.slug)
        .fetch_optional(&mut *tx)
        .await?;
        let (admin_group_id, admin_group_created) = match group_row {
            Some(row) => (row.id, false),
            None => {
                sqlx::query(
                    r#"
                    INSERT INTO groups (id, organization_id, slug, scim_external_id, display_name, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    "#,
                )
                .bind(admin_group.id)
                .bind(admin_group.organization_id)
                .bind(&admin_group.slug)
                .bind(&admin_group.scim_external_id)
                .bind(&admin_group.display_name)
                .bind(admin_group.created_at)
                .execute(&mut *tx)
                .await?;
                (admin_group.id, true)
            }
        };

        let existing_role = sqlx::query_scalar::<_, String>(
            r#"
            SELECT role
            FROM memberships
            WHERE organization_id = $1 AND group_id = $2 AND user_id = $3
            FOR UPDATE
            "#,
        )
        .bind(organization_id)
        .bind(admin_group_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let membership_role_before = existing_role
            .as_deref()
            .map(membership_role_from_str)
            .transpose()?;
        let membership_role_after = MembershipRole::Owner;

        sqlx::query(
            r#"
            INSERT INTO memberships (organization_id, user_id, group_id, role, created_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id, group_id) DO UPDATE SET
                role = EXCLUDED.role
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(admin_group_id)
        .bind(membership_role_to_str(membership_role_after))
        .bind(at)
        .execute(&mut *tx)
        .await?;

        let updated_row = sqlx::query_as::<_, UserRow>(
            r#"
            UPDATE users
            SET status = $1, updated_at = $2
            WHERE organization_id = $3 AND id = $4
            RETURNING id, organization_id, email, scim_external_id, email_verified, display_name,
                      password_hash, status, created_at, updated_at, last_login_at
            "#,
        )
        .bind(user_status_to_str(UserStatus::Active))
        .bind(at)
        .bind(organization_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;
        let updated_user = updated_row.try_into_user()?;

        sqlx::query(
            r#"
            INSERT INTO audit_events (
                id, organization_id, actor_kind, actor_id, action, target,
                ip_address, user_agent, metadata, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(audit_event.id)
        .bind(audit_event.organization_id)
        .bind(audit_actor_kind_to_str(audit_event.actor_kind))
        .bind(audit_event.actor_id)
        .bind(&audit_event.action)
        .bind(&audit_event.target)
        .bind(&audit_event.ip_address)
        .bind(&audit_event.user_agent)
        .bind(Json(&audit_event.metadata))
        .bind(audit_event.created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(BreakGlassAdminRecovery {
            organization_id,
            user_id,
            user_email: updated_user.email,
            user_status_before: user.status,
            user_status_after: updated_user.status,
            admin_group_id,
            admin_group_created,
            membership_role_before,
            membership_role_after,
        }))
    }
}
