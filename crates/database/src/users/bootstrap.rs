use crate::codec::{membership_role_to_str, user_status_to_str};
use crate::{Database, DatabaseError};
use cairn_domain::{Group, Membership, User};
use uuid::Uuid;

impl Database {
    pub async fn create_bootstrap_admin(
        &self,
        user: &User,
        password_hash: &str,
        admin_group: &Group,
        admin_membership: &Membership,
    ) -> Result<bool, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let organization_exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
                .bind(user.organization_id)
                .fetch_optional(&mut *tx)
                .await?;

        if organization_exists.is_none() {
            return Err(DatabaseError::NotFound);
        }

        let existing_users: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM users
            WHERE organization_id = $1
            "#,
        )
        .bind(user.organization_id)
        .fetch_one(&mut *tx)
        .await?;

        if existing_users > 0 {
            return Ok(false);
        }

        sqlx::query(
            r#"
            INSERT INTO users (
                id, organization_id, email, scim_external_id, email_verified, display_name,
                password_hash, status, created_at, updated_at, last_login_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(user.id)
        .bind(user.organization_id)
        .bind(&user.email)
        .bind(&user.scim_external_id)
        .bind(user.email_verified)
        .bind(&user.display_name)
        .bind(password_hash)
        .bind(user_status_to_str(user.status))
        .bind(user.created_at)
        .bind(user.updated_at)
        .bind(user.last_login_at)
        .execute(&mut *tx)
        .await?;

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

        sqlx::query(
            r#"
            INSERT INTO memberships (organization_id, user_id, group_id, role, created_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(admin_membership.organization_id)
        .bind(admin_membership.user_id)
        .bind(admin_membership.group_id)
        .bind(membership_role_to_str(admin_membership.role))
        .bind(admin_membership.created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }
}
