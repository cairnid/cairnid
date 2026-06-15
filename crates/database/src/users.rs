mod bootstrap;
mod lifecycle;
mod queries;

use super::codec::user_status_to_str;
use super::{Database, DatabaseError};
use cairn_domain::{User, UserId};
use time::OffsetDateTime;

impl Database {
    pub async fn create_user(
        &self,
        user: &User,
        password_hash: Option<&str>,
    ) -> Result<(), DatabaseError> {
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
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_user_last_login(
        &self,
        id: UserId,
        at: OffsetDateTime,
    ) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE users SET last_login_at = $1, updated_at = $1 WHERE id = $2")
            .bind(at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_user_password_and_email_verified(
        &self,
        id: UserId,
        password_hash: &str,
        email_verified: bool,
        at: OffsetDateTime,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            UPDATE users
            SET password_hash = $1, email_verified = $2, updated_at = $3
            WHERE id = $4
            "#,
        )
        .bind(password_hash)
        .bind(email_verified)
        .bind(at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_user_email_verified(
        &self,
        id: UserId,
        email_verified: bool,
        at: OffsetDateTime,
    ) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE users SET email_verified = $1, updated_at = $2 WHERE id = $3")
            .bind(email_verified)
            .bind(at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
