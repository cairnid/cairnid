use crate::codec::user_status_to_str;
use crate::repository_helpers::prefix_search_pattern;
use crate::rows::UserRow;
use crate::{
    Database, DatabaseError, ListCursor, ScimUserListFilter, UserListFilter, UserWithPassword,
};
use cairn_domain::{OrganizationId, User, UserId, UserStatus};

impl Database {
    pub async fn active_user_count(
        &self,
        organization_id: OrganizationId,
    ) -> Result<i64, DatabaseError> {
        let count = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM users
            WHERE organization_id = $1 AND status = $2
            "#,
        )
        .bind(organization_id)
        .bind(user_status_to_str(UserStatus::Active))
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    pub async fn count_users(&self, organization_id: OrganizationId) -> Result<i64, DatabaseError> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM users
            WHERE organization_id = $1
            "#,
        )
        .bind(organization_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    pub async fn list_users(
        &self,
        organization_id: OrganizationId,
        limit: i64,
    ) -> Result<Vec<User>, DatabaseError> {
        self.list_users_page(organization_id, None, limit).await
    }

    pub async fn list_users_page(
        &self,
        organization_id: OrganizationId,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<User>, DatabaseError> {
        self.list_users_page_filtered(organization_id, &UserListFilter::default(), after, limit)
            .await
    }

    pub async fn list_users_page_filtered(
        &self,
        organization_id: OrganizationId,
        filter: &UserListFilter,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<User>, DatabaseError> {
        let search_pattern = prefix_search_pattern(filter.search_prefix.as_deref());
        let status = filter.status.map(user_status_to_str);
        let rows = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, organization_id, email, scim_external_id, email_verified, display_name,
                   password_hash, status, created_at, updated_at, last_login_at
            FROM users
            WHERE organization_id = $1
              AND (
                  $2::timestamptz IS NULL
                  OR created_at < $2
                  OR (created_at = $2 AND id < $3)
              )
              AND (
                  $4::text IS NULL
                  OR lower(email) LIKE $4
                  OR lower(display_name) LIKE $4
              )
              AND ($5::text IS NULL OR status = $5)
            ORDER BY created_at DESC, id DESC
            LIMIT $6
            "#,
        )
        .bind(organization_id)
        .bind(after.map(|cursor| cursor.created_at))
        .bind(after.map(|cursor| cursor.tie_breaker_id))
        .bind(search_pattern)
        .bind(status)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(UserRow::try_into_user).collect()
    }

    pub async fn find_user_by_email(
        &self,
        organization_id: OrganizationId,
        email: &str,
    ) -> Result<Option<UserWithPassword>, DatabaseError> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, organization_id, email, scim_external_id, email_verified, display_name,
                   password_hash, status, created_at, updated_at, last_login_at
            FROM users
            WHERE organization_id = $1 AND email = $2
            "#,
        )
        .bind(organization_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        row.map(UserWithPassword::try_from_row).transpose()
    }

    pub async fn find_user_by_scim_external_id(
        &self,
        organization_id: OrganizationId,
        external_id: &str,
    ) -> Result<Option<User>, DatabaseError> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, organization_id, email, scim_external_id, email_verified, display_name,
                   password_hash, status, created_at, updated_at, last_login_at
            FROM users
            WHERE organization_id = $1 AND scim_external_id = $2
            "#,
        )
        .bind(organization_id)
        .bind(external_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(UserRow::try_into_user).transpose()
    }

    pub async fn list_scim_users_page_filtered(
        &self,
        organization_id: OrganizationId,
        filter: &ScimUserListFilter,
        start_index: i64,
        count: i64,
    ) -> Result<(i64, Vec<User>), DatabaseError> {
        let offset = start_index.saturating_sub(1);
        let active_status = user_status_to_str(UserStatus::Active);
        let total_results: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM users
            WHERE organization_id = $1
              AND ($2::text IS NULL OR email = $2)
              AND ($3::text IS NULL OR scim_external_id = $3)
              AND (
                  $4::bool IS NULL
                  OR ($4 = TRUE AND status = $5)
                  OR ($4 = FALSE AND status <> $5)
              )
            "#,
        )
        .bind(organization_id)
        .bind(filter.user_name_eq.as_deref())
        .bind(filter.external_id_eq.as_deref())
        .bind(filter.active_eq)
        .bind(active_status)
        .fetch_one(&self.pool)
        .await?;

        let rows = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, organization_id, email, scim_external_id, email_verified, display_name,
                   password_hash, status, created_at, updated_at, last_login_at
            FROM users
            WHERE organization_id = $1
              AND ($2::text IS NULL OR email = $2)
              AND ($3::text IS NULL OR scim_external_id = $3)
              AND (
                  $4::bool IS NULL
                  OR ($4 = TRUE AND status = $5)
                  OR ($4 = FALSE AND status <> $5)
              )
            ORDER BY created_at DESC, id DESC
            OFFSET $6
            LIMIT $7
            "#,
        )
        .bind(organization_id)
        .bind(filter.user_name_eq.as_deref())
        .bind(filter.external_id_eq.as_deref())
        .bind(filter.active_eq)
        .bind(active_status)
        .bind(offset)
        .bind(count)
        .fetch_all(&self.pool)
        .await?;

        Ok((
            total_results,
            rows.into_iter()
                .map(UserRow::try_into_user)
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }

    pub async fn get_user_with_password(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
    ) -> Result<Option<UserWithPassword>, DatabaseError> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, organization_id, email, scim_external_id, email_verified, display_name,
                   password_hash, status, created_at, updated_at, last_login_at
            FROM users
            WHERE organization_id = $1 AND id = $2
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(UserWithPassword::try_from_row).transpose()
    }

    pub async fn get_user(&self, id: UserId) -> Result<Option<User>, DatabaseError> {
        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT id, organization_id, email, scim_external_id, email_verified, display_name,
                   password_hash, status, created_at, updated_at, last_login_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(UserRow::try_into_user).transpose()
    }
}
