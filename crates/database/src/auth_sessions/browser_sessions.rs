use crate::rows::{AuthSessionRow, BrowserSessionSummaryRow};
use crate::{BrowserSessionSummary, Database, DatabaseError};
use cairn_domain::{AuthSession, OrganizationId, SessionId, UserId};
use time::OffsetDateTime;

impl Database {
    pub async fn list_active_browser_sessions_for_user(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        at: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<BrowserSessionSummary>, DatabaseError> {
        let rows = sqlx::query_as::<_, BrowserSessionSummaryRow>(
            r#"
            SELECT id, organization_id, user_id, acr, amr, created_at, expires_at,
                   created_ip_address, created_user_agent
            FROM auth_sessions
            WHERE organization_id = $1
              AND user_id = $2
              AND revoked_at IS NULL
              AND expires_at > $3
            ORDER BY created_at DESC, id DESC
            LIMIT $4
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(at)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn revoke_user_browser_session(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        session_id: SessionId,
        at: OffsetDateTime,
    ) -> Result<Option<AuthSession>, DatabaseError> {
        let row = sqlx::query_as::<_, AuthSessionRow>(
            r#"
            UPDATE auth_sessions
            SET revoked_at = $1
            WHERE organization_id = $2
              AND user_id = $3
              AND id = $4
              AND revoked_at IS NULL
              AND expires_at > $1
            RETURNING id, organization_id, user_id, acr, amr, created_at, expires_at, revoked_at
            "#,
        )
        .bind(at)
        .bind(organization_id)
        .bind(user_id)
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }
}
