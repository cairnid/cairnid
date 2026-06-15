mod browser_sessions;
mod rotation;

use super::rows::AuthSessionRow;
use super::{AuthSessionCreationInput, Database, DatabaseError, SessionRequestContext};
use cairn_domain::{AuthSession, OrganizationId, SessionId, UserId};
use sqlx::{Executor, Postgres, types::Json};
use time::OffsetDateTime;
use uuid::Uuid;

impl Database {
    pub async fn create_auth_session(&self, session: &AuthSession) -> Result<(), DatabaseError> {
        self.create_auth_session_with_context(session, SessionRequestContext::default())
            .await
    }

    pub async fn create_auth_session_with_context(
        &self,
        session: &AuthSession,
        request_context: SessionRequestContext<'_>,
    ) -> Result<(), DatabaseError> {
        Self::insert_auth_session(&self.pool, session, request_context).await
    }

    pub async fn revoke_auth_session(
        &self,
        id: Uuid,
        at: OffsetDateTime,
    ) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE auth_sessions SET revoked_at = $1 WHERE id = $2")
            .bind(at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn create_auth_session_with_new_context_notification(
        &self,
        input: AuthSessionCreationInput<'_>,
    ) -> Result<Option<Uuid>, DatabaseError> {
        let AuthSessionCreationInput {
            session,
            request_context,
            new_context_notification,
        } = input;
        let should_check_context =
            request_context.has_identifying_context() && new_context_notification.is_some();

        let mut tx = self.pool.begin().await?;
        let known_context = if should_check_context {
            let _ = sqlx::query_scalar::<_, Uuid>(
                r#"
                SELECT id
                FROM users
                WHERE organization_id = $1 AND id = $2
                FOR UPDATE
                "#,
            )
            .bind(session.organization_id)
            .bind(session.user_id)
            .fetch_optional(&mut *tx)
            .await?;

            sqlx::query_scalar::<_, bool>(
                r#"
                SELECT EXISTS (
                    SELECT 1
                    FROM auth_sessions
                    WHERE organization_id = $1
                      AND user_id = $2
                      AND created_ip_address IS NOT DISTINCT FROM $3
                      AND created_user_agent IS NOT DISTINCT FROM $4
                )
                "#,
            )
            .bind(session.organization_id)
            .bind(session.user_id)
            .bind(request_context.ip_address)
            .bind(request_context.user_agent)
            .fetch_one(&mut *tx)
            .await?
        } else {
            true
        };

        Self::insert_auth_session(&mut *tx, session, request_context).await?;

        let notification_email_outbox_id = if known_context {
            None
        } else if let Some(message) = new_context_notification {
            debug_assert_eq!(message.organization_id, session.organization_id);
            Self::insert_email_outbox_message_in_tx(&mut tx, message).await?;
            Some(message.id)
        } else {
            None
        };

        tx.commit().await?;
        Ok(notification_email_outbox_id)
    }

    async fn insert_auth_session<'e, E>(
        executor: E,
        session: &AuthSession,
        request_context: SessionRequestContext<'_>,
    ) -> Result<(), DatabaseError>
    where
        E: Executor<'e, Database = Postgres>,
    {
        sqlx::query(
            r#"
            INSERT INTO auth_sessions (
                id, organization_id, user_id, acr, amr, created_at, expires_at, revoked_at,
                created_ip_address, created_user_agent
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(session.id)
        .bind(session.organization_id)
        .bind(session.user_id)
        .bind(&session.acr)
        .bind(Json(&session.amr))
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session.revoked_at)
        .bind(request_context.ip_address)
        .bind(request_context.user_agent)
        .execute(executor)
        .await?;
        Ok(())
    }

    pub async fn get_auth_session(&self, id: Uuid) -> Result<Option<AuthSession>, DatabaseError> {
        let row = sqlx::query_as::<_, AuthSessionRow>(
            r#"
            SELECT id, organization_id, user_id, acr, amr, created_at, expires_at, revoked_at
            FROM auth_sessions
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    pub async fn set_auth_session_request_context(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        session_id: SessionId,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            UPDATE auth_sessions
            SET created_ip_address = $1, created_user_agent = $2
            WHERE organization_id = $3 AND user_id = $4 AND id = $5
            "#,
        )
        .bind(ip_address)
        .bind(user_agent)
        .bind(organization_id)
        .bind(user_id)
        .bind(session_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn revoke_user_sessions(
        &self,
        user_id: UserId,
        at: OffsetDateTime,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            UPDATE auth_sessions
            SET revoked_at = COALESCE(revoked_at, $1)
            WHERE user_id = $2
            "#,
        )
        .bind(at)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
