use crate::{Database, DatabaseError, SessionRequestContext};
use cairn_domain::AuthSession;
use time::OffsetDateTime;
use uuid::Uuid;

impl Database {
    pub async fn rotate_auth_session(
        &self,
        old_session_id: Uuid,
        new_session: &AuthSession,
        at: OffsetDateTime,
    ) -> Result<(), DatabaseError> {
        self.rotate_auth_session_with_context(
            old_session_id,
            new_session,
            at,
            SessionRequestContext::default(),
        )
        .await
    }

    pub async fn rotate_auth_session_with_context(
        &self,
        old_session_id: Uuid,
        new_session: &AuthSession,
        at: OffsetDateTime,
        request_context: SessionRequestContext<'_>,
    ) -> Result<(), DatabaseError> {
        debug_assert_ne!(old_session_id, new_session.id);

        let mut tx = self.pool.begin().await?;
        let revoked = sqlx::query(
            r#"
            UPDATE auth_sessions
            SET revoked_at = $1
            WHERE id = $2
              AND organization_id = $3
              AND user_id = $4
              AND revoked_at IS NULL
              AND expires_at > $1
            "#,
        )
        .bind(at)
        .bind(old_session_id)
        .bind(new_session.organization_id)
        .bind(new_session.user_id)
        .execute(&mut *tx)
        .await?;

        if revoked.rows_affected() != 1 {
            return Err(DatabaseError::NotFound);
        }

        Self::insert_auth_session(&mut *tx, new_session, request_context).await?;

        tx.commit().await?;
        Ok(())
    }
}
