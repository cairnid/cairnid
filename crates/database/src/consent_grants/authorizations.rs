use crate::rows::{ConsentAuthorizationRow, ConsentGrantRow};
use crate::{ConsentAuthorizationConsumption, Database, DatabaseError};
use cairn_domain::{ConsentAuthorization, OrganizationId, UserId};
use sqlx::types::Json;
use uuid::Uuid;

impl Database {
    pub async fn create_consent_authorization(
        &self,
        authorization: &ConsentAuthorization,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO consent_authorizations (
                id, organization_id, user_id, session_id, client_id, authorization_request_hash, scopes,
                created_at, expires_at, consumed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(authorization.id)
        .bind(authorization.organization_id)
        .bind(authorization.user_id)
        .bind(authorization.session_id)
        .bind(authorization.client_id)
        .bind(&authorization.authorization_request_hash)
        .bind(Json(&authorization.scopes))
        .bind(authorization.created_at)
        .bind(authorization.expires_at)
        .bind(authorization.consumed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn consume_consent_authorization(
        &self,
        request: ConsentAuthorizationConsumption<'_>,
    ) -> Result<bool, DatabaseError> {
        let rows = sqlx::query_as::<_, ConsentAuthorizationRow>(
            r#"
            SELECT id, scopes
            FROM consent_authorizations
            WHERE organization_id = $1
              AND user_id = $2
              AND session_id = $3
              AND client_id = $4
              AND authorization_request_hash = $5
              AND consumed_at IS NULL
              AND expires_at > $6
            ORDER BY created_at DESC, id DESC
            "#,
        )
        .bind(request.organization_id)
        .bind(request.user_id)
        .bind(request.session_id)
        .bind(request.client_id)
        .bind(request.authorization_request_hash)
        .bind(request.at)
        .fetch_all(&self.pool)
        .await?;

        for row in rows {
            let authorized = row.scopes.0;
            if !request
                .scopes
                .iter()
                .all(|scope| authorized.iter().any(|candidate| candidate == scope))
            {
                continue;
            }

            let updated = sqlx::query(
                r#"
                UPDATE consent_authorizations
                SET consumed_at = $1
                WHERE id = $2 AND consumed_at IS NULL
                "#,
            )
            .bind(request.at)
            .bind(row.id)
            .execute(&self.pool)
            .await?
            .rows_affected();

            if updated == 1 {
                return Ok(true);
            }
        }

        Ok(false)
    }

    pub async fn has_active_consent_grant(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        client_id: Uuid,
        scopes: &[String],
    ) -> Result<bool, DatabaseError> {
        let rows = sqlx::query_as::<_, ConsentGrantRow>(
            r#"
            SELECT id, organization_id, user_id, client_id, scopes, created_at, revoked_at
            FROM consent_grants
            WHERE organization_id = $1 AND user_id = $2 AND client_id = $3 AND revoked_at IS NULL
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(client_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().any(|row| {
            let granted = row.scopes.0;
            scopes
                .iter()
                .all(|scope| granted.iter().any(|candidate| candidate == scope))
        }))
    }
}
