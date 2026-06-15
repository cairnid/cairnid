use crate::rows::ConsentGrantSummaryRow;
use crate::{ConsentGrantRevocation, ConsentGrantSummary, Database, DatabaseError};
use cairn_domain::{ClientId, ConsentGrantId, OrganizationId, UserId};
use time::OffsetDateTime;

impl Database {
    pub async fn revoke_user_client_consent_and_tokens(
        &self,
        organization_id: OrganizationId,
        client_id: ClientId,
        grant_id: ConsentGrantId,
        at: OffsetDateTime,
    ) -> Result<Option<ConsentGrantRevocation>, DatabaseError> {
        self.revoke_consent_grant_and_tokens(organization_id, Some(client_id), None, grant_id, at)
            .await
    }

    pub async fn revoke_current_user_consent_and_tokens(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        grant_id: ConsentGrantId,
        at: OffsetDateTime,
    ) -> Result<Option<ConsentGrantRevocation>, DatabaseError> {
        self.revoke_consent_grant_and_tokens(organization_id, None, Some(user_id), grant_id, at)
            .await
    }

    async fn revoke_consent_grant_and_tokens(
        &self,
        organization_id: OrganizationId,
        client_id: Option<ClientId>,
        user_id: Option<UserId>,
        grant_id: ConsentGrantId,
        at: OffsetDateTime,
    ) -> Result<Option<ConsentGrantRevocation>, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let Some(row) = sqlx::query_as::<_, ConsentGrantSummaryRow>(
            r#"
            SELECT consent_grants.id,
                   consent_grants.organization_id,
                   consent_grants.user_id,
                   users.email AS user_email,
                   users.display_name AS user_display_name,
                   consent_grants.client_id,
                   consent_grants.scopes,
                   consent_grants.created_at,
                   consent_grants.revoked_at
            FROM consent_grants
            INNER JOIN users
                    ON users.id = consent_grants.user_id
                   AND users.organization_id = consent_grants.organization_id
            WHERE consent_grants.organization_id = $1
              AND consent_grants.id = $2
              AND ($3::uuid IS NULL OR consent_grants.client_id = $3)
              AND ($4::uuid IS NULL OR consent_grants.user_id = $4)
            FOR UPDATE OF consent_grants
            "#,
        )
        .bind(organization_id)
        .bind(grant_id)
        .bind(client_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?
        else {
            tx.commit().await?;
            return Ok(None);
        };

        let mut grant = ConsentGrantSummary::from(row);
        let consent_grants_revoked = sqlx::query(
            r#"
            UPDATE consent_grants
            SET revoked_at = COALESCE(revoked_at, $1)
            WHERE organization_id = $2
              AND user_id = $3
              AND client_id = $4
              AND revoked_at IS NULL
            "#,
        )
        .bind(at)
        .bind(organization_id)
        .bind(grant.user_id)
        .bind(grant.client_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        let authorization_codes_invalidated = sqlx::query(
            r#"
            UPDATE authorization_codes
            SET used_at = COALESCE(used_at, $1)
            WHERE organization_id = $2
              AND user_id = $3
              AND client_id = $4
              AND used_at IS NULL
              AND expires_at > $1
            "#,
        )
        .bind(at)
        .bind(organization_id)
        .bind(grant.user_id)
        .bind(grant.client_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        let access_tokens_revoked = sqlx::query(
            r#"
            UPDATE access_tokens
            SET revoked_at = COALESCE(revoked_at, $1)
            WHERE organization_id = $2
              AND user_id = $3
              AND client_id = $4
              AND revoked_at IS NULL
            "#,
        )
        .bind(at)
        .bind(organization_id)
        .bind(grant.user_id)
        .bind(grant.client_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        let refresh_tokens_revoked = sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = COALESCE(revoked_at, $1)
            WHERE organization_id = $2
              AND user_id = $3
              AND client_id = $4
              AND revoked_at IS NULL
            "#,
        )
        .bind(at)
        .bind(organization_id)
        .bind(grant.user_id)
        .bind(grant.client_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        tx.commit().await?;
        grant.revoked_at = grant.revoked_at.or(Some(at));
        Ok(Some(ConsentGrantRevocation {
            grant,
            consent_grants_revoked,
            authorization_codes_invalidated,
            access_tokens_revoked,
            refresh_tokens_revoked,
        }))
    }
}
