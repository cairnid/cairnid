use crate::codec::oidc_client_status_to_str;
use crate::rows::OidcClientRow;
use crate::{Database, DatabaseError, OidcClientStatusMutation, OidcClientStatusMutationOutcome};
use cairn_domain::{ClientId, OidcClientStatus, OrganizationId};
use time::OffsetDateTime;
use uuid::Uuid;

impl Database {
    pub async fn update_oidc_client_status(
        &self,
        organization_id: OrganizationId,
        client_id: ClientId,
        status: OidcClientStatus,
        at: OffsetDateTime,
    ) -> Result<OidcClientStatusMutationOutcome, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let Some(_) = sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id
            FROM oidc_clients
            WHERE organization_id = $1 AND id = $2
            FOR UPDATE
            "#,
        )
        .bind(organization_id)
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await?
        else {
            tx.commit().await?;
            return Ok(OidcClientStatusMutationOutcome::NotFound);
        };

        let updated_row = sqlx::query_as::<_, OidcClientRow>(
            r#"
            UPDATE oidc_clients
            SET status = $1
            WHERE organization_id = $2 AND id = $3
            RETURNING id, organization_id, client_id, client_secret_hash, consent_policy_template_id, name,
                      redirect_uris, post_logout_redirect_uris, allowed_scopes, grant_types,
                      public_client, require_pkce, status, created_at
            "#,
        )
        .bind(oidc_client_status_to_str(status))
        .bind(organization_id)
        .bind(client_id)
        .fetch_one(&mut *tx)
        .await?;
        let client = updated_row.try_into_client()?;

        let mut authorization_codes_invalidated = 0;
        let mut access_tokens_revoked = 0;
        let mut refresh_tokens_revoked = 0;

        if status == OidcClientStatus::Disabled {
            authorization_codes_invalidated = sqlx::query(
                r#"
                UPDATE authorization_codes
                SET used_at = COALESCE(used_at, $1)
                WHERE organization_id = $2
                  AND client_id = $3
                  AND used_at IS NULL
                  AND expires_at > $1
                "#,
            )
            .bind(at)
            .bind(organization_id)
            .bind(client_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();

            access_tokens_revoked = sqlx::query(
                r#"
                UPDATE access_tokens
                SET revoked_at = COALESCE(revoked_at, $1)
                WHERE organization_id = $2
                  AND client_id = $3
                  AND revoked_at IS NULL
                "#,
            )
            .bind(at)
            .bind(organization_id)
            .bind(client_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();

            refresh_tokens_revoked = sqlx::query(
                r#"
                UPDATE refresh_tokens
                SET revoked_at = COALESCE(revoked_at, $1)
                WHERE organization_id = $2
                  AND client_id = $3
                  AND revoked_at IS NULL
                "#,
            )
            .bind(at)
            .bind(organization_id)
            .bind(client_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        }

        tx.commit().await?;
        Ok(OidcClientStatusMutationOutcome::Applied(Box::new(
            OidcClientStatusMutation {
                client,
                authorization_codes_invalidated,
                access_tokens_revoked,
                refresh_tokens_revoked,
            },
        )))
    }
}
