use crate::codec::oidc_client_status_to_str;
use crate::oidc_clients::runtime_credentials::revoke_client_runtime_credentials;
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
            let mutation =
                revoke_client_runtime_credentials(&mut tx, organization_id, client_id, at).await?;
            authorization_codes_invalidated = mutation.authorization_codes_invalidated;
            access_tokens_revoked = mutation.access_tokens_revoked;
            refresh_tokens_revoked = mutation.refresh_tokens_revoked;
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
