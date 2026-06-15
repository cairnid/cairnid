use crate::codec::oidc_client_status_to_str;
use crate::rows::OidcClientRow;
use crate::{Database, DatabaseError};
use cairn_domain::{ClientId, OidcClient};
use sqlx::types::Json;

impl Database {
    pub async fn create_oidc_client(&self, client: &OidcClient) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO oidc_clients (
                id, organization_id, client_id, client_secret_hash, consent_policy_template_id, name,
                redirect_uris, post_logout_redirect_uris, allowed_scopes, grant_types,
                public_client, require_pkce, status, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
        )
        .bind(client.id)
        .bind(client.organization_id)
        .bind(&client.client_id)
        .bind(&client.client_secret_hash)
        .bind(client.consent_policy_template_id)
        .bind(&client.name)
        .bind(Json(&client.redirect_uris))
        .bind(Json(&client.post_logout_redirect_uris))
        .bind(Json(&client.allowed_scopes))
        .bind(Json(&client.grant_types))
        .bind(client.public_client)
        .bind(client.require_pkce)
        .bind(oidc_client_status_to_str(client.status))
        .bind(client.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_oidc_client_by_public_id(
        &self,
        client_id: &str,
    ) -> Result<Option<OidcClient>, DatabaseError> {
        let row = sqlx::query_as::<_, OidcClientRow>(
            r#"
            SELECT id, organization_id, client_id, client_secret_hash, consent_policy_template_id, name,
                   redirect_uris, post_logout_redirect_uris, allowed_scopes, grant_types,
                   public_client, require_pkce, status, created_at
            FROM oidc_clients
            WHERE client_id = $1
            "#,
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(OidcClientRow::try_into_client).transpose()
    }

    pub async fn get_oidc_client(&self, id: ClientId) -> Result<Option<OidcClient>, DatabaseError> {
        let row = sqlx::query_as::<_, OidcClientRow>(
            r#"
            SELECT id, organization_id, client_id, client_secret_hash, consent_policy_template_id, name,
                   redirect_uris, post_logout_redirect_uris, allowed_scopes, grant_types,
                   public_client, require_pkce, status, created_at
            FROM oidc_clients
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(OidcClientRow::try_into_client).transpose()
    }
}
