use crate::codec::oidc_client_status_to_str;
use crate::oidc_clients::runtime_credentials::{
    invalidate_pending_authorization_codes, revoke_active_tokens,
};
use crate::rows::OidcClientRow;
use crate::{
    Database, DatabaseError, OidcClientDetailsMutation, OidcClientDetailsMutationOutcome,
    OidcClientDetailsUpdate,
};
use cairn_domain::{ClientId, OidcClient, OrganizationId, RedirectUri};
use sqlx::types::Json;
use std::collections::BTreeSet;
use time::OffsetDateTime;

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

    pub async fn get_oidc_client_in_organization(
        &self,
        organization_id: OrganizationId,
        id: ClientId,
    ) -> Result<Option<OidcClient>, DatabaseError> {
        let row = sqlx::query_as::<_, OidcClientRow>(
            r#"
            SELECT id, organization_id, client_id, client_secret_hash, consent_policy_template_id, name,
                   redirect_uris, post_logout_redirect_uris, allowed_scopes, grant_types,
                   public_client, require_pkce, status, created_at
            FROM oidc_clients
            WHERE organization_id = $1 AND id = $2
            "#,
        )
        .bind(organization_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(OidcClientRow::try_into_client).transpose()
    }

    pub async fn update_oidc_client_details(
        &self,
        organization_id: OrganizationId,
        client_id: ClientId,
        update: OidcClientDetailsUpdate,
        at: OffsetDateTime,
    ) -> Result<OidcClientDetailsMutationOutcome, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let Some(row) = sqlx::query_as::<_, OidcClientRow>(
            r#"
            SELECT id, organization_id, client_id, client_secret_hash, consent_policy_template_id, name,
                   redirect_uris, post_logout_redirect_uris, allowed_scopes, grant_types,
                   public_client, require_pkce, status, created_at
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
            return Ok(OidcClientDetailsMutationOutcome::NotFound);
        };
        let existing = row.try_into_client()?;

        let mut changed_fields = Vec::new();
        if existing.name != update.name {
            changed_fields.push("name".to_owned());
        }
        if existing.redirect_uris != update.redirect_uris {
            changed_fields.push("redirect_uris".to_owned());
        }
        if existing.post_logout_redirect_uris != update.post_logout_redirect_uris {
            changed_fields.push("post_logout_redirect_uris".to_owned());
        }
        if existing.allowed_scopes != update.allowed_scopes {
            changed_fields.push("allowed_scopes".to_owned());
        }
        if existing.consent_policy_template_id != update.consent_policy_template_id {
            changed_fields.push("consent_policy_template_id".to_owned());
        }

        let redirect_uris_security_changed =
            redirect_uri_set(&existing.redirect_uris) != redirect_uri_set(&update.redirect_uris);
        let allowed_scopes_security_changed =
            string_set(&existing.allowed_scopes) != string_set(&update.allowed_scopes);

        let updated_row = sqlx::query_as::<_, OidcClientRow>(
            r#"
            UPDATE oidc_clients
            SET name = $1,
                redirect_uris = $2,
                post_logout_redirect_uris = $3,
                allowed_scopes = $4,
                consent_policy_template_id = $5
            WHERE organization_id = $6 AND id = $7
            RETURNING id, organization_id, client_id, client_secret_hash, consent_policy_template_id, name,
                      redirect_uris, post_logout_redirect_uris, allowed_scopes, grant_types,
                      public_client, require_pkce, status, created_at
            "#,
        )
        .bind(&update.name)
        .bind(Json(&update.redirect_uris))
        .bind(Json(&update.post_logout_redirect_uris))
        .bind(Json(&update.allowed_scopes))
        .bind(update.consent_policy_template_id)
        .bind(organization_id)
        .bind(client_id)
        .fetch_one(&mut *tx)
        .await?;
        let client = updated_row.try_into_client()?;

        let mut authorization_codes_invalidated = 0;
        let mut access_tokens_revoked = 0;
        let mut refresh_tokens_revoked = 0;

        if redirect_uris_security_changed || allowed_scopes_security_changed {
            authorization_codes_invalidated =
                invalidate_pending_authorization_codes(&mut tx, organization_id, client_id, at)
                    .await?;
        }
        if allowed_scopes_security_changed {
            (access_tokens_revoked, refresh_tokens_revoked) =
                revoke_active_tokens(&mut tx, organization_id, client_id, at).await?;
        }

        tx.commit().await?;
        Ok(OidcClientDetailsMutationOutcome::Applied(Box::new(
            OidcClientDetailsMutation {
                client,
                changed_fields,
                authorization_codes_invalidated,
                access_tokens_revoked,
                refresh_tokens_revoked,
            },
        )))
    }
}

fn redirect_uri_set(uris: &[RedirectUri]) -> BTreeSet<&str> {
    uris.iter().map(|uri| uri.value.as_str()).collect()
}

fn string_set(values: &[String]) -> BTreeSet<&str> {
    values.iter().map(String::as_str).collect()
}
