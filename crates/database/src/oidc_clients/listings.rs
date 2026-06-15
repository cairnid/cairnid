use crate::codec::{oidc_client_status_to_str, oidc_grant_type_to_str};
use crate::repository_helpers::prefix_search_pattern;
use crate::rows::OidcClientRow;
use crate::{Database, DatabaseError, ListCursor, OidcClientListFilter};
use cairn_domain::{OidcClient, OrganizationId};

impl Database {
    pub async fn list_oidc_clients(
        &self,
        organization_id: OrganizationId,
        limit: i64,
    ) -> Result<Vec<OidcClient>, DatabaseError> {
        self.list_oidc_clients_page(organization_id, None, limit)
            .await
    }

    pub async fn list_oidc_clients_page(
        &self,
        organization_id: OrganizationId,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<OidcClient>, DatabaseError> {
        self.list_oidc_clients_page_filtered(
            organization_id,
            &OidcClientListFilter::default(),
            after,
            limit,
        )
        .await
    }

    pub async fn list_oidc_clients_page_filtered(
        &self,
        organization_id: OrganizationId,
        filter: &OidcClientListFilter,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<OidcClient>, DatabaseError> {
        let search_pattern = prefix_search_pattern(filter.search_prefix.as_deref());
        let grant_type = filter.grant_type.map(oidc_grant_type_to_str);
        let status = filter.status.map(oidc_client_status_to_str);
        let rows = sqlx::query_as::<_, OidcClientRow>(
            r#"
            SELECT id, organization_id, client_id, client_secret_hash, consent_policy_template_id, name,
                   redirect_uris, post_logout_redirect_uris, allowed_scopes, grant_types,
                   public_client, require_pkce, status, created_at
            FROM oidc_clients
            WHERE organization_id = $1
              AND (
                  $2::timestamptz IS NULL
                  OR created_at < $2
                  OR (created_at = $2 AND id < $3)
              )
              AND (
                  $4::text IS NULL
                  OR lower(client_id) LIKE $4
                  OR lower(name) LIKE $4
              )
              AND ($5::boolean IS NULL OR public_client = $5)
              AND ($6::text IS NULL OR status = $6)
              AND ($7::text IS NULL OR grant_types @> jsonb_build_array($7::text))
              AND ($8::text IS NULL OR allowed_scopes @> jsonb_build_array($8::text))
            ORDER BY created_at DESC, id DESC
            LIMIT $9
            "#,
        )
        .bind(organization_id)
        .bind(after.map(|cursor| cursor.created_at))
        .bind(after.map(|cursor| cursor.tie_breaker_id))
        .bind(search_pattern)
        .bind(filter.public_client)
        .bind(status)
        .bind(grant_type)
        .bind(filter.scope.as_deref())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(OidcClientRow::try_into_client)
            .collect()
    }
}
