use crate::rows::{ConsentGrantSummaryRow, UserConsentGrantSummaryRow};
use crate::{
    ConsentGrantListFilter, ConsentGrantSummary, Database, DatabaseError, ListCursor,
    UserConsentGrantSummary,
};
use cairn_domain::{ClientId, OrganizationId, UserId};

impl Database {
    pub async fn list_active_consent_grants_for_client_page(
        &self,
        organization_id: OrganizationId,
        client_id: ClientId,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<ConsentGrantSummary>, DatabaseError> {
        self.list_consent_grants_for_client_page_filtered(
            organization_id,
            client_id,
            &ConsentGrantListFilter {
                revoked: Some(false),
            },
            after,
            limit,
        )
        .await
    }

    pub async fn list_consent_grants_for_client_page_filtered(
        &self,
        organization_id: OrganizationId,
        client_id: ClientId,
        filter: &ConsentGrantListFilter,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<ConsentGrantSummary>, DatabaseError> {
        let rows = sqlx::query_as::<_, ConsentGrantSummaryRow>(
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
              AND consent_grants.client_id = $2
              AND (
                  $3::timestamptz IS NULL
                  OR consent_grants.created_at < $3
                  OR (consent_grants.created_at = $3 AND consent_grants.id < $4)
              )
              AND ($5::boolean IS NULL OR (consent_grants.revoked_at IS NOT NULL) = $5)
            ORDER BY consent_grants.created_at DESC, consent_grants.id DESC
            LIMIT $6
            "#,
        )
        .bind(organization_id)
        .bind(client_id)
        .bind(after.map(|cursor| cursor.created_at))
        .bind(after.map(|cursor| cursor.tie_breaker_id))
        .bind(filter.revoked)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn list_consent_grants_for_user_page_filtered(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        filter: &ConsentGrantListFilter,
        after: Option<ListCursor>,
        limit: i64,
    ) -> Result<Vec<UserConsentGrantSummary>, DatabaseError> {
        let rows = sqlx::query_as::<_, UserConsentGrantSummaryRow>(
            r#"
            SELECT consent_grants.id,
                   consent_grants.organization_id,
                   consent_grants.user_id,
                   consent_grants.client_id,
                   oidc_clients.client_id AS client_public_id,
                   oidc_clients.name AS client_name,
                   consent_grants.scopes,
                   consent_grants.created_at,
                   consent_grants.revoked_at
            FROM consent_grants
            INNER JOIN oidc_clients
                    ON oidc_clients.id = consent_grants.client_id
                   AND oidc_clients.organization_id = consent_grants.organization_id
            WHERE consent_grants.organization_id = $1
              AND consent_grants.user_id = $2
              AND (
                  $3::timestamptz IS NULL
                  OR consent_grants.created_at < $3
                  OR (consent_grants.created_at = $3 AND consent_grants.id < $4)
              )
              AND ($5::boolean IS NULL OR (consent_grants.revoked_at IS NOT NULL) = $5)
            ORDER BY consent_grants.created_at DESC, consent_grants.id DESC
            LIMIT $6
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(after.map(|cursor| cursor.created_at))
        .bind(after.map(|cursor| cursor.tie_breaker_id))
        .bind(filter.revoked)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }
}
