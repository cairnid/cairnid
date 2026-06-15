mod authorizations;
mod listings;
mod revocation;

use crate::{Database, DatabaseError};
use cairn_domain::ConsentGrant;
use sqlx::types::Json;

impl Database {
    pub async fn create_consent_grant(&self, grant: &ConsentGrant) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO consent_grants (
                id, organization_id, user_id, client_id, scopes, created_at, revoked_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(grant.id)
        .bind(grant.organization_id)
        .bind(grant.user_id)
        .bind(grant.client_id)
        .bind(Json(&grant.scopes))
        .bind(grant.created_at)
        .bind(grant.revoked_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
