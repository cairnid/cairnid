use crate::{Database, DatabaseError};
use cairn_domain::{ClientId, OrganizationId};

impl Database {
    pub async fn rotate_oidc_client_secret(
        &self,
        organization_id: OrganizationId,
        client_id: ClientId,
        client_secret_hash: &str,
    ) -> Result<bool, DatabaseError> {
        let updated = sqlx::query(
            r#"
            UPDATE oidc_clients
            SET client_secret_hash = $1
            WHERE organization_id = $2 AND id = $3 AND public_client = FALSE
            "#,
        )
        .bind(client_secret_hash)
        .bind(organization_id)
        .bind(client_id)
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok(updated == 1)
    }
}
