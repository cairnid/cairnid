use super::metadata::metadata_with_status;
use crate::{Database, DatabaseError, codec::mfa_kind_to_str, rows::MfaCredentialRow};
use cairn_domain::{MfaCredential, MfaKind, OrganizationId, UserId};
use serde_json::Value;
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

impl Database {
    pub async fn create_mfa_credential(
        &self,
        credential: &MfaCredential,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO mfa_credentials (
                id, organization_id, user_id, kind, label, secret_metadata, created_at, last_used_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(credential.id)
        .bind(credential.organization_id)
        .bind(credential.user_id)
        .bind(mfa_kind_to_str(credential.kind))
        .bind(&credential.label)
        .bind(Json(&credential.secret_metadata))
        .bind(credential.created_at)
        .bind(credential.last_used_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_mfa_credentials(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        kind: MfaKind,
    ) -> Result<Vec<MfaCredential>, DatabaseError> {
        let rows = sqlx::query_as::<_, MfaCredentialRow>(
            r#"
            SELECT id, organization_id, user_id, kind, label, secret_metadata, created_at, last_used_at
            FROM mfa_credentials
            WHERE organization_id = $1 AND user_id = $2 AND kind = $3
            ORDER BY created_at DESC
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(mfa_kind_to_str(kind))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(MfaCredentialRow::try_into_credential)
            .collect()
    }

    pub async fn mark_mfa_credential_used(
        &self,
        id: Uuid,
        at: OffsetDateTime,
    ) -> Result<(), DatabaseError> {
        sqlx::query("UPDATE mfa_credentials SET last_used_at = $1 WHERE id = $2")
            .bind(at)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_mfa_credential_metadata(
        &self,
        id: Uuid,
        secret_metadata: &Value,
        last_used_at: Option<OffsetDateTime>,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            UPDATE mfa_credentials
            SET secret_metadata = $1, last_used_at = $2
            WHERE id = $3
            "#,
        )
        .bind(Json(secret_metadata))
        .bind(last_used_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn consume_active_recovery_code(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        code_hash: &str,
        at: OffsetDateTime,
    ) -> Result<bool, DatabaseError> {
        let result = sqlx::query(
            r#"
            UPDATE mfa_credentials
            SET secret_metadata = jsonb_set(secret_metadata, '{status}', '"consumed"'::jsonb, true),
                last_used_at = $4
            WHERE organization_id = $1
              AND user_id = $2
              AND kind = $3
              AND secret_metadata->>'status' = 'active'
              AND secret_metadata->>'code_hash' = $5
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(mfa_kind_to_str(MfaKind::RecoveryCode))
        .bind(at)
        .bind(code_hash)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn revoke_mfa_credential(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        credential_id: Uuid,
        at: OffsetDateTime,
    ) -> Result<Option<MfaCredential>, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query_as::<_, MfaCredentialRow>(
            r#"
            SELECT id, organization_id, user_id, kind, label, secret_metadata, created_at, last_used_at
            FROM mfa_credentials
            WHERE organization_id = $1
              AND user_id = $2
              AND id = $3
              AND kind IN ('totp', 'web_authn')
            FOR UPDATE
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(credential_id)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };

        let mut credential = row.try_into_credential()?;
        credential.secret_metadata = metadata_with_status(credential.secret_metadata, "revoked");
        credential.last_used_at = Some(at);

        sqlx::query(
            r#"
            UPDATE mfa_credentials
            SET secret_metadata = $1, last_used_at = $2
            WHERE id = $3
            "#,
        )
        .bind(Json(&credential.secret_metadata))
        .bind(credential.last_used_at)
        .bind(credential.id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(credential))
    }

    pub async fn revoke_active_mfa_credentials_by_kind(
        &self,
        organization_id: OrganizationId,
        user_id: UserId,
        kind: MfaKind,
        at: OffsetDateTime,
    ) -> Result<u64, DatabaseError> {
        let result = sqlx::query(
            r#"
            UPDATE mfa_credentials
            SET secret_metadata = jsonb_set(secret_metadata, '{status}', '"revoked"'::jsonb, true),
                last_used_at = $4
            WHERE organization_id = $1
              AND user_id = $2
              AND kind = $3
              AND secret_metadata->>'status' = 'active'
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(mfa_kind_to_str(kind))
        .bind(at)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    pub async fn find_active_webauthn_credential_by_credential_id(
        &self,
        organization_id: OrganizationId,
        credential_id: &str,
    ) -> Result<Option<MfaCredential>, DatabaseError> {
        let row = sqlx::query_as::<_, MfaCredentialRow>(
            r#"
            SELECT id, organization_id, user_id, kind, label, secret_metadata, created_at, last_used_at
            FROM mfa_credentials
            WHERE organization_id = $1
              AND kind = 'web_authn'
              AND secret_metadata->>'status' = 'active'
              AND secret_metadata->>'credential_id' = $2
            LIMIT 1
            "#,
        )
        .bind(organization_id)
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(MfaCredentialRow::try_into_credential).transpose()
    }
}
