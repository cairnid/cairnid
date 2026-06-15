use super::rows::{EmailOutboxDeliveryTokenRow, SigningKeyMaterialRow, SigningKeyRow};
use super::{
    Database, DatabaseError, EmailOutboxDeliveryToken, ReencryptedEmailOutboxDeliveryToken,
    SigningKeyLifecycleSummary,
};
use cairn_domain::{SigningKey, SigningKeyMaterial};
use sqlx::types::Json;
use time::OffsetDateTime;

impl Database {
    pub async fn active_jwks(&self) -> Result<Vec<SigningKey>, DatabaseError> {
        let rows = sqlx::query_as::<_, SigningKeyRow>(
            r#"
            SELECT kid, algorithm, public_jwk, signing_active, created_at, retired_at
            FROM signing_keys
            WHERE retired_at IS NULL
            ORDER BY signing_active DESC, created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn list_signing_keys(&self) -> Result<Vec<SigningKey>, DatabaseError> {
        let rows = sqlx::query_as::<_, SigningKeyRow>(
            r#"
            SELECT kid, algorithm, public_jwk, signing_active, created_at, retired_at
            FROM signing_keys
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    pub async fn signing_key_lifecycle_summary(
        &self,
    ) -> Result<SigningKeyLifecycleSummary, DatabaseError> {
        Ok(sqlx::query_as::<_, SigningKeyLifecycleSummary>(
            r#"
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (
                    WHERE signing_active = TRUE
                      AND retired_at IS NULL
                ) AS active,
                COUNT(*) FILTER (
                    WHERE signing_active = TRUE
                      AND retired_at IS NULL
                      AND private_key_ciphertext IS NOT NULL
                      AND private_key_nonce IS NOT NULL
                ) AS active_with_private_material,
                COUNT(*) FILTER (WHERE retired_at IS NULL) AS unretired,
                COUNT(*) FILTER (WHERE retired_at IS NOT NULL) AS retired,
                COUNT(*) FILTER (
                    WHERE signing_active = FALSE
                      AND retired_at IS NULL
                ) AS rollover,
                COUNT(*) FILTER (
                    WHERE private_key_ciphertext IS NOT NULL
                      AND private_key_nonce IS NOT NULL
                ) AS encrypted_private_material,
                MAX(created_at) FILTER (
                    WHERE signing_active = TRUE
                      AND retired_at IS NULL
                ) AS active_created_at,
                MIN(created_at) FILTER (WHERE retired_at IS NULL) AS oldest_unretired_created_at,
                MAX(retired_at) AS newest_retired_at
            FROM signing_keys
            "#,
        )
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn active_signing_key(&self) -> Result<Option<SigningKeyMaterial>, DatabaseError> {
        let row = sqlx::query_as::<_, SigningKeyMaterialRow>(
            r#"
            SELECT kid, algorithm, public_jwk, private_key_ciphertext, private_key_nonce,
                   signing_active, created_at, retired_at
            FROM signing_keys
            WHERE signing_active = TRUE
              AND retired_at IS NULL
              AND private_key_ciphertext IS NOT NULL
              AND private_key_nonce IS NOT NULL
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(SigningKeyMaterialRow::try_into_material)
            .transpose()
    }

    pub async fn list_encrypted_signing_key_materials(
        &self,
    ) -> Result<Vec<SigningKeyMaterial>, DatabaseError> {
        let rows = sqlx::query_as::<_, SigningKeyMaterialRow>(
            r#"
            SELECT kid, algorithm, public_jwk, private_key_ciphertext, private_key_nonce,
                   signing_active, created_at, retired_at
            FROM signing_keys
            WHERE private_key_ciphertext IS NOT NULL
              AND private_key_nonce IS NOT NULL
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(SigningKeyMaterialRow::try_into_material)
            .collect()
    }

    pub async fn list_email_outbox_delivery_tokens(
        &self,
    ) -> Result<Vec<EmailOutboxDeliveryToken>, DatabaseError> {
        let rows = sqlx::query_as::<_, EmailOutboxDeliveryTokenRow>(
            r#"
            SELECT id, delivery_token_ciphertext, delivery_token_nonce, metadata
            FROM email_outbox
            WHERE delivery_token_ciphertext IS NOT NULL
              AND delivery_token_nonce IS NOT NULL
            ORDER BY created_at
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(EmailOutboxDeliveryTokenRow::try_into_token)
            .collect()
    }

    pub async fn apply_key_encryption_rotation(
        &self,
        signing_keys: &[SigningKeyMaterial],
        email_delivery_tokens: &[ReencryptedEmailOutboxDeliveryToken],
    ) -> Result<(), DatabaseError> {
        let mut tx = self.pool.begin().await?;

        for key in signing_keys {
            sqlx::query(
                r#"
                UPDATE signing_keys
                SET private_key_ciphertext = $2,
                    private_key_nonce = $3
                WHERE kid = $1
                "#,
            )
            .bind(&key.kid)
            .bind(&key.private_key_ciphertext)
            .bind(&key.private_key_nonce)
            .execute(&mut *tx)
            .await?;
        }

        for token in email_delivery_tokens {
            sqlx::query(
                r#"
                UPDATE email_outbox
                SET delivery_token_ciphertext = $2,
                    delivery_token_nonce = $3,
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(token.id)
            .bind(&token.delivery_token_ciphertext)
            .bind(&token.delivery_token_nonce)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub async fn upsert_signing_key_material(
        &self,
        key: &SigningKeyMaterial,
    ) -> Result<(), DatabaseError> {
        let mut tx = self.pool.begin().await?;
        if key.signing_active {
            sqlx::query(
                "UPDATE signing_keys SET signing_active = FALSE WHERE signing_active = TRUE",
            )
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            r#"
            INSERT INTO signing_keys (
                kid, algorithm, public_jwk, private_key_ciphertext, private_key_nonce,
                signing_active, created_at, retired_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (kid) DO UPDATE SET
                algorithm = EXCLUDED.algorithm,
                public_jwk = EXCLUDED.public_jwk,
                private_key_ciphertext = EXCLUDED.private_key_ciphertext,
                private_key_nonce = EXCLUDED.private_key_nonce,
                signing_active = EXCLUDED.signing_active,
                created_at = EXCLUDED.created_at,
                retired_at = EXCLUDED.retired_at
            "#,
        )
        .bind(&key.kid)
        .bind(&key.algorithm)
        .bind(Json(&key.public_jwk))
        .bind(&key.private_key_ciphertext)
        .bind(&key.private_key_nonce)
        .bind(key.signing_active)
        .bind(key.created_at)
        .bind(key.retired_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn retire_signing_key(
        &self,
        kid: &str,
        retired_at: OffsetDateTime,
    ) -> Result<bool, DatabaseError> {
        let result = sqlx::query(
            r#"
            UPDATE signing_keys
            SET retired_at = $1, signing_active = FALSE
            WHERE kid = $2 AND retired_at IS NULL
            "#,
        )
        .bind(retired_at)
        .bind(kid)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }
}
