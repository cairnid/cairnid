use crate::{
    Database, DatabaseError, codec::webauthn_challenge_kind_to_str, rows::WebAuthnChallengeRow,
};
use cairn_domain::{OrganizationId, UserId, WebAuthnChallenge, WebAuthnChallengeKind};
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

impl Database {
    pub async fn insert_webauthn_challenge(
        &self,
        challenge: &WebAuthnChallenge,
    ) -> Result<(), DatabaseError> {
        sqlx::query(
            r#"
            INSERT INTO webauthn_challenges (
                id, organization_id, user_id, kind, state, created_at, expires_at, consumed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(challenge.id)
        .bind(challenge.organization_id)
        .bind(challenge.user_id)
        .bind(webauthn_challenge_kind_to_str(challenge.kind))
        .bind(Json(&challenge.state))
        .bind(challenge.created_at)
        .bind(challenge.expires_at)
        .bind(challenge.consumed_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn consume_webauthn_challenge(
        &self,
        id: Uuid,
        organization_id: OrganizationId,
        user_id: UserId,
        kind: WebAuthnChallengeKind,
        at: OffsetDateTime,
    ) -> Result<Option<WebAuthnChallenge>, DatabaseError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query_as::<_, WebAuthnChallengeRow>(
            r#"
            SELECT id, organization_id, user_id, kind, state, created_at, expires_at, consumed_at
            FROM webauthn_challenges
            WHERE id = $1
              AND organization_id = $2
              AND user_id = $3
              AND kind = $4
              AND consumed_at IS NULL
              AND expires_at > $5
            FOR UPDATE
            "#,
        )
        .bind(id)
        .bind(organization_id)
        .bind(user_id)
        .bind(webauthn_challenge_kind_to_str(kind))
        .bind(at)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };

        sqlx::query("UPDATE webauthn_challenges SET consumed_at = $1 WHERE id = $2")
            .bind(at)
            .bind(id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        row.try_into_challenge().map(Some)
    }
}
