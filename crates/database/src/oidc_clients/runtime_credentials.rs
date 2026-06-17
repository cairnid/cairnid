use crate::DatabaseError;
use cairn_domain::{ClientId, OrganizationId};
use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct ClientRuntimeCredentialMutation {
    pub(super) authorization_codes_invalidated: u64,
    pub(super) access_tokens_revoked: u64,
    pub(super) refresh_tokens_revoked: u64,
}

pub(super) async fn invalidate_pending_authorization_codes(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    client_id: ClientId,
    at: OffsetDateTime,
) -> Result<u64, DatabaseError> {
    Ok(sqlx::query(
        r#"
        UPDATE authorization_codes
        SET used_at = COALESCE(used_at, $1)
        WHERE organization_id = $2
          AND client_id = $3
          AND used_at IS NULL
          AND expires_at > $1
        "#,
    )
    .bind(at)
    .bind(organization_id)
    .bind(client_id)
    .execute(&mut **tx)
    .await?
    .rows_affected())
}

pub(super) async fn revoke_active_tokens(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    client_id: ClientId,
    at: OffsetDateTime,
) -> Result<(u64, u64), DatabaseError> {
    let access_tokens_revoked = sqlx::query(
        r#"
        UPDATE access_tokens
        SET revoked_at = COALESCE(revoked_at, $1)
        WHERE organization_id = $2
          AND client_id = $3
          AND revoked_at IS NULL
        "#,
    )
    .bind(at)
    .bind(organization_id)
    .bind(client_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    let refresh_tokens_revoked = sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = COALESCE(revoked_at, $1)
        WHERE organization_id = $2
          AND client_id = $3
          AND revoked_at IS NULL
        "#,
    )
    .bind(at)
    .bind(organization_id)
    .bind(client_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();

    Ok((access_tokens_revoked, refresh_tokens_revoked))
}

pub(super) async fn revoke_client_runtime_credentials(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: OrganizationId,
    client_id: ClientId,
    at: OffsetDateTime,
) -> Result<ClientRuntimeCredentialMutation, DatabaseError> {
    let authorization_codes_invalidated =
        invalidate_pending_authorization_codes(tx, organization_id, client_id, at).await?;
    let (access_tokens_revoked, refresh_tokens_revoked) =
        revoke_active_tokens(tx, organization_id, client_id, at).await?;

    Ok(ClientRuntimeCredentialMutation {
        authorization_codes_invalidated,
        access_tokens_revoked,
        refresh_tokens_revoked,
    })
}
