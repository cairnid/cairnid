use crate::{DatabaseError, codec::pkce_method_from_str};
use cairn_domain::{AuthorizationCode, OrganizationId, RefreshToken, UserId};
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenRecord {
    pub token_hash: String,
    pub organization_id: OrganizationId,
    pub user_id: Option<UserId>,
    pub client_id: Uuid,
    pub scopes: Vec<String>,
    pub refresh_family_id: Option<Uuid>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct AuthorizationCodeRow {
    pub(crate) code_hash: String,
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) session_id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) redirect_uri: String,
    pub(crate) scopes: Json<Vec<String>>,
    pub(crate) nonce: Option<String>,
    pub(crate) code_challenge: String,
    pub(crate) code_challenge_method: String,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) used_at: Option<OffsetDateTime>,
}

impl AuthorizationCodeRow {
    pub(crate) fn try_into_code(self) -> Result<AuthorizationCode, DatabaseError> {
        Ok(AuthorizationCode {
            code_hash: self.code_hash,
            organization_id: self.organization_id,
            user_id: self.user_id,
            session_id: self.session_id,
            client_id: self.client_id,
            redirect_uri: self.redirect_uri,
            scopes: self.scopes.0,
            nonce: self.nonce,
            code_challenge: self.code_challenge,
            code_challenge_method: pkce_method_from_str(&self.code_challenge_method)?,
            created_at: self.created_at,
            expires_at: self.expires_at,
            used_at: self.used_at,
        })
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct AccessTokenRow {
    pub(crate) token_hash: String,
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Option<Uuid>,
    pub(crate) client_id: Uuid,
    pub(crate) scopes: Json<Vec<String>>,
    pub(crate) refresh_family_id: Option<Uuid>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) revoked_at: Option<OffsetDateTime>,
}

impl From<AccessTokenRow> for AccessTokenRecord {
    fn from(row: AccessTokenRow) -> Self {
        Self {
            token_hash: row.token_hash,
            organization_id: row.organization_id,
            user_id: row.user_id,
            client_id: row.client_id,
            scopes: row.scopes.0,
            refresh_family_id: row.refresh_family_id,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct RefreshTokenRow {
    pub(crate) id: Uuid,
    pub(crate) token_hash: String,
    pub(crate) family_id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Option<Uuid>,
    pub(crate) client_id: Uuid,
    pub(crate) scopes: Json<Vec<String>>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) rotated_at: Option<OffsetDateTime>,
    pub(crate) revoked_at: Option<OffsetDateTime>,
}

impl From<RefreshTokenRow> for RefreshToken {
    fn from(row: RefreshTokenRow) -> Self {
        Self {
            id: row.id,
            token_hash: row.token_hash,
            family_id: row.family_id,
            organization_id: row.organization_id,
            user_id: row.user_id,
            client_id: row.client_id,
            scopes: row.scopes.0,
            created_at: row.created_at,
            expires_at: row.expires_at,
            rotated_at: row.rotated_at,
            revoked_at: row.revoked_at,
        }
    }
}
