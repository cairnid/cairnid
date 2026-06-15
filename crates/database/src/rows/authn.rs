use crate::{
    BrowserSessionSummary, DatabaseError,
    codec::{mfa_kind_from_str, webauthn_challenge_kind_from_str},
};
use cairn_domain::{AuthSession, MfaCredential, WebAuthnChallenge};
use serde_json::Value;
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct AuthSessionRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) acr: String,
    pub(crate) amr: Json<Vec<String>>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) revoked_at: Option<OffsetDateTime>,
}

impl From<AuthSessionRow> for AuthSession {
    fn from(row: AuthSessionRow) -> Self {
        Self {
            id: row.id,
            organization_id: row.organization_id,
            user_id: row.user_id,
            acr: row.acr,
            amr: row.amr.0,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct BrowserSessionSummaryRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) acr: String,
    pub(crate) amr: Json<Vec<String>>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) created_ip_address: Option<String>,
    pub(crate) created_user_agent: Option<String>,
}

impl From<BrowserSessionSummaryRow> for BrowserSessionSummary {
    fn from(row: BrowserSessionSummaryRow) -> Self {
        Self {
            id: row.id,
            organization_id: row.organization_id,
            user_id: row.user_id,
            acr: row.acr,
            amr: row.amr.0,
            created_at: row.created_at,
            expires_at: row.expires_at,
            created_ip_address: row.created_ip_address,
            created_user_agent: row.created_user_agent,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct MfaCredentialRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) kind: String,
    pub(crate) label: String,
    pub(crate) secret_metadata: Json<Value>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) last_used_at: Option<OffsetDateTime>,
}

impl MfaCredentialRow {
    pub(crate) fn try_into_credential(self) -> Result<MfaCredential, DatabaseError> {
        Ok(MfaCredential {
            id: self.id,
            organization_id: self.organization_id,
            user_id: self.user_id,
            kind: mfa_kind_from_str(&self.kind)?,
            label: self.label,
            secret_metadata: self.secret_metadata.0,
            created_at: self.created_at,
            last_used_at: self.last_used_at,
        })
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct WebAuthnChallengeRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) kind: String,
    pub(crate) state: Json<Value>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) consumed_at: Option<OffsetDateTime>,
}

impl WebAuthnChallengeRow {
    pub(crate) fn try_into_challenge(self) -> Result<WebAuthnChallenge, DatabaseError> {
        Ok(WebAuthnChallenge {
            id: self.id,
            organization_id: self.organization_id,
            user_id: self.user_id,
            kind: webauthn_challenge_kind_from_str(&self.kind)?,
            state: self.state.0,
            created_at: self.created_at,
            expires_at: self.expires_at,
            consumed_at: self.consumed_at,
        })
    }
}
