use crate::{
    ConsentGrantSummary, DatabaseError, UserConsentGrantSummary,
    codec::{consent_grant_mode_from_str, oidc_client_status_from_str},
};
use cairn_domain::{ConsentGrant, ConsentPolicyTemplate, OidcClient, OidcGrantType, RedirectUri};
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct OidcClientRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) client_id: String,
    pub(crate) client_secret_hash: Option<String>,
    pub(crate) consent_policy_template_id: Option<Uuid>,
    pub(crate) name: String,
    pub(crate) redirect_uris: Json<Vec<RedirectUri>>,
    pub(crate) post_logout_redirect_uris: Json<Vec<RedirectUri>>,
    pub(crate) allowed_scopes: Json<Vec<String>>,
    pub(crate) grant_types: Json<Vec<OidcGrantType>>,
    pub(crate) public_client: bool,
    pub(crate) require_pkce: bool,
    pub(crate) status: String,
    pub(crate) created_at: OffsetDateTime,
}

impl OidcClientRow {
    pub(crate) fn try_into_client(self) -> Result<OidcClient, DatabaseError> {
        Ok(OidcClient {
            id: self.id,
            organization_id: self.organization_id,
            client_id: self.client_id,
            client_secret_hash: self.client_secret_hash,
            consent_policy_template_id: self.consent_policy_template_id,
            name: self.name,
            redirect_uris: self.redirect_uris.0,
            post_logout_redirect_uris: self.post_logout_redirect_uris.0,
            allowed_scopes: self.allowed_scopes.0,
            grant_types: self.grant_types.0,
            public_client: self.public_client,
            require_pkce: self.require_pkce,
            status: oidc_client_status_from_str(&self.status)?,
            created_at: self.created_at,
        })
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct ConsentPolicyTemplateRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) slug: String,
    pub(crate) name: String,
    pub(crate) grant_mode: String,
    pub(crate) created_at: OffsetDateTime,
}

impl ConsentPolicyTemplateRow {
    pub(crate) fn try_into_template(self) -> Result<ConsentPolicyTemplate, DatabaseError> {
        Ok(ConsentPolicyTemplate {
            id: self.id,
            organization_id: self.organization_id,
            slug: self.slug,
            name: self.name,
            grant_mode: consent_grant_mode_from_str(&self.grant_mode)?,
            created_at: self.created_at,
        })
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct ConsentAuthorizationRow {
    pub(crate) id: Uuid,
    pub(crate) scopes: Json<Vec<String>>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct ConsentGrantRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) scopes: Json<Vec<String>>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) revoked_at: Option<OffsetDateTime>,
}

impl From<ConsentGrantRow> for ConsentGrant {
    fn from(row: ConsentGrantRow) -> Self {
        Self {
            id: row.id,
            organization_id: row.organization_id,
            user_id: row.user_id,
            client_id: row.client_id,
            scopes: row.scopes.0,
            created_at: row.created_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct ConsentGrantSummaryRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) user_email: String,
    pub(crate) user_display_name: String,
    pub(crate) client_id: Uuid,
    pub(crate) scopes: Json<Vec<String>>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) revoked_at: Option<OffsetDateTime>,
}

impl From<ConsentGrantSummaryRow> for ConsentGrantSummary {
    fn from(row: ConsentGrantSummaryRow) -> Self {
        Self {
            id: row.id,
            organization_id: row.organization_id,
            user_id: row.user_id,
            user_email: row.user_email,
            user_display_name: row.user_display_name,
            client_id: row.client_id,
            scopes: row.scopes.0,
            created_at: row.created_at,
            revoked_at: row.revoked_at,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct UserConsentGrantSummaryRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) client_public_id: String,
    pub(crate) client_name: String,
    pub(crate) scopes: Json<Vec<String>>,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) revoked_at: Option<OffsetDateTime>,
}

impl From<UserConsentGrantSummaryRow> for UserConsentGrantSummary {
    fn from(row: UserConsentGrantSummaryRow) -> Self {
        Self {
            id: row.id,
            organization_id: row.organization_id,
            user_id: row.user_id,
            client_id: row.client_id,
            client_public_id: row.client_public_id,
            client_name: row.client_name,
            scopes: row.scopes.0,
            created_at: row.created_at,
            revoked_at: row.revoked_at,
        }
    }
}
