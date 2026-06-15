use cairn_domain::{AuditActorKind, OidcClientStatus, OidcGrantType, UserStatus};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListCursor {
    pub created_at: OffsetDateTime,
    pub tie_breaker_id: Uuid,
}

impl ListCursor {
    pub fn new(created_at: OffsetDateTime, tie_breaker_id: Uuid) -> Self {
        Self {
            created_at,
            tie_breaker_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UserListFilter {
    pub search_prefix: Option<String>,
    pub status: Option<UserStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScimUserListFilter {
    pub user_name_eq: Option<String>,
    pub external_id_eq: Option<String>,
    pub active_eq: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScimGroupListFilter {
    pub display_name_eq: Option<String>,
    pub external_id_eq: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OidcClientListFilter {
    pub search_prefix: Option<String>,
    pub public_client: Option<bool>,
    pub status: Option<OidcClientStatus>,
    pub grant_type: Option<OidcGrantType>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConsentGrantListFilter {
    pub revoked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuditEventListFilter {
    pub action_prefix: Option<String>,
    pub target_prefix: Option<String>,
    pub actor_kind: Option<AuditActorKind>,
    pub actor_id: Option<Uuid>,
    pub created_from: Option<OffsetDateTime>,
    pub created_to: Option<OffsetDateTime>,
}
