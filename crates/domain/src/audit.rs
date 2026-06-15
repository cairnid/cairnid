use crate::{AuditEventId, OrganizationId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditActorKind {
    User,
    Client,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditEvent {
    pub id: AuditEventId,
    pub organization_id: OrganizationId,
    pub actor_kind: AuditActorKind,
    pub actor_id: Option<Uuid>,
    pub action: String,
    pub target: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
