use crate::{DatabaseError, codec::audit_actor_kind_from_str};
use cairn_domain::AuditEvent;
use serde_json::Value;
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct AuditEventRow {
    pub(crate) id: Uuid,
    pub(crate) organization_id: Uuid,
    pub(crate) actor_kind: String,
    pub(crate) actor_id: Option<Uuid>,
    pub(crate) action: String,
    pub(crate) target: String,
    pub(crate) ip_address: Option<String>,
    pub(crate) user_agent: Option<String>,
    pub(crate) metadata: Json<Value>,
    pub(crate) created_at: OffsetDateTime,
}

impl AuditEventRow {
    pub(crate) fn try_into_event(self) -> Result<AuditEvent, DatabaseError> {
        Ok(AuditEvent {
            id: self.id,
            organization_id: self.organization_id,
            actor_kind: audit_actor_kind_from_str(&self.actor_kind)?,
            actor_id: self.actor_id,
            action: self.action,
            target: self.target,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            metadata: self.metadata.0,
            created_at: self.created_at,
        })
    }
}
