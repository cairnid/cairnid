use cairn_domain::{AuditActorKind, AuditEvent, OrganizationId};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::redaction::redact_sensitive_metadata;

#[derive(Debug, Clone)]
pub struct AuditEventBuilder {
    organization_id: OrganizationId,
    actor_kind: AuditActorKind,
    actor_id: Option<Uuid>,
    action: String,
    target: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    metadata: Value,
}

impl AuditEventBuilder {
    pub fn system(
        organization_id: OrganizationId,
        action: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            organization_id,
            actor_kind: AuditActorKind::System,
            actor_id: None,
            action: action.into(),
            target: target.into(),
            ip_address: None,
            user_agent: None,
            metadata: json!({}),
        }
    }

    pub fn user(
        organization_id: OrganizationId,
        actor_id: Uuid,
        action: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            organization_id,
            actor_kind: AuditActorKind::User,
            actor_id: Some(actor_id),
            action: action.into(),
            target: target.into(),
            ip_address: None,
            user_agent: None,
            metadata: json!({}),
        }
    }

    pub fn client(
        organization_id: OrganizationId,
        actor_id: Uuid,
        action: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            organization_id,
            actor_kind: AuditActorKind::Client,
            actor_id: Some(actor_id),
            action: action.into(),
            target: target.into(),
            ip_address: None,
            user_agent: None,
            metadata: json!({}),
        }
    }

    pub fn request_context(
        mut self,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        self.ip_address = ip_address;
        self.user_agent = user_agent;
        self
    }

    pub fn metadata(mut self, metadata: Value) -> Self {
        self.metadata = redact_sensitive_metadata(metadata);
        self
    }

    pub fn build(self) -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4(),
            organization_id: self.organization_id,
            actor_kind: self.actor_kind,
            actor_id: self.actor_id,
            action: self.action,
            target: self.target,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            metadata: self.metadata,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}
