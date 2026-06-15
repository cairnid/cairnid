use super::sessions::SessionRequestContext;
use cairn_domain::{AccountTokenId, AuthSession, EmailOutboxMessage, OrganizationId, UserId};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordChangeOutcome {
    Applied(Box<PasswordChangeMutation>),
    NotFound,
}

#[derive(Debug, Clone, Copy)]
pub struct PasswordChangeInput<'a> {
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub password_hash: &'a str,
    pub new_session: &'a AuthSession,
    pub request_context: SessionRequestContext<'a>,
    pub notification: Option<&'a EmailOutboxMessage>,
    pub at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordChangeMutation {
    pub session: AuthSession,
    pub sessions_revoked: u64,
    pub access_tokens_revoked: u64,
    pub refresh_tokens_revoked: u64,
    pub account_tokens_consumed: u64,
    pub notification_email_outbox_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordRecoveryOutcome {
    Applied(Box<PasswordRecoveryMutation>),
    NotFound,
}

#[derive(Debug, Clone, Copy)]
pub struct PasswordRecoveryInput<'a> {
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub token_id: AccountTokenId,
    pub password_hash: &'a str,
    pub notification: Option<&'a EmailOutboxMessage>,
    pub at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRecoveryMutation {
    pub sessions_revoked: u64,
    pub access_tokens_revoked: u64,
    pub refresh_tokens_revoked: u64,
    pub account_tokens_consumed: u64,
    pub notification_email_outbox_id: Option<Uuid>,
}
