use cairn_domain::{AuthSession, EmailOutboxMessage, OrganizationId, SessionId, UserId};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSessionSummary {
    pub id: SessionId,
    pub organization_id: OrganizationId,
    pub user_id: UserId,
    pub acr: String,
    pub amr: Vec<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub created_ip_address: Option<String>,
    pub created_user_agent: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionRequestContext<'a> {
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

impl<'a> SessionRequestContext<'a> {
    pub fn new(ip_address: Option<&'a str>, user_agent: Option<&'a str>) -> Self {
        Self {
            ip_address,
            user_agent,
        }
    }

    pub fn has_identifying_context(self) -> bool {
        self.ip_address.is_some() || self.user_agent.is_some()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AuthSessionCreationInput<'a> {
    pub session: &'a AuthSession,
    pub request_context: SessionRequestContext<'a>,
    pub new_context_notification: Option<&'a EmailOutboxMessage>,
}
