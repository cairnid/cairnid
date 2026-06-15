use cairn_database::BrowserSessionSummary;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub(super) struct BrowserSessionListResponse {
    pub(super) sessions: Vec<BrowserSessionResponse>,
}

#[derive(Debug, Serialize)]
pub(super) struct BrowserSessionResponse {
    id: Uuid,
    current: bool,
    acr: String,
    amr: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
    created_ip_address: Option<String>,
    created_user_agent: Option<String>,
}

impl BrowserSessionResponse {
    pub(super) fn from_summary(session: BrowserSessionSummary, current_session_id: Uuid) -> Self {
        Self {
            id: session.id,
            current: session.id == current_session_id,
            acr: session.acr,
            amr: session.amr,
            created_at: session.created_at,
            expires_at: session.expires_at,
            created_ip_address: session.created_ip_address,
            created_user_agent: session.created_user_agent,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct BrowserSessionRevocationResponse {
    pub(super) status: &'static str,
    pub(super) session_id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[test]
    fn browser_session_response_marks_current_session_without_exposing_hashes() {
        let session_id = Uuid::new_v4();
        let created_at = OffsetDateTime::now_utc();
        let response = BrowserSessionResponse::from_summary(
            BrowserSessionSummary {
                id: session_id,
                organization_id: Uuid::new_v4(),
                user_id: Uuid::new_v4(),
                acr: "urn:cairn:acr:password".to_owned(),
                amr: vec!["pwd".to_owned()],
                created_at,
                expires_at: created_at + Duration::hours(1),
                created_ip_address: Some("203.0.113.10".to_owned()),
                created_user_agent: Some("Test Agent".to_owned()),
            },
            session_id,
        );

        assert!(response.current);
        assert_eq!(response.id, session_id);
        assert_eq!(response.acr, "urn:cairn:acr:password");
        assert_eq!(response.amr, ["pwd"]);
        assert_eq!(response.created_ip_address.as_deref(), Some("203.0.113.10"));
        assert_eq!(response.created_user_agent.as_deref(), Some("Test Agent"));
    }
}
