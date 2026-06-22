use axum::{
    Json,
    extract::{RawQuery, State},
    http::HeaderMap,
};
use cairn_database::ListCursor;
use cairn_domain::AuditEvent;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    ADMIN_LIST_DEFAULT_LIMIT, ADMIN_LIST_MAX_LIMIT, AppState,
    admin_query::{ListPage, ListQueryLabels, list_page, list_query},
    api_response::ApiError,
    session_auth::require_session,
};

pub(in crate::http) async fn list_security_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<ListPage<SessionSecurityActivityEvent>>, ApiError> {
    let session = require_session(&state, &headers).await?;
    let query = list_query(
        raw_query.as_deref(),
        ADMIN_LIST_DEFAULT_LIMIT,
        ADMIN_LIST_MAX_LIMIT,
        ListQueryLabels {
            too_large: "session security activity query too large",
            invalid_query: "invalid session security activity query",
            duplicate_parameter: "duplicate session security activity parameter",
            invalid_limit: "invalid session security activity limit",
            limit_out_of_range: "session security activity limit out of range",
            invalid_cursor: "invalid session security activity cursor",
            unsupported_parameter: "unsupported session security activity parameter",
        },
    )?;
    let events = state
        .database
        .list_user_security_events_page(
            session.organization_id,
            session.user_id,
            query.cursor,
            query.fetch_limit(),
        )
        .await?
        .into_iter()
        .map(SessionSecurityActivityEvent::from)
        .collect::<Vec<_>>();

    Ok(Json(list_page(events, query.limit, |event| {
        ListCursor::new(event.occurred_at, event.id)
    })))
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(in crate::http) struct SessionSecurityActivityEvent {
    id: Uuid,
    event_type: &'static str,
    summary: &'static str,
    ip_address: Option<String>,
    user_agent: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    occurred_at: OffsetDateTime,
}

impl From<AuditEvent> for SessionSecurityActivityEvent {
    fn from(event: AuditEvent) -> Self {
        let (event_type, summary) = security_activity_labels(&event.action);
        Self {
            id: event.id,
            event_type,
            summary,
            ip_address: event.ip_address,
            user_agent: event.user_agent,
            occurred_at: event.created_at,
        }
    }
}

fn security_activity_labels(action: &str) -> (&'static str, &'static str) {
    match action {
        "session.logged_in" => ("sign_in", "Signed in"),
        "session.logged_out" => ("sign_out", "Signed out"),
        "session.reauthenticated" => ("reauthentication", "Reauthenticated"),
        "session.revoked_by_user" => ("session_revoked", "Browser session revoked"),
        "admin.user_session_revoked" => (
            "administrator_action",
            "An administrator revoked a browser session",
        ),
        "admin.consent_revoked" => (
            "application_consent",
            "An administrator revoked application access",
        ),
        "admin.email_verification_requested" => (
            "email_verification_requested",
            "An administrator requested email verification",
        ),
        "admin.password_recovery_requested" => (
            "password_recovery_requested",
            "An administrator requested password recovery",
        ),
        "admin.user_created" => (
            "administrator_action",
            "An administrator created this account",
        ),
        "admin.user_status_updated" => (
            "administrator_action",
            "An administrator updated account status",
        ),
        "account.password_changed" => ("password_changed", "Password changed"),
        "account.password_recovery_requested" => {
            ("password_recovery_requested", "Password recovery requested")
        }
        "account.password_recovered" => ("password_recovered", "Password recovered"),
        "account.email_verification_requested" => (
            "email_verification_requested",
            "Email verification requested",
        ),
        "account.email_verified" => ("email_verified", "Email verified"),
        "mfa.totp_enrollment_started" => ("mfa_updated", "Authenticator app enrollment started"),
        "mfa.totp_enabled" => ("mfa_updated", "Authenticator app enabled"),
        "mfa.webauthn_enrollment_started" => ("mfa_updated", "Passkey enrollment started"),
        "mfa.webauthn_enabled" => ("mfa_updated", "Passkey enabled"),
        "mfa.credential_revoked" => ("mfa_updated", "Multi-factor credential revoked"),
        "mfa.recovery_codes_regenerated" => ("mfa_updated", "Recovery codes regenerated"),
        "oauth.consent_granted" => ("application_consent", "Application access approved"),
        "user.consent_revoked" => ("application_consent", "Application access revoked"),
        action if action.starts_with("admin.") => (
            "administrator_action",
            "An administrator updated this account",
        ),
        _ => ("security_event", "Security event recorded"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_domain::{AuditActorKind, AuditEvent};
    use serde_json::json;

    #[test]
    fn security_activity_projection_redacts_raw_audit_details() {
        let event = AuditEvent {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            actor_kind: AuditActorKind::User,
            actor_id: Some(Uuid::new_v4()),
            action: "account.password_changed".to_owned(),
            target: Uuid::new_v4().to_string(),
            ip_address: Some("203.0.113.10".to_owned()),
            user_agent: Some("Cairn-Test/1.0".to_owned()),
            metadata: json!({ "notification_email_outbox_id": Uuid::new_v4() }),
            created_at: OffsetDateTime::now_utc(),
        };

        let projected = SessionSecurityActivityEvent::from(event);

        assert_eq!(projected.event_type, "password_changed");
        assert_eq!(projected.summary, "Password changed");
        assert_eq!(projected.ip_address.as_deref(), Some("203.0.113.10"));
        assert_eq!(projected.user_agent.as_deref(), Some("Cairn-Test/1.0"));
    }

    #[test]
    fn admin_actions_are_coarsened_for_product_activity() {
        assert_eq!(
            security_activity_labels("admin.user_created"),
            (
                "administrator_action",
                "An administrator created this account"
            )
        );
        assert_eq!(
            security_activity_labels("admin.group_membership_upserted"),
            (
                "administrator_action",
                "An administrator updated this account"
            )
        );
        assert_eq!(
            security_activity_labels("admin.consent_revoked"),
            (
                "application_consent",
                "An administrator revoked application access"
            )
        );
    }
}
