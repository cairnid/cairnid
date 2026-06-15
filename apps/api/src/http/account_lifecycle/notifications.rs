use cairn_domain::{AccountToken, AuthSession, EmailOutboxMessage, User, UserId};
use serde_json::json;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use super::super::AppState;

pub(in crate::http) fn password_change_notification_email(
    state: &AppState,
    user: &User,
    session: &AuthSession,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    at: OffsetDateTime,
) -> EmailOutboxMessage {
    debug_assert_eq!(user.organization_id, state.organization_id);
    debug_assert_eq!(user.id, session.user_id);
    let changed_at = format_rfc3339(at);
    let ip_line = ip_address.unwrap_or("Unknown");
    let user_agent_line = user_agent.unwrap_or("Unknown");

    EmailOutboxMessage {
        id: Uuid::new_v4(),
        organization_id: state.organization_id,
        recipient_email: user.email.clone(),
        subject: "Your Cairn Identity password was changed".to_owned(),
        body_text: format!(
            "Your Cairn Identity password was changed.\n\nTime: {changed_at}\nIP address: {ip_line}\nBrowser: {user_agent_line}\n\nIf this was you, no action is needed. If this was not you, reset your password immediately and contact your administrator."
        ),
        template: "password_changed_notification".to_owned(),
        action_path: None,
        delivery_token_ciphertext: None,
        delivery_token_nonce: None,
        status: "queued".to_owned(),
        attempts: 0,
        last_error: None,
        provider_message_id: None,
        metadata: json!({
            "kind": "password_changed_notification",
            "user_id": user.id,
            "session_id": session.id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "changed_at": changed_at
        }),
        created_at: at,
        updated_at: at,
        next_attempt_at: None,
        sent_at: None,
    }
}

pub(in crate::http) fn password_recovery_completed_notification_email(
    state: &AppState,
    token: &AccountToken,
    user_id: UserId,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    at: OffsetDateTime,
) -> EmailOutboxMessage {
    debug_assert_eq!(token.organization_id, state.organization_id);
    let recovered_at = format_rfc3339(at);
    let ip_line = ip_address.unwrap_or("Unknown");
    let user_agent_line = user_agent.unwrap_or("Unknown");

    EmailOutboxMessage {
        id: Uuid::new_v4(),
        organization_id: state.organization_id,
        recipient_email: token.email.clone(),
        subject: "Your Cairn Identity password was reset".to_owned(),
        body_text: format!(
            "Your Cairn Identity password was reset using account recovery.\n\nTime: {recovered_at}\nIP address: {ip_line}\nBrowser: {user_agent_line}\n\nIf this was you, no action is needed. If this was not you, contact your administrator immediately."
        ),
        template: "password_recovered_notification".to_owned(),
        action_path: None,
        delivery_token_ciphertext: None,
        delivery_token_nonce: None,
        status: "queued".to_owned(),
        attempts: 0,
        last_error: None,
        provider_message_id: None,
        metadata: json!({
            "kind": "password_recovered_notification",
            "account_token_id": token.id,
            "user_id": user_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "recovered_at": recovered_at
        }),
        created_at: at,
        updated_at: at,
        next_attempt_at: None,
        sent_at: None,
    }
}

pub(in crate::http) fn new_login_notification_email(
    state: &AppState,
    user: &User,
    session: &AuthSession,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    at: OffsetDateTime,
) -> EmailOutboxMessage {
    debug_assert_eq!(user.organization_id, state.organization_id);
    debug_assert_eq!(user.id, session.user_id);
    let logged_in_at = format_rfc3339(at);
    let ip_line = ip_address.unwrap_or("Unknown");
    let user_agent_line = user_agent.unwrap_or("Unknown");

    EmailOutboxMessage {
        id: Uuid::new_v4(),
        organization_id: state.organization_id,
        recipient_email: user.email.clone(),
        subject: "New Cairn Identity sign-in".to_owned(),
        body_text: format!(
            "A new Cairn Identity sign-in was detected.\n\nTime: {logged_in_at}\nIP address: {ip_line}\nBrowser: {user_agent_line}\n\nIf this was you, no action is needed. If this was not you, change your password immediately and contact your administrator."
        ),
        template: "new_login_notification".to_owned(),
        action_path: None,
        delivery_token_ciphertext: None,
        delivery_token_nonce: None,
        status: "queued".to_owned(),
        attempts: 0,
        last_error: None,
        provider_message_id: None,
        metadata: json!({
            "kind": "new_login_notification",
            "user_id": user.id,
            "session_id": session.id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "logged_in_at": logged_in_at
        }),
        created_at: at,
        updated_at: at,
        next_attempt_at: None,
        sent_at: None,
    }
}

fn format_rfc3339(timestamp: OffsetDateTime) -> String {
    timestamp
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_owned())
}
