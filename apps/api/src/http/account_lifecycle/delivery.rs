use axum::http::StatusCode;
use cairn_authn::generate_hashed_secret;
use cairn_domain::{AccountToken, AccountTokenKind, EmailOutboxMessage, Environment, UserId};
use cairn_oidc::encrypt_secret;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::super::{AppState, api_response::ApiError};

pub(in crate::http) struct AccountLifecycleEmail {
    pub(in crate::http) kind: AccountTokenKind,
    pub(in crate::http) user_id: Option<UserId>,
    pub(in crate::http) email: String,
    pub(in crate::http) created_by_user_id: Option<UserId>,
    pub(in crate::http) ttl: Duration,
    pub(in crate::http) template: &'static str,
    pub(in crate::http) subject: &'static str,
    pub(in crate::http) action_path: &'static str,
    pub(in crate::http) body_intro: &'static str,
    pub(in crate::http) metadata: Value,
}

pub(in crate::http) async fn queue_account_lifecycle_email(
    state: &AppState,
    request: AccountLifecycleEmail,
) -> Result<Value, ApiError> {
    let secret = generate_hashed_secret(32);
    let now = OffsetDateTime::now_utc();
    let token = AccountToken {
        id: secret.id,
        organization_id: state.organization_id,
        kind: request.kind,
        user_id: request.user_id,
        email: request.email.clone(),
        token_hash: secret.hash,
        created_by_user_id: request.created_by_user_id,
        created_at: now,
        expires_at: now + request.ttl,
        consumed_at: None,
        metadata: request.metadata,
    };
    let encrypted_delivery = match &state.config.key_encryption_key {
        Some(key) => Some(encrypt_secret(
            secret.value.expose_secret(),
            key,
            &account_token_aad(request.kind, token.id),
        )?),
        None if matches!(state.config.environment, Environment::Development) => None,
        None => {
            return Err(ApiError::status(
                StatusCode::INTERNAL_SERVER_ERROR,
                "CAIRN_KEY_ENCRYPTION_KEY is required for account lifecycle email delivery",
            ));
        }
    };
    let message = EmailOutboxMessage {
        id: Uuid::new_v4(),
        organization_id: state.organization_id,
        recipient_email: request.email,
        subject: request.subject.to_owned(),
        body_text: format!(
            "{}\n\nOpen this link to continue: {{{{action_url}}}}\n\nIf you did not request this email, ignore it.",
            request.body_intro
        ),
        template: request.template.to_owned(),
        action_path: Some(request.action_path.to_owned()),
        delivery_token_ciphertext: encrypted_delivery
            .as_ref()
            .map(|secret| secret.ciphertext.clone()),
        delivery_token_nonce: encrypted_delivery
            .as_ref()
            .map(|secret| secret.nonce.clone()),
        status: "queued".to_owned(),
        attempts: 0,
        last_error: None,
        provider_message_id: None,
        metadata: json!({
            "account_token_id": token.id,
            "kind": account_token_kind_label(request.kind),
            "encrypted_delivery_token": encrypted_delivery.is_some()
        }),
        created_at: now,
        updated_at: now,
        next_attempt_at: None,
        sent_at: None,
    };

    state
        .database
        .insert_account_token_and_email_outbox_message(&token, &message)
        .await?;

    // Raw token URLs stay out of HTTP responses; the outbox worker renders
    // action links from encrypted delivery tokens for operator-controlled sends.
    Ok(queued_delivery_response(
        message.id,
        message.recipient_email,
        token.expires_at,
    ))
}

fn queued_delivery_response(
    email_outbox_id: Uuid,
    recipient_email: String,
    expires_at: OffsetDateTime,
) -> Value {
    json!({
        "status": "queued",
        "email_outbox_id": email_outbox_id,
        "recipient_email": recipient_email,
        "expires_at": expires_at
    })
}

fn account_token_aad(kind: AccountTokenKind, token_id: Uuid) -> String {
    format!(
        "cairnid:account-token-delivery:{}:{token_id}",
        account_token_kind_label(kind)
    )
}

fn account_token_kind_label(kind: AccountTokenKind) -> &'static str {
    match kind {
        AccountTokenKind::EmailVerification => "email_verification",
        AccountTokenKind::PasswordRecovery => "password_recovery",
        AccountTokenKind::Invitation => "invitation",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::queued_delivery_response;

    #[test]
    fn queued_delivery_response_does_not_expose_raw_token_preview_url() {
        let message_id = Uuid::new_v4();
        let expires_at = OffsetDateTime::UNIX_EPOCH;

        let response =
            queued_delivery_response(message_id, "user@example.com".to_owned(), expires_at);

        assert_eq!(
            response,
            json!({
                "status": "queued",
                "email_outbox_id": message_id,
                "recipient_email": "user@example.com",
                "expires_at": expires_at
            })
        );
        assert!(response.get("preview_url").is_none());
    }
}
