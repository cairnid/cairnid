mod mfa;
mod reauthenticate;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_authn::verify_password;
use cairn_database::{AuthSessionCreationInput, SessionRequestContext};
use cairn_domain::UserStatus;
use secrecy::SecretString;
use serde_json::json;
use time::OffsetDateTime;

pub(in crate::http) use reauthenticate::reauthenticate;

use self::mfa::{MfaFailurePolicy, MfaVerification, SubmittedMfa, verify_submitted_mfa};
use super::super::{
    AppState, LOGIN_RATE_LIMIT_BLOCK, LOGIN_RATE_LIMIT_MAX_ATTEMPTS, LOGIN_RATE_LIMIT_WINDOW,
    account_lifecycle::new_login_notification_email,
    api_response::{ApiError, ApiJson},
    cookies::{require_csrf, set_session_cookie},
    mfa::authenticated_session,
    request_context::{
        RequestIdentity, audit_request_context_for_identity, enforce_rate_limit,
        login_pre_credential_rate_limit_keys, login_verified_user_rate_limit_keys,
        record_rate_limit_failure,
    },
};
use super::requests::LoginRequest;

pub(in crate::http) async fn login(
    State(state): State<AppState>,
    request_identity: RequestIdentity,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<LoginRequest>,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    let submitted_mfa_code = payload.mfa_code().map(ToOwned::to_owned);
    let webauthn_challenge_id = payload.webauthn_challenge_id;
    let webauthn_credential = payload.webauthn_credential;
    let email = cairn_domain::normalize_email(payload.email)?;
    let pre_credential_rate_limit_keys =
        login_pre_credential_rate_limit_keys(state.organization_id, &request_identity);
    enforce_rate_limit(&state, &pre_credential_rate_limit_keys).await?;

    let Some(user_with_password) = state
        .database
        .find_user_by_email(state.organization_id, &email)
        .await?
    else {
        record_rate_limit_failure(
            &state,
            &pre_credential_rate_limit_keys,
            LOGIN_RATE_LIMIT_WINDOW,
            LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
            LOGIN_RATE_LIMIT_BLOCK,
        )
        .await?;
        return Err(ApiError::status(
            StatusCode::UNAUTHORIZED,
            "invalid credentials",
        ));
    };
    let Some(password_hash) = user_with_password.password_hash.as_deref() else {
        record_rate_limit_failure(
            &state,
            &pre_credential_rate_limit_keys,
            LOGIN_RATE_LIMIT_WINDOW,
            LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
            LOGIN_RATE_LIMIT_BLOCK,
        )
        .await?;
        return Err(ApiError::status(
            StatusCode::UNAUTHORIZED,
            "invalid credentials",
        ));
    };
    if user_with_password.user.status != UserStatus::Active {
        record_rate_limit_failure(
            &state,
            &pre_credential_rate_limit_keys,
            LOGIN_RATE_LIMIT_WINDOW,
            LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
            LOGIN_RATE_LIMIT_BLOCK,
        )
        .await?;
        return Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "user is not active",
        ));
    }

    if verify_password(&SecretString::from(payload.password), password_hash).is_err() {
        record_rate_limit_failure(
            &state,
            &pre_credential_rate_limit_keys,
            LOGIN_RATE_LIMIT_WINDOW,
            LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
            LOGIN_RATE_LIMIT_BLOCK,
        )
        .await?;
        return Err(ApiError::status(
            StatusCode::UNAUTHORIZED,
            "invalid credentials",
        ));
    }

    let verified_user_rate_limit_keys = login_verified_user_rate_limit_keys(
        state.organization_id,
        user_with_password.user.id,
        &request_identity,
    );
    enforce_rate_limit(&state, &verified_user_rate_limit_keys).await?;

    let mfa = verify_submitted_mfa(
        &state,
        user_with_password.user.organization_id,
        user_with_password.user.id,
        SubmittedMfa {
            code: submitted_mfa_code.as_deref(),
            webauthn_challenge_id,
            webauthn_credential: webauthn_credential.as_ref(),
        },
        MfaFailurePolicy {
            rate_limit_keys: &verified_user_rate_limit_keys,
            window: LOGIN_RATE_LIMIT_WINDOW,
            max_attempts: LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
            block_for: LOGIN_RATE_LIMIT_BLOCK,
        },
    )
    .await?;
    let mfa_method = match mfa {
        MfaVerification::Verified(method) => method,
        MfaVerification::Required(response) => return Ok(response),
    };

    let now = OffsetDateTime::now_utc();
    let session = authenticated_session(
        user_with_password.user.organization_id,
        user_with_password.user.id,
        mfa_method.as_ref(),
        now,
    );
    let (ip_address, user_agent) = audit_request_context_for_identity(&request_identity, &headers);
    let new_context_notification =
        SessionRequestContext::new(ip_address.as_deref(), user_agent.as_deref())
            .has_identifying_context()
            .then(|| {
                new_login_notification_email(
                    &state,
                    &user_with_password.user,
                    &session,
                    ip_address.as_deref(),
                    user_agent.as_deref(),
                    now,
                )
            });
    let new_context_notification_email_outbox_id = state
        .database
        .create_auth_session_with_new_context_notification(AuthSessionCreationInput {
            session: &session,
            request_context: SessionRequestContext::new(
                ip_address.as_deref(),
                user_agent.as_deref(),
            ),
            new_context_notification: new_context_notification.as_ref(),
        })
        .await?;
    state
        .database
        .set_user_last_login(session.user_id, now)
        .await?;
    state
        .database
        .clear_rate_limit_bucket(verified_user_rate_limit_keys[0].bucket_key())
        .await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                session.organization_id,
                session.user_id,
                "session.logged_in",
                session.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "acr": session.acr.clone(),
                "amr": session.amr.clone(),
                "new_context_notification_email_outbox_id": new_context_notification_email_outbox_id
            }))
            .build(),
        )
        .await?;

    let mut response = Json(json!({ "user": user_with_password.user })).into_response();
    set_session_cookie(response.headers_mut(), &state.config, session.id)?;
    Ok(response)
}
