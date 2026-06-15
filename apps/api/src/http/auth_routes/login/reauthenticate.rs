use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_authn::verify_password;
use cairn_database::SessionRequestContext;
use cairn_domain::UserStatus;
use secrecy::SecretString;
use serde_json::json;
use time::OffsetDateTime;

use super::super::super::{
    AppState, REAUTHENTICATION_RATE_LIMIT_BLOCK, REAUTHENTICATION_RATE_LIMIT_MAX_ATTEMPTS,
    REAUTHENTICATION_RATE_LIMIT_WINDOW,
    api_response::{ApiError, ApiJson},
    cookies::{require_csrf, set_session_cookie},
    mfa::authenticated_session,
    request_context::{
        RequestIdentity, audit_request_context_for_identity, enforce_rate_limit,
        reauthentication_rate_limit_keys_for_identity, record_rate_limit_failure,
    },
    session_auth::require_session,
};
use super::super::requests::ReauthenticateRequest;
use super::mfa::{MfaFailurePolicy, MfaVerification, SubmittedMfa, verify_submitted_mfa};

pub(in crate::http) async fn reauthenticate(
    State(state): State<AppState>,
    request_identity: RequestIdentity,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<ReauthenticateRequest>,
) -> Result<Response, ApiError> {
    let current_session = require_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let submitted_mfa_code = payload.mfa_code().map(ToOwned::to_owned);
    let webauthn_challenge_id = payload.webauthn_challenge_id;
    let webauthn_credential = payload.webauthn_credential;
    let rate_limit_keys = reauthentication_rate_limit_keys_for_identity(
        current_session.organization_id,
        current_session.user_id,
        &request_identity,
    );
    enforce_rate_limit(&state, &rate_limit_keys).await?;

    let user_with_password = state
        .database
        .get_user_with_password(current_session.organization_id, current_session.user_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::UNAUTHORIZED, "user missing"))?;
    let Some(password_hash) = user_with_password.password_hash.as_deref() else {
        return Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "password authentication unavailable",
        ));
    };
    if user_with_password.user.status != UserStatus::Active {
        return Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "user is not active",
        ));
    }

    if verify_password(&SecretString::from(payload.password), password_hash).is_err() {
        record_rate_limit_failure(
            &state,
            &rate_limit_keys,
            REAUTHENTICATION_RATE_LIMIT_WINDOW,
            REAUTHENTICATION_RATE_LIMIT_MAX_ATTEMPTS,
            REAUTHENTICATION_RATE_LIMIT_BLOCK,
        )
        .await?;
        return Err(ApiError::status(
            StatusCode::UNAUTHORIZED,
            "invalid credentials",
        ));
    }

    let mfa = verify_submitted_mfa(
        &state,
        current_session.organization_id,
        current_session.user_id,
        SubmittedMfa {
            code: submitted_mfa_code.as_deref(),
            webauthn_challenge_id,
            webauthn_credential: webauthn_credential.as_ref(),
        },
        MfaFailurePolicy {
            rate_limit_keys: &rate_limit_keys,
            window: REAUTHENTICATION_RATE_LIMIT_WINDOW,
            max_attempts: REAUTHENTICATION_RATE_LIMIT_MAX_ATTEMPTS,
            block_for: REAUTHENTICATION_RATE_LIMIT_BLOCK,
        },
    )
    .await?;
    let mfa_method = match mfa {
        MfaVerification::Verified(method) => method,
        MfaVerification::Required(response) => return Ok(response),
    };

    let now = OffsetDateTime::now_utc();
    let new_session = authenticated_session(
        current_session.organization_id,
        current_session.user_id,
        mfa_method.as_ref(),
        now,
    );
    let (ip_address, user_agent) = audit_request_context_for_identity(&request_identity, &headers);
    state
        .database
        .rotate_auth_session_with_context(
            current_session.id,
            &new_session,
            now,
            SessionRequestContext::new(ip_address.as_deref(), user_agent.as_deref()),
        )
        .await?;
    state
        .database
        .set_user_last_login(new_session.user_id, now)
        .await?;
    state
        .database
        .clear_rate_limit_bucket(rate_limit_keys[0].bucket_key())
        .await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                new_session.organization_id,
                new_session.user_id,
                "session.reauthenticated",
                new_session.id.to_string(),
            )
            .request_context(ip_address, user_agent)
            .metadata(json!({
                "previous_session_id": current_session.id,
                "acr": new_session.acr.clone(),
                "amr": new_session.amr.clone()
            }))
            .build(),
        )
        .await?;

    let mut response = Json(json!({
        "status": "reauthenticated",
        "acr": new_session.acr.clone(),
        "amr": new_session.amr.clone()
    }))
    .into_response();
    set_session_cookie(response.headers_mut(), &state.config, new_session.id)?;
    Ok(response)
}
