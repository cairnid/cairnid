use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_authn::{hash_password, verify_token_hash};
use cairn_domain::{Membership, MembershipRole, User};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use time::OffsetDateTime;

use super::super::{
    AppState, BOOTSTRAP_RATE_LIMIT_BLOCK, BOOTSTRAP_RATE_LIMIT_MAX_ATTEMPTS,
    BOOTSTRAP_RATE_LIMIT_WINDOW,
    account_lifecycle::valid_new_password,
    api_response::{ApiError, ApiJson},
    cookies::require_csrf,
    request_context::{
        RequestIdentity, bootstrap_rate_limit_keys, enforce_rate_limit, record_rate_limit_failure,
    },
    session_auth::bootstrap_admin_group,
};
use super::requests::BootstrapRequest;

pub(in crate::http) async fn bootstrap(
    State(state): State<AppState>,
    request_identity: RequestIdentity,
    headers: HeaderMap,
    ApiJson(payload): ApiJson<BootstrapRequest>,
) -> Result<Response, ApiError> {
    require_csrf(&headers)?;
    let rate_limit_keys = bootstrap_rate_limit_keys(state.organization_id, &request_identity);
    enforce_rate_limit(&state, &rate_limit_keys).await?;

    if !valid_bootstrap_setup_secret(
        state.config.bootstrap_setup_secret_hash.as_ref(),
        payload.setup_secret.as_deref(),
    ) {
        record_rate_limit_failure(
            &state,
            &rate_limit_keys,
            BOOTSTRAP_RATE_LIMIT_WINDOW,
            BOOTSTRAP_RATE_LIMIT_MAX_ATTEMPTS,
            BOOTSTRAP_RATE_LIMIT_BLOCK,
        )
        .await?;
        return Err(ApiError::status(
            StatusCode::UNAUTHORIZED,
            "invalid setup secret",
        ));
    }

    let mut user = User::new(state.organization_id, payload.email, payload.display_name)?;
    user.email_verified = true;
    let password = valid_new_password(payload.password)?;
    let hash = hash_password(&SecretString::from(password))?;
    let now = OffsetDateTime::now_utc();
    let admin_group = bootstrap_admin_group(state.organization_id, now);
    let admin_membership = Membership {
        organization_id: state.organization_id,
        user_id: user.id,
        group_id: admin_group.id,
        role: MembershipRole::Owner,
        created_at: now,
    };

    match state
        .database
        .create_bootstrap_admin(&user, &hash, &admin_group, &admin_membership)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(ApiError::status(
                StatusCode::CONFLICT,
                "bootstrap is already complete",
            ));
        }
        Err(error) => {
            record_rate_limit_failure(
                &state,
                &rate_limit_keys,
                BOOTSTRAP_RATE_LIMIT_WINDOW,
                BOOTSTRAP_RATE_LIMIT_MAX_ATTEMPTS,
                BOOTSTRAP_RATE_LIMIT_BLOCK,
            )
            .await?;
            return Err(error.into());
        }
    }

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::system(
                state.organization_id,
                "bootstrap.user_created",
                user.id.to_string(),
            )
            .metadata(json!({ "admin_group_id": admin_group.id }))
            .build(),
        )
        .await?;

    Ok((StatusCode::CREATED, Json(user)).into_response())
}

fn valid_bootstrap_setup_secret(
    expected_hash: Option<&SecretString>,
    submitted_secret: Option<&str>,
) -> bool {
    let Some(expected_hash) = expected_hash else {
        return true;
    };
    let Some(submitted_secret) = submitted_secret
        .map(str::trim)
        .filter(|secret| !secret.is_empty())
    else {
        return false;
    };

    verify_token_hash(submitted_secret, expected_hash.expose_secret())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_authn::hash_token;

    #[test]
    fn bootstrap_setup_secret_is_optional_when_unconfigured() {
        assert!(valid_bootstrap_setup_secret(None, None));
        assert!(valid_bootstrap_setup_secret(None, Some("anything")));
    }

    #[test]
    fn bootstrap_setup_secret_requires_matching_submitted_value() {
        let expected_hash = SecretString::from(hash_token("operator-held-secret"));

        assert!(valid_bootstrap_setup_secret(
            Some(&expected_hash),
            Some(" operator-held-secret ")
        ));
        assert!(!valid_bootstrap_setup_secret(
            Some(&expected_hash),
            Some("wrong-secret")
        ));
        assert!(!valid_bootstrap_setup_secret(Some(&expected_hash), None));
        assert!(!valid_bootstrap_setup_secret(
            Some(&expected_hash),
            Some(" ")
        ));
    }
}
