use axum::{Json, http::StatusCode, response::Response};
use cairn_authn::{generate_hashed_secret, hash_token};
use cairn_database::AccessTokenRecord;
use cairn_domain::{OidcGrantType, RefreshToken};
use cairn_oidc::{
    IdTokenIssueRequest, OAuthErrorBody, TokenRequest, TokenResponse, issue_id_token,
    verify_authorization_code_pkce,
};
use secrecy::ExposeSecret;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::super::super::{
    AppState,
    api_response::ApiError,
    app_settings::resolve_signing_material,
    oauth_client::{
        authenticated_client_from_request, require_client_bound_to_stored_grant,
        require_token_endpoint_grant,
    },
    oauth_http::{OAuthClientAuth, oauth_json_response, required_oauth_form_parameter},
    oauth_token::{
        required_authorization_code_verifier, should_issue_refresh_token, token_response_scope,
        validate_authorization_code_redirect_uri,
    },
    session_auth::{groups_claim_for_user, user_allows_runtime_access},
};

pub(super) async fn authorization_code_token(
    state: AppState,
    request: TokenRequest,
    client_auth: OAuthClientAuth,
) -> Result<Response, ApiError> {
    let code = required_oauth_form_parameter(request.code.as_deref(), "code")?;
    let code_hash = hash_token(code);
    let stored = state
        .database
        .get_authorization_code(&code_hash)
        .await?
        .ok_or_else(|| {
            ApiError::oauth(
                StatusCode::BAD_REQUEST,
                OAuthErrorBody::invalid_grant("unknown code"),
            )
        })?;

    let now = OffsetDateTime::now_utc();
    if stored.used_at.is_some() || stored.expires_at <= now {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant("code expired or already used"),
        ));
    }
    validate_authorization_code_redirect_uri(
        request.redirect_uri.as_deref(),
        &stored.redirect_uri,
    )?;

    let client = authenticated_client_from_request(&state, &client_auth).await?;
    require_client_bound_to_stored_grant(&client, stored.organization_id, stored.client_id)?;
    require_token_endpoint_grant(&client, OidcGrantType::AuthorizationCode)?;

    let verifier = required_authorization_code_verifier(request.code_verifier.as_deref())?;
    verify_authorization_code_pkce(
        verifier,
        &stored.code_challenge,
        stored.code_challenge_method,
    )
    .map_err(|err| {
        ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant(err.to_string()),
        )
    })?;

    let user = state
        .database
        .get_user(stored.user_id)
        .await?
        .ok_or_else(|| {
            ApiError::oauth(
                StatusCode::BAD_REQUEST,
                OAuthErrorBody::invalid_grant("user missing"),
            )
        })?;
    if !user_allows_runtime_access(&user, stored.organization_id) {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant("session expired or revoked"),
        ));
    }
    let auth_session = state
        .database
        .get_auth_session(stored.session_id)
        .await?
        .ok_or_else(|| {
            ApiError::oauth(
                StatusCode::BAD_REQUEST,
                OAuthErrorBody::invalid_grant("session missing"),
            )
        })?;
    if auth_session.organization_id != stored.organization_id
        || auth_session.user_id != stored.user_id
        || auth_session.revoked_at.is_some()
        || auth_session.expires_at <= now
    {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant("session expired or revoked"),
        ));
    }
    let groups = groups_claim_for_user(
        &state,
        stored.organization_id,
        stored.user_id,
        &stored.scopes,
    )
    .await?;
    let signing = resolve_signing_material(&state).await?;
    let id_token = issue_id_token(IdTokenIssueRequest {
        issuer: &state.config.issuer,
        client: &client,
        user: &user,
        scopes: &stored.scopes,
        nonce: stored.nonce.clone(),
        auth_time: Some(auth_session.created_at),
        amr: auth_session.amr.clone(),
        acr: auth_session.acr.clone(),
        groups,
        signing: &signing,
    })
    .map_err(|err| {
        ApiError::oauth(
            StatusCode::INTERNAL_SERVER_ERROR,
            OAuthErrorBody::invalid_request(err.to_string()),
        )
    })?;

    let refresh = should_issue_refresh_token(&stored.scopes, &client).then(|| {
        let refresh = generate_hashed_secret(32);
        let record = RefreshToken {
            id: refresh.id,
            token_hash: refresh.hash.clone(),
            family_id: Uuid::new_v4(),
            organization_id: stored.organization_id,
            user_id: Some(stored.user_id),
            client_id: stored.client_id,
            scopes: stored.scopes.clone(),
            created_at: now,
            expires_at: now + Duration::days(30),
            rotated_at: None,
            revoked_at: None,
        };
        (refresh, record)
    });
    let access = generate_hashed_secret(32);
    let access_record = AccessTokenRecord {
        token_hash: access.hash,
        organization_id: stored.organization_id,
        user_id: Some(stored.user_id),
        client_id: stored.client_id,
        scopes: stored.scopes.clone(),
        refresh_family_id: refresh.as_ref().map(|(_, record)| record.family_id),
        created_at: now,
        expires_at: now + Duration::minutes(15),
        revoked_at: None,
    };
    let refresh_record = refresh.as_ref().map(|(_, record)| record);

    let consumed = state
        .database
        .consume_authorization_code_and_insert_tokens(
            &code_hash,
            &access_record,
            refresh_record,
            now,
        )
        .await?;
    if !consumed {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_grant("code expired or already used"),
        ));
    }

    Ok(oauth_json_response(
        StatusCode::OK,
        Json(TokenResponse {
            access_token: access.value.expose_secret().to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: 900,
            refresh_token: refresh
                .as_ref()
                .map(|(refresh, _)| refresh.value.expose_secret().to_owned()),
            id_token: Some(id_token),
            scope: token_response_scope(&stored.scopes),
        }),
    ))
}
