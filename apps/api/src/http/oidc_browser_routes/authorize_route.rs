use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method},
    response::Response,
};
use cairn_authn::generate_hashed_secret;
use cairn_database::ConsentAuthorizationConsumption;
use cairn_domain::AuthorizationCode;
use cairn_oidc::{OidcError, append_authorization_response_params};
use secrecy::ExposeSecret;
use time::{Duration, OffsetDateTime};

use super::super::{
    AppState, OAUTH_FORM_BODY_MAX_BYTES,
    api_response::ApiError,
    authorization::{
        AuthorizeUrlPromptMode, authorization_error_redirect,
        authorization_error_redirect_with_code, authorization_query_pairs,
        authorization_request_from_query_pairs, authorization_request_hash, current_authorize_url,
        duplicate_authorization_request_parameter,
    },
    client_policy::client_consent_policy_requires_prompt,
    content_type::request_has_urlencoded_content_type,
    oauth_client::oidc_client_is_active,
    oauth_http::oauth_redirect_response,
    request_body::bounded_request_body,
    session_auth::{
        require_client_in_session_organization, session_exceeds_max_age, session_from_cookie,
    },
    urlencoded::{parse_url_encoded_pairs, percent_encode_minimal},
};

pub(in crate::http) async fn authorize(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, ApiError> {
    let method = request.method().clone();
    let headers = request.headers().clone();
    let raw_query = request.uri().query().map(str::to_owned);
    let query_pairs = if method == Method::POST {
        authorization_form_pairs(&headers, request).await?
    } else {
        authorization_query_pairs(raw_query.as_deref())?
    };

    authorize_with_pairs(state, headers, query_pairs).await
}

async fn authorize_with_pairs(
    state: AppState,
    headers: HeaderMap,
    query_pairs: Vec<(String, String)>,
) -> Result<Response, ApiError> {
    let duplicate_parameter = duplicate_authorization_request_parameter(&query_pairs);
    if matches!(duplicate_parameter, Some("client_id" | "redirect_uri")) {
        return Err(ApiError::bad_request(
            "duplicate authorization request parameter",
        ));
    }
    let (request, parse_error) = authorization_request_from_query_pairs(&query_pairs);

    let client = state
        .database
        .get_oidc_client_by_public_id(&request.client_id)
        .await?
        .ok_or_else(|| ApiError::bad_request("unknown client"))?;
    if !client.allows_redirect_uri(&request.redirect_uri) {
        return Err(ApiError::bad_request("invalid redirect URI"));
    }
    if !oidc_client_is_active(&client) {
        let target = authorization_error_redirect_with_code(
            &request,
            &state.config.issuer,
            "unauthorized_client",
            Some("client is disabled"),
        );
        return Ok(oauth_redirect_response(&target));
    }
    if duplicate_parameter.is_some() {
        let target = authorization_error_redirect_with_code(
            &request,
            &state.config.issuer,
            "invalid_request",
            Some("duplicate authorization request parameter"),
        );
        return Ok(oauth_redirect_response(&target));
    }
    if let Some(error) = parse_error {
        let target = authorization_error_redirect(&request, &state.config.issuer, error);
        return Ok(oauth_redirect_response(&target));
    }
    let validated = match request.clone().validate(&client) {
        Ok(validated) => validated,
        Err(OidcError::InvalidRedirectUri) => {
            return Err(ApiError::bad_request("invalid redirect URI"));
        }
        Err(error) => {
            let target = authorization_error_redirect(&request, &state.config.issuer, error);
            return Ok(oauth_redirect_response(&target));
        }
    };

    let Some(session) = session_from_cookie(&state, &headers).await? else {
        if validated.prompt.is_none() {
            let target = authorization_error_redirect_with_code(
                &request,
                &state.config.issuer,
                "login_required",
                Some("login required"),
            );
            return Ok(oauth_redirect_response(&target));
        }
        let prompt_mode = if validated.prompt.requires_login() {
            AuthorizeUrlPromptMode::RemoveLogin
        } else {
            AuthorizeUrlPromptMode::Preserve
        };
        let return_to = percent_encode_minimal(&current_authorize_url(
            &state.config.issuer,
            &request,
            prompt_mode,
        ));
        let target = format!(
            "{}/login?return_to={return_to}",
            state.config.public_web_origin
        );
        return Ok(oauth_redirect_response(&target));
    };
    require_client_in_session_organization(&client, &session)?;
    let now = OffsetDateTime::now_utc();
    if validated.prompt.requires_login() {
        let return_to = percent_encode_minimal(&current_authorize_url(
            &state.config.issuer,
            &request,
            AuthorizeUrlPromptMode::RemoveLogin,
        ));
        let target = format!(
            "{}/login?return_to={return_to}",
            state.config.public_web_origin
        );
        return Ok(oauth_redirect_response(&target));
    }
    if session_exceeds_max_age(&session, validated.max_age, now) {
        if validated.prompt.is_none() {
            let target = authorization_error_redirect_with_code(
                &request,
                &state.config.issuer,
                "login_required",
                Some("login required"),
            );
            return Ok(oauth_redirect_response(&target));
        }
        let return_to = percent_encode_minimal(&current_authorize_url(
            &state.config.issuer,
            &request,
            AuthorizeUrlPromptMode::Preserve,
        ));
        let target = format!(
            "{}/login?return_to={return_to}",
            state.config.public_web_origin
        );
        return Ok(oauth_redirect_response(&target));
    }
    if !session_satisfies_requested_acr(&session.acr, &validated.acr_values) {
        if validated.prompt.is_none() {
            let target = authorization_error_redirect_with_code(
                &request,
                &state.config.issuer,
                "login_required",
                Some("requested acr_values require reauthentication"),
            );
            return Ok(oauth_redirect_response(&target));
        }
        let return_to = percent_encode_minimal(&current_authorize_url(
            &state.config.issuer,
            &request,
            AuthorizeUrlPromptMode::Preserve,
        ));
        let target = format!(
            "{}/login?return_to={return_to}",
            state.config.public_web_origin
        );
        return Ok(oauth_redirect_response(&target));
    }

    let has_consent = state
        .database
        .has_active_consent_grant(
            session.organization_id,
            session.user_id,
            client.id,
            &validated.scopes,
        )
        .await?;
    let policy_requires_consent =
        client_consent_policy_requires_prompt(&state, session.organization_id, &client).await?;
    let prompt_requires_consent = validated.prompt.requires_consent();
    let policy_consent_satisfied =
        if policy_requires_consent && !prompt_requires_consent && !validated.prompt.is_none() {
            let request_hash = authorization_request_hash(&state.config.issuer, &request);
            state
                .database
                .consume_consent_authorization(ConsentAuthorizationConsumption {
                    organization_id: session.organization_id,
                    user_id: session.user_id,
                    session_id: session.id,
                    client_id: client.id,
                    authorization_request_hash: &request_hash,
                    scopes: &validated.scopes,
                    at: now,
                })
                .await?
        } else {
            false
        };
    if !has_consent
        || prompt_requires_consent
        || (policy_requires_consent && !policy_consent_satisfied)
    {
        if validated.prompt.is_none() {
            let target = authorization_error_redirect_with_code(
                &request,
                &state.config.issuer,
                "consent_required",
                Some("consent required"),
            );
            return Ok(oauth_redirect_response(&target));
        }
        let return_to = percent_encode_minimal(&current_authorize_url(
            &state.config.issuer,
            &request,
            AuthorizeUrlPromptMode::RemoveConsent,
        ));
        let scopes = percent_encode_minimal(&validated.scopes.join(" "));
        let target = format!(
            "{}/consent?return_to={return_to}&client_id={}&client_name={}&scopes={scopes}",
            state.config.public_web_origin,
            percent_encode_minimal(&client.client_id),
            percent_encode_minimal(&client.name),
        );
        return Ok(oauth_redirect_response(&target));
    }

    let grant = generate_hashed_secret(32);
    let code = AuthorizationCode {
        code_hash: grant.hash,
        organization_id: session.organization_id,
        user_id: session.user_id,
        session_id: session.id,
        client_id: client.id,
        redirect_uri: validated.redirect_uri.clone(),
        scopes: validated.scopes,
        nonce: validated.nonce,
        code_challenge: validated.code_challenge,
        code_challenge_method: validated.code_challenge_method,
        created_at: now,
        expires_at: now + Duration::minutes(5),
        used_at: None,
    };
    state.database.insert_authorization_code(&code).await?;

    let target = append_authorization_response_params(
        &validated.redirect_uri,
        grant.value.expose_secret(),
        validated.state.as_deref(),
        &state.config.issuer,
    );

    Ok(oauth_redirect_response(&target))
}

async fn authorization_form_pairs(
    headers: &HeaderMap,
    request: Request,
) -> Result<Vec<(String, String)>, ApiError> {
    if !request_has_urlencoded_content_type(headers) {
        return Err(ApiError::bad_request(
            "content type must be application/x-www-form-urlencoded",
        ));
    }
    let body = bounded_request_body(request, OAUTH_FORM_BODY_MAX_BYTES)
        .await
        .map_err(|_| ApiError::bad_request("authorization request too large"))?;
    let body = std::str::from_utf8(&body)
        .map_err(|_| ApiError::bad_request("invalid authorization request"))?;
    parse_url_encoded_pairs(body)
        .map_err(|_| ApiError::bad_request("invalid authorization request"))
}

fn session_satisfies_requested_acr(session_acr: &str, requested_acr_values: &[String]) -> bool {
    requested_acr_values.is_empty()
        || requested_acr_values
            .iter()
            .any(|requested| requested == session_acr)
}
