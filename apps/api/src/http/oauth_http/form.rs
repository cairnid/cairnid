use axum::http::{HeaderMap, StatusCode};
use cairn_oidc::{OAuthErrorBody, TokenRequest};

use super::super::{
    ApiError, OAUTH_FORM_BODY_MAX_BYTES, content_type::request_has_urlencoded_content_type,
    urlencoded::parse_url_encoded_pairs,
};
use super::BearerTokenError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct IntrospectionRequest {
    pub(in crate::http) token: String,
    pub(in crate::http) token_type_hint: Option<String>,
    pub(in crate::http) client_id: Option<String>,
    pub(in crate::http) client_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct RevocationRequest {
    pub(in crate::http) token: String,
    pub(in crate::http) token_type_hint: Option<String>,
    pub(in crate::http) client_id: Option<String>,
    pub(in crate::http) client_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct UserInfoRequest {
    pub(in crate::http) access_token: Option<String>,
}

pub(in crate::http) fn token_request_from_oauth_form(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<TokenRequest, ApiError> {
    let pairs = oauth_form_pairs(headers, body)?;
    reject_duplicate_oauth_form_parameters(&pairs)?;

    let mut request = TokenRequest {
        grant_type: String::new(),
        code: None,
        redirect_uri: None,
        client_id: None,
        client_secret: None,
        code_verifier: None,
        refresh_token: None,
        scope: None,
    };
    for (name, value) in pairs {
        match name.as_str() {
            "grant_type" => request.grant_type = value,
            "code" => request.code = Some(value),
            "redirect_uri" => request.redirect_uri = Some(value),
            "client_id" => request.client_id = Some(value),
            "client_secret" => request.client_secret = Some(value),
            "code_verifier" => request.code_verifier = Some(value),
            "refresh_token" => request.refresh_token = Some(value),
            "scope" => request.scope = Some(value),
            _ => {}
        }
    }
    Ok(request)
}

pub(in crate::http) fn introspection_request_from_oauth_form(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<IntrospectionRequest, ApiError> {
    let pairs = oauth_form_pairs(headers, body)?;
    reject_duplicate_oauth_form_parameters(&pairs)?;

    let mut request = IntrospectionRequest {
        token: String::new(),
        token_type_hint: None,
        client_id: None,
        client_secret: None,
    };
    for (name, value) in pairs {
        match name.as_str() {
            "token" => request.token = value,
            "token_type_hint" => request.token_type_hint = Some(value),
            "client_id" => request.client_id = Some(value),
            "client_secret" => request.client_secret = Some(value),
            _ => {}
        }
    }
    required_oauth_form_parameter(Some(&request.token), "token")?;
    Ok(request)
}

pub(in crate::http) fn revocation_request_from_oauth_form(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<RevocationRequest, ApiError> {
    let pairs = oauth_form_pairs(headers, body)?;
    reject_duplicate_oauth_form_parameters(&pairs)?;

    let mut request = RevocationRequest {
        token: String::new(),
        token_type_hint: None,
        client_id: None,
        client_secret: None,
    };
    for (name, value) in pairs {
        match name.as_str() {
            "token" => request.token = value,
            "token_type_hint" => request.token_type_hint = Some(value),
            "client_id" => request.client_id = Some(value),
            "client_secret" => request.client_secret = Some(value),
            _ => {}
        }
    }
    required_oauth_form_parameter(Some(&request.token), "token")?;
    Ok(request)
}

fn oauth_form_pairs(headers: &HeaderMap, body: &[u8]) -> Result<Vec<(String, String)>, ApiError> {
    require_oauth_form_content_type(headers)?;
    parse_oauth_form_body(body)
}

fn parse_oauth_form_body(body: &[u8]) -> Result<Vec<(String, String)>, ApiError> {
    if body.len() > OAUTH_FORM_BODY_MAX_BYTES {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_request("form body too large"),
        ));
    }
    let body = std::str::from_utf8(body).map_err(|_| invalid_oauth_form_request())?;
    parse_url_encoded_pairs(body).map_err(|_| invalid_oauth_form_request())
}

pub(in crate::http) fn userinfo_request_from_form_body(
    body: &[u8],
) -> Result<UserInfoRequest, BearerTokenError> {
    if body.len() > OAUTH_FORM_BODY_MAX_BYTES {
        return Err(BearerTokenError::InvalidRequest);
    }
    let body = std::str::from_utf8(body).map_err(|_| BearerTokenError::InvalidRequest)?;
    let pairs = parse_url_encoded_pairs(body).map_err(|_| BearerTokenError::InvalidRequest)?;
    if contains_duplicate_oauth_form_parameter(&pairs) {
        return Err(BearerTokenError::InvalidRequest);
    }
    let mut request = UserInfoRequest { access_token: None };
    for (name, value) in pairs {
        if name == "access_token" {
            request.access_token = Some(value);
        }
    }
    Ok(request)
}

fn reject_duplicate_oauth_form_parameters(pairs: &[(String, String)]) -> Result<(), ApiError> {
    if contains_duplicate_oauth_form_parameter(pairs) {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_request("duplicate form parameter"),
        ));
    }

    Ok(())
}

fn contains_duplicate_oauth_form_parameter(pairs: &[(String, String)]) -> bool {
    let mut seen: Vec<&str> = Vec::with_capacity(pairs.len());
    for (name, _) in pairs {
        if seen.iter().any(|existing| existing == name) {
            return true;
        }
        seen.push(name);
    }
    false
}

fn invalid_oauth_form_request() -> ApiError {
    ApiError::oauth(
        StatusCode::BAD_REQUEST,
        OAuthErrorBody::invalid_request("invalid form request"),
    )
}

pub(in crate::http) fn require_oauth_form_content_type(
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    if request_has_urlencoded_content_type(headers) {
        Ok(())
    } else {
        Err(invalid_oauth_form_content_type())
    }
}

fn invalid_oauth_form_content_type() -> ApiError {
    ApiError::oauth(
        StatusCode::BAD_REQUEST,
        OAuthErrorBody::invalid_request("content type must be application/x-www-form-urlencoded"),
    )
}

pub(in crate::http) fn required_oauth_form_parameter<'a>(
    value: Option<&'a str>,
    parameter: &'static str,
) -> Result<&'a str, ApiError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::oauth(
                StatusCode::BAD_REQUEST,
                OAuthErrorBody::invalid_request(format!("missing {parameter}")),
            )
        })
}
