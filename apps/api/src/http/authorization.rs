use axum::http::StatusCode;
use cairn_domain::OidcClient;
use url::Url;

use super::ApiError;

mod redirect;
mod request;

pub(super) use self::redirect::{
    AuthorizeUrlPromptMode, authorization_error_redirect, authorization_error_redirect_with_code,
    authorization_request_hash, current_authorize_url,
};
pub(super) use self::request::{
    authorization_query_pairs, authorization_request_from_query_pairs,
    duplicate_authorization_request_parameter,
};

pub(super) fn validate_consent_return_to(
    issuer: &str,
    return_to: &str,
    client: &OidcClient,
    scopes: &[String],
) -> Result<String, ApiError> {
    let parsed_return_to =
        Url::parse(return_to).map_err(|_| ApiError::bad_request("invalid consent return_to"))?;
    let issuer_url = Url::parse(issuer)
        .map_err(|_| ApiError::status(StatusCode::INTERNAL_SERVER_ERROR, "invalid issuer"))?;

    if parsed_return_to.origin().ascii_serialization() != issuer_url.origin().ascii_serialization()
        || parsed_return_to.path() != "/oauth2/authorize"
        || !parsed_return_to.username().is_empty()
        || parsed_return_to.password().is_some()
        || parsed_return_to.fragment().is_some()
    {
        return Err(ApiError::bad_request("invalid consent return_to"));
    }

    let query_pairs = authorization_query_pairs(parsed_return_to.query())?;
    if duplicate_authorization_request_parameter(&query_pairs).is_some() {
        return Err(ApiError::bad_request("invalid consent return_to"));
    }
    let (request, parse_error) = authorization_request_from_query_pairs(&query_pairs);
    if parse_error.is_some() {
        return Err(ApiError::bad_request("invalid consent return_to"));
    }
    let validated = request
        .clone()
        .validate(client)
        .map_err(|_| ApiError::bad_request("invalid consent return_to"))?;
    if validated.prompt.is_none() || validated.prompt.requires_consent() {
        return Err(ApiError::bad_request("invalid consent return_to"));
    }
    if !same_scope_set(&validated.scopes, scopes) {
        return Err(ApiError::bad_request("invalid consent scope"));
    }

    Ok(authorization_request_hash(issuer, &request))
}

fn same_scope_set(left: &[String], right: &[String]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|scope| right.iter().any(|candidate| candidate == scope))
}
