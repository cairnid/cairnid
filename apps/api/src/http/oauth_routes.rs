use axum::{
    body::Bytes,
    extract::Request,
    http::{HeaderMap, StatusCode},
};
use cairn_oidc::OAuthErrorBody;

use super::{
    OAUTH_FORM_BODY_MAX_BYTES, api_response::ApiError, oauth_http::require_oauth_form_content_type,
    request_body::bounded_request_body,
};

mod token_exchange;
mod token_status;
mod userinfo;

pub(super) use self::token_exchange::token;
pub(super) use self::token_status::{introspect, revoke};
pub(super) use self::userinfo::userinfo_route;

async fn oauth_form_body_from_request(
    headers: &HeaderMap,
    request: Request,
) -> Result<Bytes, ApiError> {
    require_oauth_form_content_type(headers)?;
    bounded_request_body(request, OAUTH_FORM_BODY_MAX_BYTES)
        .await
        .map_err(|_| {
            ApiError::oauth(
                StatusCode::BAD_REQUEST,
                OAuthErrorBody::invalid_request("form body too large"),
            )
        })
}
