use axum::{extract::Request, http::HeaderMap};
use cairn_oidc::EndSessionRequest;

use super::{
    ApiError, OAUTH_FORM_BODY_MAX_BYTES, OAUTH_QUERY_MAX_BYTES, bounded_request_body,
    content_type::request_has_urlencoded_content_type, urlencoded::parse_url_encoded_pairs,
};

pub(super) fn end_session_request_from_query(
    raw_query: Option<&str>,
) -> Result<EndSessionRequest, ApiError> {
    let query = raw_query.unwrap_or_default();
    if query.len() > OAUTH_QUERY_MAX_BYTES {
        return Err(ApiError::bad_request("logout request too large"));
    }
    let pairs = parse_url_encoded_pairs(query)
        .map_err(|_| ApiError::bad_request("invalid logout request"))?;
    end_session_request_from_pairs(&pairs)
}

pub(super) async fn end_session_request_from_form(
    headers: &HeaderMap,
    request: Request,
) -> Result<EndSessionRequest, ApiError> {
    require_logout_form_content_type(headers)?;
    let body = bounded_request_body(request, OAUTH_FORM_BODY_MAX_BYTES)
        .await
        .map_err(|_| ApiError::bad_request("logout request too large"))?;
    let body =
        std::str::from_utf8(&body).map_err(|_| ApiError::bad_request("invalid logout request"))?;
    let pairs = parse_url_encoded_pairs(body)
        .map_err(|_| ApiError::bad_request("invalid logout request"))?;
    end_session_request_from_pairs(&pairs)
}

fn end_session_request_from_pairs(
    pairs: &[(String, String)],
) -> Result<EndSessionRequest, ApiError> {
    if duplicate_end_session_request_parameter(pairs).is_some() {
        return Err(ApiError::bad_request("duplicate logout request parameter"));
    }

    let mut request = EndSessionRequest {
        id_token_hint: None,
        logout_hint: None,
        client_id: None,
        post_logout_redirect_uri: None,
        state: None,
        ui_locales: None,
    };
    for (name, value) in pairs {
        match name.as_str() {
            "id_token_hint" => request.id_token_hint = Some(value.clone()),
            "logout_hint" => request.logout_hint = Some(value.clone()),
            "client_id" => request.client_id = Some(value.clone()),
            "post_logout_redirect_uri" => request.post_logout_redirect_uri = Some(value.clone()),
            "state" => request.state = Some(value.clone()),
            "ui_locales" => request.ui_locales = Some(value.clone()),
            _ => {}
        }
    }

    Ok(request)
}

fn duplicate_end_session_request_parameter(pairs: &[(String, String)]) -> Option<&'static str> {
    let mut seen = Vec::new();
    for (name, _) in pairs {
        let Some(parameter) = end_session_request_parameter_name(name) else {
            continue;
        };
        if seen.iter().any(|existing| existing == &parameter) {
            return Some(parameter);
        }
        seen.push(parameter);
    }
    None
}

fn end_session_request_parameter_name(name: &str) -> Option<&'static str> {
    match name {
        "id_token_hint" => Some("id_token_hint"),
        "logout_hint" => Some("logout_hint"),
        "client_id" => Some("client_id"),
        "post_logout_redirect_uri" => Some("post_logout_redirect_uri"),
        "state" => Some("state"),
        "ui_locales" => Some("ui_locales"),
        _ => None,
    }
}

fn require_logout_form_content_type(headers: &HeaderMap) -> Result<(), ApiError> {
    if request_has_urlencoded_content_type(headers) {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "content type must be application/x-www-form-urlencoded",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    #[test]
    fn end_session_query_parser_decodes_registered_parameters() {
        let request = end_session_request_from_query(Some(
            "id_token_hint=id-token&logout_hint=user%40example.com&client_id=client&post_logout_redirect_uri=https%3A%2F%2Fclient.example%2Fbye&state=a%2Bb&ui_locales=en+fr&ignored=extension",
        ))
        .expect("logout request");

        assert_eq!(request.id_token_hint.as_deref(), Some("id-token"));
        assert_eq!(request.logout_hint.as_deref(), Some("user@example.com"));
        assert_eq!(request.client_id.as_deref(), Some("client"));
        assert_eq!(
            request.post_logout_redirect_uri.as_deref(),
            Some("https://client.example/bye")
        );
        assert_eq!(request.state.as_deref(), Some("a+b"));
        assert_eq!(request.ui_locales.as_deref(), Some("en fr"));
    }

    #[test]
    fn end_session_query_parser_rejects_duplicates_and_malformed_encoding() {
        assert!(matches!(
            end_session_request_from_query(Some("id_token_hint=one&id_token_hint=two")),
            Err(ApiError::Status { ref message, .. }) if message == "duplicate logout request parameter"
        ));
        assert!(matches!(
            end_session_request_from_query(Some("id_token_hint=%")),
            Err(ApiError::Status { ref message, .. }) if message == "invalid logout request"
        ));
    }

    #[test]
    fn logout_form_content_type_accepts_parameters_and_rejects_missing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );
        assert!(require_logout_form_content_type(&headers).is_ok());

        let error = require_logout_form_content_type(&HeaderMap::new())
            .expect_err("missing form content type should fail");
        assert!(matches!(
            error,
            ApiError::Status { ref message, .. }
                if message == "content type must be application/x-www-form-urlencoded"
        ));
    }
}
