use cairn_oidc::{AuthorizationRequest, OidcError};

use super::super::{ApiError, OAUTH_QUERY_MAX_BYTES, urlencoded::parse_url_encoded_pairs};

pub(in crate::http) fn authorization_query_pairs(
    raw_query: Option<&str>,
) -> Result<Vec<(String, String)>, ApiError> {
    let query = raw_query.unwrap_or_default();
    if query.len() > OAUTH_QUERY_MAX_BYTES {
        return Err(ApiError::bad_request("authorization request too large"));
    }
    parse_url_encoded_pairs(query)
        .map_err(|_| ApiError::bad_request("invalid authorization request"))
}

pub(in crate::http) fn duplicate_authorization_request_parameter(
    pairs: &[(String, String)],
) -> Option<&'static str> {
    let mut seen = Vec::new();
    for (name, _) in pairs {
        let Some(parameter) = authorization_request_parameter_name(name) else {
            continue;
        };
        if seen.iter().any(|existing| existing == &parameter) {
            return Some(parameter);
        }
        seen.push(parameter);
    }
    None
}

pub(in crate::http) fn authorization_request_from_query_pairs(
    pairs: &[(String, String)],
) -> (AuthorizationRequest, Option<OidcError>) {
    let mut request = AuthorizationRequest {
        response_type: String::new(),
        client_id: String::new(),
        redirect_uri: String::new(),
        scope: String::new(),
        state: None,
        nonce: None,
        max_age: None,
        response_mode: None,
        prompt: None,
        display: None,
        acr_values: None,
        ui_locales: None,
        claims_locales: None,
        login_hint: None,
        claims: None,
        request: None,
        request_uri: None,
        code_challenge: None,
        code_challenge_method: None,
    };
    let mut parse_error = None;

    for (name, value) in pairs {
        match name.as_str() {
            "response_type" => request.response_type = value.clone(),
            "client_id" => request.client_id = value.clone(),
            "redirect_uri" => request.redirect_uri = value.clone(),
            "scope" => request.scope = value.clone(),
            "state" => request.state = Some(value.clone()),
            "nonce" => request.nonce = Some(value.clone()),
            "max_age" => match value.parse() {
                Ok(max_age) => request.max_age = Some(max_age),
                Err(_) => {
                    parse_error.get_or_insert(OidcError::InvalidMaxAge);
                }
            },
            "response_mode" => request.response_mode = Some(value.clone()),
            "prompt" => request.prompt = Some(value.clone()),
            "display" => request.display = Some(value.clone()),
            "acr_values" => request.acr_values = Some(value.clone()),
            "ui_locales" => request.ui_locales = Some(value.clone()),
            "claims_locales" => request.claims_locales = Some(value.clone()),
            "login_hint" => request.login_hint = Some(value.clone()),
            "claims" => request.claims = Some(value.clone()),
            "request" => request.request = Some(value.clone()),
            "request_uri" => request.request_uri = Some(value.clone()),
            "code_challenge" => request.code_challenge = Some(value.clone()),
            "code_challenge_method" => request.code_challenge_method = Some(value.clone()),
            _ => {}
        }
    }

    (request, parse_error)
}

fn authorization_request_parameter_name(name: &str) -> Option<&'static str> {
    match name {
        "response_type" => Some("response_type"),
        "client_id" => Some("client_id"),
        "redirect_uri" => Some("redirect_uri"),
        "scope" => Some("scope"),
        "state" => Some("state"),
        "nonce" => Some("nonce"),
        "max_age" => Some("max_age"),
        "response_mode" => Some("response_mode"),
        "prompt" => Some("prompt"),
        "display" => Some("display"),
        "acr_values" => Some("acr_values"),
        "ui_locales" => Some("ui_locales"),
        "claims_locales" => Some("claims_locales"),
        "login_hint" => Some("login_hint"),
        "claims" => Some("claims"),
        "request" => Some("request"),
        "request_uri" => Some("request_uri"),
        "code_challenge" => Some("code_challenge"),
        "code_challenge_method" => Some("code_challenge_method"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::*;

    #[test]
    fn authorization_request_duplicate_parameter_detection_handles_known_parameters() {
        let empty = authorization_query_pairs(None).expect("empty query parses");
        assert_eq!(duplicate_authorization_request_parameter(&empty), None);

        let duplicated_scope =
            authorization_query_pairs(Some("scope=openid&scope=email")).expect("query parses");
        assert_eq!(
            duplicate_authorization_request_parameter(&duplicated_scope),
            Some("scope")
        );
        let duplicated_encoded_client =
            authorization_query_pairs(Some("client%5Fid=public-client&client_id=other-client"))
                .expect("query parses");
        assert_eq!(
            duplicate_authorization_request_parameter(&duplicated_encoded_client),
            Some("client_id")
        );
        let duplicated_request_uri =
            authorization_query_pairs(Some("request_uri=a&request_uri=b")).expect("query parses");
        assert_eq!(
            duplicate_authorization_request_parameter(&duplicated_request_uri),
            Some("request_uri")
        );
        let extension_params =
            authorization_query_pairs(Some("extension=one&extension=two&scope=openid"))
                .expect("query parses");
        assert_eq!(
            duplicate_authorization_request_parameter(&extension_params),
            None
        );
    }

    #[test]
    fn authorization_query_parser_decodes_expected_fields() {
        let pairs = authorization_query_pairs(Some(
            "response_type=code&client_id=public-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid+profile&state=a%2Bb&max_age=300&code_challenge=challenge&code_challenge_method=S256",
        ))
        .expect("query parses");
        let (request, parse_error) = authorization_request_from_query_pairs(&pairs);

        assert!(parse_error.is_none());
        assert_eq!(request.response_type, "code");
        assert_eq!(request.client_id, "public-client");
        assert_eq!(request.redirect_uri, "http://localhost:3000/callback");
        assert_eq!(request.scope, "openid profile");
        assert_eq!(request.state.as_deref(), Some("a+b"));
        assert_eq!(request.max_age, Some(300));
        assert_eq!(request.code_challenge.as_deref(), Some("challenge"));
        assert_eq!(request.code_challenge_method.as_deref(), Some("S256"));

        let pairs = authorization_query_pairs(Some("max_age=soon")).expect("query parses");
        let (request, parse_error) = authorization_request_from_query_pairs(&pairs);
        assert_eq!(request.max_age, None);
        assert!(matches!(parse_error, Some(OidcError::InvalidMaxAge)));
    }

    #[test]
    fn authorization_query_parser_rejects_malformed_encoding() {
        assert!(authorization_query_pairs(Some("state=%")).is_err());
        assert!(authorization_query_pairs(Some("state=%GG")).is_err());
        assert!(authorization_query_pairs(Some("state=%C3%28")).is_err());
    }

    #[test]
    fn authorization_query_parser_rejects_oversized_queries() {
        let query = "a".repeat(OAUTH_QUERY_MAX_BYTES + 1);
        let error = authorization_query_pairs(Some(&query)).expect_err("oversized query fails");
        assert!(matches!(
            error,
            ApiError::Status {
                status: StatusCode::BAD_REQUEST,
                ref message,
                ..
            } if message == "authorization request too large"
        ));
    }
}
