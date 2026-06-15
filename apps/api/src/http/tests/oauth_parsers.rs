use super::super::admin_oidc::validate_allowed_client_scopes;
use super::super::api_response::ApiError;
use super::super::cookies::{CSRF_HEADER, require_csrf};
use super::super::oauth_http::{
    BearerTokenError, bearer_token, bearer_token_from_sources, oauth_client_auth_from_request,
    required_oauth_form_parameter, userinfo_request_from_form_body,
};
use super::TEST_CSRF_TOKEN;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

#[test]
fn csrf_requires_matching_cookie_and_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static(
            "other=value; cairn_csrf=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg",
        ),
    );
    headers.insert(
        HeaderName::from_static(CSRF_HEADER),
        HeaderValue::from_static(TEST_CSRF_TOKEN),
    );

    assert!(require_csrf(&headers).is_ok());
}

#[test]
fn csrf_rejects_missing_or_mismatched_tokens() {
    let empty = HeaderMap::new();
    assert!(require_csrf(&empty).is_err());

    let mut missing_header = HeaderMap::new();
    missing_header.insert(
        header::COOKIE,
        HeaderValue::from_static("cairn_csrf=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"),
    );
    assert!(require_csrf(&missing_header).is_err());

    let mut mismatch = missing_header;
    mismatch.insert(
        HeaderName::from_static(CSRF_HEADER),
        HeaderValue::from_static("other-token"),
    );
    assert!(require_csrf(&mismatch).is_err());
}

#[test]
fn csrf_rejects_empty_or_malformed_tokens() {
    let mut empty_values = HeaderMap::new();
    empty_values.insert(header::COOKIE, HeaderValue::from_static("cairn_csrf="));
    empty_values.insert(
        HeaderName::from_static(CSRF_HEADER),
        HeaderValue::from_static(""),
    );
    assert!(require_csrf(&empty_values).is_err());

    let mut malformed_header = HeaderMap::new();
    malformed_header.insert(
        header::COOKIE,
        HeaderValue::from_static("cairn_csrf=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg"),
    );
    malformed_header.insert(
        HeaderName::from_static(CSRF_HEADER),
        HeaderValue::from_static("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef="),
    );
    assert!(require_csrf(&malformed_header).is_err());

    let mut malformed_cookie = HeaderMap::new();
    malformed_cookie.insert(
        header::COOKIE,
        HeaderValue::from_static("cairn_csrf=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef="),
    );
    malformed_cookie.insert(
        HeaderName::from_static(CSRF_HEADER),
        HeaderValue::from_static(TEST_CSRF_TOKEN),
    );
    assert!(require_csrf(&malformed_cookie).is_err());
}

#[test]
fn basic_client_auth_decodes_form_encoded_credentials() {
    let raw_credentials = BASE64_STANDARD.encode("client%2Fid:secret+value%21");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {raw_credentials}")).unwrap(),
    );

    let auth = oauth_client_auth_from_request(&headers, None, None).unwrap();

    assert_eq!(auth.client_id.as_deref(), Some("client/id"));
    assert_eq!(auth.client_secret.as_deref(), Some("secret value!"));
}

#[test]
fn basic_client_auth_rejects_multiple_authorization_headers() {
    let raw_credentials = BASE64_STANDARD.encode("client:secret");
    let mut headers = HeaderMap::new();
    headers.append(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {raw_credentials}")).unwrap(),
    );
    headers.append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Basic other-secret"),
    );

    let error = oauth_client_auth_from_request(&headers, None, None)
        .expect_err("duplicate Authorization headers should fail");
    assert!(matches!(
        error,
        ApiError::OAuth {
            status: StatusCode::BAD_REQUEST,
            ref body,
        } if body.error == "invalid_request"
            && body.error_description.as_deref() == Some("invalid Authorization header")
    ));
}

#[test]
fn bearer_token_parser_accepts_case_insensitive_scheme_and_whitespace() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("bearer    abc.DEF_123-~+/="),
    );

    assert_eq!(bearer_token(&headers), Ok("abc.DEF_123-~+/="));
}

#[test]
fn bearer_token_source_resolver_accepts_post_body_tokens() {
    let headers = HeaderMap::new();

    assert_eq!(
        bearer_token_from_sources(&headers, Some("form.token-123".to_owned()), None)
            .expect("form token")
            .as_ref(),
        "form.token-123"
    );
}

#[test]
fn bearer_token_source_resolver_rejects_multiple_or_invalid_methods() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer header-token"),
    );

    assert_eq!(
        bearer_token_from_sources(&headers, Some("form-token".to_owned()), None),
        Err(BearerTokenError::MultipleMethods)
    );

    let empty_headers = HeaderMap::new();
    assert_eq!(
        bearer_token_from_sources(&empty_headers, Some("bad,token".to_owned()), None),
        Err(BearerTokenError::InvalidRequest)
    );
    assert_eq!(
        bearer_token_from_sources(&empty_headers, None, Some("access_token=query-token")),
        Err(BearerTokenError::InvalidRequest)
    );
    assert_eq!(
        bearer_token_from_sources(&empty_headers, None, Some("other=value")),
        Err(BearerTokenError::Missing)
    );
    assert_eq!(
        bearer_token_from_sources(&empty_headers, None, Some("other=%")),
        Err(BearerTokenError::InvalidRequest)
    );
    assert_eq!(
        bearer_token_from_sources(&empty_headers, None, Some("other=%C3%28")),
        Err(BearerTokenError::InvalidRequest)
    );
    assert_eq!(
        bearer_token_from_sources(
            &empty_headers,
            None,
            Some("other=value&access_token=query-token"),
        ),
        Err(BearerTokenError::InvalidRequest)
    );
}

#[test]
fn userinfo_form_parser_rejects_duplicate_parameters() {
    assert_eq!(
        userinfo_request_from_form_body(b"access_token=one&access_token=two"),
        Err(BearerTokenError::InvalidRequest)
    );
    assert_eq!(
        userinfo_request_from_form_body(b"ignored=one&ignored=two"),
        Err(BearerTokenError::InvalidRequest)
    );
}

#[test]
fn bearer_token_parser_rejects_malformed_headers() {
    let empty = HeaderMap::new();
    assert_eq!(bearer_token(&empty), Err(BearerTokenError::Missing));

    let mut wrong_scheme = HeaderMap::new();
    wrong_scheme.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));
    assert_eq!(
        bearer_token(&wrong_scheme),
        Err(BearerTokenError::UnsupportedScheme)
    );

    let mut missing_token = HeaderMap::new();
    missing_token.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer"));
    assert_eq!(
        bearer_token(&missing_token),
        Err(BearerTokenError::InvalidRequest)
    );

    let mut extra_parts = HeaderMap::new();
    extra_parts.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer token extra"),
    );
    assert_eq!(
        bearer_token(&extra_parts),
        Err(BearerTokenError::InvalidRequest)
    );

    let mut invalid_token = HeaderMap::new();
    invalid_token.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer token,"),
    );
    assert_eq!(
        bearer_token(&invalid_token),
        Err(BearerTokenError::InvalidRequest)
    );

    let mut duplicate_headers = HeaderMap::new();
    duplicate_headers.append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer first-token"),
    );
    duplicate_headers.append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer second-token"),
    );
    assert_eq!(
        bearer_token(&duplicate_headers),
        Err(BearerTokenError::InvalidRequest)
    );
}

#[test]
fn client_auth_rejects_mixed_basic_and_form_credentials() {
    let raw_credentials = BASE64_STANDARD.encode("client:secret");
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {raw_credentials}")).unwrap(),
    );

    assert!(oauth_client_auth_from_request(&headers, Some("client"), Some("secret")).is_err());
}

#[test]
fn oauth_required_form_parameters_reject_blank_values() {
    for missing in [None, Some(""), Some("   ")] {
        let error =
            required_oauth_form_parameter(missing, "code").expect_err("missing code should fail");
        assert!(matches!(
            error,
            ApiError::OAuth {
                status: StatusCode::BAD_REQUEST,
                ref body,
            } if body.error == "invalid_request"
                && body.error_description.as_deref() == Some("missing code")
        ));
    }

    assert_eq!(
        required_oauth_form_parameter(Some("abc"), "code").expect("code"),
        "abc"
    );
}

#[test]
fn allowed_client_scopes_are_valid_unique_and_include_openid() {
    assert_eq!(
        validate_allowed_client_scopes(vec![
            "profile".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ])
        .expect("valid client scopes"),
        vec!["profile", "email", "openid"]
    );

    for scopes in [
        vec!["".to_owned()],
        vec!["bad\"scope".to_owned()],
        vec!["bad\\scope".to_owned()],
        vec!["caf\u{e9}".to_owned()],
    ] {
        assert!(matches!(
            validate_allowed_client_scopes(scopes),
            Err(ApiError::Status {
                status: StatusCode::BAD_REQUEST,
                ..
            })
        ));
    }
}
