use cairn_oidc::{AuthorizationRequest, OidcError};

use super::{
    AuthorizeUrlPromptMode, authorization_error_redirect, current_authorize_url,
    errors::authorization_error_parts,
};

#[test]
fn authorization_return_url_preserves_max_age_without_empty_optional_parameters() {
    let request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "public-client".to_owned(),
        redirect_uri: "http://localhost:3000/callback".to_owned(),
        scope: "openid profile".to_owned(),
        state: None,
        nonce: Some("nonce value".to_owned()),
        max_age: Some(300),
        response_mode: Some("query".to_owned()),
        prompt: Some("login consent".to_owned()),
        display: Some("popup".to_owned()),
        acr_values: Some("urn:cairn:acr:password+totp urn:cairn:acr:password".to_owned()),
        ui_locales: Some("en-GB fr".to_owned()),
        claims_locales: Some("en fr".to_owned()),
        login_hint: Some("user@example.com".to_owned()),
        claims: Some(r#"{"userinfo":{"name":{"essential":true}}}"#.to_owned()),
        request: None,
        request_uri: None,
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    let url = current_authorize_url(
        "http://localhost:8080/",
        &request,
        AuthorizeUrlPromptMode::Preserve,
    );

    assert_eq!(
        url,
        "http://localhost:8080/oauth2/authorize?response_type=code&client_id=public-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid%20profile&nonce=nonce%20value&display=popup&acr_values=urn%3Acairn%3Aacr%3Apassword%2Btotp%20urn%3Acairn%3Aacr%3Apassword&ui_locales=en-GB%20fr&claims_locales=en%20fr&max_age=300&response_mode=query&prompt=login%20consent&login_hint=user%40example.com&claims=%7B%22userinfo%22%3A%7B%22name%22%3A%7B%22essential%22%3Atrue%7D%7D%7D&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
    );
    assert!(!url.contains("state=&"));

    let after_prompt_login = current_authorize_url(
        "http://localhost:8080/",
        &request,
        AuthorizeUrlPromptMode::RemoveLogin,
    );
    assert!(!after_prompt_login.contains("prompt=login"));
    assert!(after_prompt_login.contains("prompt=consent"));
    assert!(after_prompt_login.contains("response_mode=query"));
    assert!(after_prompt_login.contains("login_hint=user%40example.com"));
    assert!(after_prompt_login.contains("claims=%7B%22userinfo%22%3A"));

    let after_prompt_consent = current_authorize_url(
        "http://localhost:8080/",
        &request,
        AuthorizeUrlPromptMode::RemoveConsent,
    );
    assert!(after_prompt_consent.contains("prompt=login"));
    assert!(!after_prompt_consent.contains("prompt=login%20consent"));
}

#[test]
fn authorization_error_redirect_uses_registered_redirect_uri_and_state() {
    let request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "public-client".to_owned(),
        redirect_uri: "http://localhost:3000/callback".to_owned(),
        scope: "openid admin".to_owned(),
        state: Some("state value".to_owned()),
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
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    let target =
        authorization_error_redirect(&request, "http://localhost:8080", OidcError::InvalidScope);

    assert_eq!(
        target,
        "http://localhost:3000/callback?error=invalid_scope&iss=http%3A%2F%2Flocalhost%3A8080&error_description=invalid%20scope&state=state%20value"
    );
}

#[test]
fn authorization_error_mapping_uses_oauth_authorization_error_codes() {
    assert_eq!(
        authorization_error_parts(OidcError::UnsupportedResponseType).0,
        "unsupported_response_type"
    );
    assert_eq!(
        authorization_error_parts(OidcError::MissingResponseType).0,
        "invalid_request"
    );
    assert_eq!(
        authorization_error_parts(OidcError::UnsupportedGrantType).0,
        "unauthorized_client"
    );
    assert_eq!(
        authorization_error_parts(OidcError::PkceRequired).0,
        "invalid_request"
    );
    assert_eq!(
        authorization_error_parts(OidcError::InvalidDisplay).0,
        "invalid_request"
    );
    assert_eq!(
        authorization_error_parts(OidcError::UnsupportedResponseMode).0,
        "invalid_request"
    );
    assert_eq!(
        authorization_error_parts(OidcError::InvalidPkceChallenge).0,
        "invalid_request"
    );
    assert_eq!(
        authorization_error_parts(OidcError::UnsupportedClaimsParameter).0,
        "invalid_request"
    );
    assert_eq!(
        authorization_error_parts(OidcError::UnsupportedRequestParameter).0,
        "request_not_supported"
    );
    assert_eq!(
        authorization_error_parts(OidcError::UnsupportedRequestUriParameter).0,
        "request_uri_not_supported"
    );
}
