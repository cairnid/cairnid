use super::*;
use crate::oauth_types::is_oauth_error_text_character;
use crate::signing::rsa_public_jwk;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cairn_domain::SigningKeyMaterial;
use cairn_domain::{OidcClient, OidcClientStatus, OidcGrantType, RedirectUri, User};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use openssl::{pkey::PKey, rsa::Rsa};
use serde_json::json;
use time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

const TEST_CODE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn client() -> OidcClient {
    OidcClient {
        id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        client_id: "web".to_owned(),
        client_secret_hash: None,
        consent_policy_template_id: None,
        name: "Web".to_owned(),
        redirect_uris: vec![RedirectUri::parse("https://app.example.com/callback").unwrap()],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_owned(), "profile".to_owned()],
        grant_types: vec![
            OidcGrantType::AuthorizationCode,
            OidcGrantType::RefreshToken,
        ],
        public_client: true,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: OffsetDateTime::now_utc(),
    }
}

fn signing_material() -> SigningMaterial {
    let private_key = Rsa::generate(2048).unwrap();
    let key_pair = PKey::from_rsa(private_key).unwrap();
    let private_key_pem = String::from_utf8(key_pair.private_key_to_pem_pkcs8().unwrap())
        .expect("test key PEM is valid UTF-8");
    SigningMaterial {
        key_id: "rs256-test".to_owned(),
        public_jwk: rsa_public_jwk("rs256-test", &private_key_pem).unwrap(),
        private_key_pem,
    }
}

#[test]
fn rejects_implicit_flow() {
    let request = AuthorizationRequest {
        response_type: "token".to_owned(),
        client_id: "web".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scope: "openid".to_owned(),
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
        code_challenge: Some(TEST_CODE_CHALLENGE.to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    assert!(matches!(
        request.validate(&client()),
        Err(OidcError::UnsupportedResponseType)
    ));
}

#[test]
fn rejects_missing_response_type_as_invalid_request() {
    let request = AuthorizationRequest {
        response_type: String::new(),
        client_id: "web".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scope: "openid".to_owned(),
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
        code_challenge: Some(TEST_CODE_CHALLENGE.to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    assert!(matches!(
        request.validate(&client()),
        Err(OidcError::MissingResponseType)
    ));
}

#[test]
fn validates_exact_redirect_and_pkce() {
    let request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "web".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scope: "openid profile".to_owned(),
        state: Some("state".to_owned()),
        nonce: Some("nonce".to_owned()),
        max_age: Some(300),
        response_mode: Some("query".to_owned()),
        prompt: Some("none".to_owned()),
        display: Some("popup".to_owned()),
        acr_values: Some(
            "urn:cairn:acr:password+totp urn:cairn:acr:password+totp urn:cairn:acr:password"
                .to_owned(),
        ),
        ui_locales: Some("en-GB fr en-GB".to_owned()),
        claims_locales: Some("en fr en".to_owned()),
        login_hint: Some("user@example.com".to_owned()),
        claims: None,
        request: None,
        request_uri: None,
        code_challenge: Some(TEST_CODE_CHALLENGE.to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    let validated = request.validate(&client()).unwrap();
    assert_eq!(validated.scopes, vec!["openid", "profile"]);
    assert_eq!(validated.max_age, Some(300));
    assert_eq!(validated.response_mode, AuthorizationResponseMode::Query);
    assert_eq!(validated.prompt, AuthorizationPrompt::None);
    assert_eq!(validated.display, AuthorizationDisplay::Popup);
    assert_eq!(
        validated.acr_values,
        vec!["urn:cairn:acr:password+totp", "urn:cairn:acr:password"]
    );
    assert_eq!(validated.ui_locales, vec!["en-GB", "fr"]);
    assert_eq!(validated.claims_locales, vec!["en", "fr"]);
    assert_eq!(validated.login_hint.as_deref(), Some("user@example.com"));
}

#[test]
fn validates_scope_tokens_against_oauth_syntax() {
    assert_eq!(
        parse_scopes("openid profile openid").expect("valid scopes"),
        vec!["openid", "profile"]
    );
    assert_eq!(
        parse_scopes("read:users write.users").expect("valid punctuation scopes"),
        vec!["read:users", "write.users"]
    );

    for scope in [
        "",
        "openid  profile",
        " openid",
        "openid ",
        "openid\tprofile",
        "bad\"scope",
        "bad\\scope",
        "caf\u{e9}",
    ] {
        assert!(matches!(parse_scopes(scope), Err(OidcError::InvalidScope)));
    }
}

#[test]
fn rejects_negative_max_age() {
    let request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "web".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scope: "openid".to_owned(),
        state: None,
        nonce: None,
        max_age: Some(-1),
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
        code_challenge: Some(TEST_CODE_CHALLENGE.to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    assert!(matches!(
        request.validate(&client()),
        Err(OidcError::InvalidMaxAge)
    ));
}

#[test]
fn rejects_unsupported_response_mode() {
    let request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "web".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scope: "openid".to_owned(),
        state: None,
        nonce: None,
        max_age: None,
        response_mode: Some("fragment".to_owned()),
        prompt: None,
        display: None,
        acr_values: None,
        ui_locales: None,
        claims_locales: None,
        login_hint: None,
        claims: None,
        request: None,
        request_uri: None,
        code_challenge: Some(TEST_CODE_CHALLENGE.to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    assert!(matches!(
        request.validate(&client()),
        Err(OidcError::UnsupportedResponseMode)
    ));
}

#[test]
fn rejects_invalid_pkce_code_challenge_syntax() {
    let request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "web".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scope: "openid".to_owned(),
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
        code_challenge: Some("too-short".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    assert!(matches!(
        request.validate(&client()),
        Err(OidcError::InvalidPkceChallenge)
    ));
}

#[test]
fn rejects_unsupported_request_object_parameters() {
    let request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "web".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scope: "openid".to_owned(),
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
        claims: Some(r#"{"id_token":{"email":null}}"#.to_owned()),
        request: None,
        request_uri: None,
        code_challenge: Some(TEST_CODE_CHALLENGE.to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    assert!(matches!(
        request.clone().validate(&client()),
        Err(OidcError::UnsupportedClaimsParameter)
    ));

    let mut request_object = request.clone();
    request_object.claims = None;
    request_object.request = Some("eyJhbGciOiJSUzI1NiJ9".to_owned());
    assert!(matches!(
        request_object.validate(&client()),
        Err(OidcError::UnsupportedRequestParameter)
    ));

    let mut request_uri = request;
    request_uri.claims = None;
    request_uri.request_uri = Some("https://client.example.com/request.jwt".to_owned());
    assert!(matches!(
        request_uri.validate(&client()),
        Err(OidcError::UnsupportedRequestUriParameter)
    ));
}

#[test]
fn rejects_offline_access_without_refresh_token_grant() {
    let request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "web".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scope: "openid offline_access".to_owned(),
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
        code_challenge: Some(TEST_CODE_CHALLENGE.to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };
    let mut client = client();
    client.grant_types = vec![OidcGrantType::AuthorizationCode];
    client.allowed_scopes.push("offline_access".to_owned());

    assert!(matches!(
        request.validate(&client),
        Err(OidcError::InvalidScope)
    ));
}

#[test]
fn validates_prompt_consent_combinations() {
    let request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "web".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scope: "openid".to_owned(),
        state: None,
        nonce: None,
        max_age: None,
        response_mode: None,
        prompt: Some("login consent".to_owned()),
        display: None,
        acr_values: None,
        ui_locales: None,
        claims_locales: None,
        login_hint: None,
        claims: None,
        request: None,
        request_uri: None,
        code_challenge: Some(TEST_CODE_CHALLENGE.to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    let validated = request.validate(&client()).unwrap();
    assert_eq!(validated.prompt, AuthorizationPrompt::LoginConsent);
    assert!(validated.prompt.requires_login());
    assert!(validated.prompt.requires_consent());
}

#[test]
fn rejects_invalid_display_values() {
    let request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "web".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scope: "openid".to_owned(),
        state: None,
        nonce: None,
        max_age: None,
        response_mode: None,
        prompt: None,
        display: Some("modal".to_owned()),
        acr_values: None,
        ui_locales: None,
        claims_locales: None,
        login_hint: None,
        claims: None,
        request: None,
        request_uri: None,
        code_challenge: Some(TEST_CODE_CHALLENGE.to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    assert!(matches!(
        request.validate(&client()),
        Err(OidcError::InvalidDisplay)
    ));
}

#[test]
fn rejects_invalid_prompt_values() {
    let request = AuthorizationRequest {
        response_type: "code".to_owned(),
        client_id: "web".to_owned(),
        redirect_uri: "https://app.example.com/callback".to_owned(),
        scope: "openid".to_owned(),
        state: None,
        nonce: None,
        max_age: None,
        response_mode: None,
        prompt: Some("none login".to_owned()),
        display: None,
        acr_values: None,
        ui_locales: None,
        claims_locales: None,
        login_hint: None,
        claims: None,
        request: None,
        request_uri: None,
        code_challenge: Some(TEST_CODE_CHALLENGE.to_owned()),
        code_challenge_method: Some("S256".to_owned()),
    };

    assert!(matches!(
        request.clone().validate(&client()),
        Err(OidcError::InvalidPrompt)
    ));

    let mut unsupported = request;
    unsupported.prompt = Some("select_account".to_owned());
    assert!(matches!(
        unsupported.clone().validate(&client()),
        Err(OidcError::InvalidPrompt)
    ));

    unsupported.prompt = Some("login login".to_owned());
    assert!(matches!(
        unsupported.validate(&client()),
        Err(OidcError::InvalidPrompt)
    ));
}

#[test]
fn provider_metadata_advertises_strict_code_flow_and_issuer_responses() {
    let metadata = ProviderMetadata::new("https://id.example.com/");

    assert_eq!(metadata.issuer, "https://id.example.com");
    assert_eq!(
        metadata.end_session_endpoint,
        "https://id.example.com/oauth2/logout"
    );
    assert_eq!(metadata.response_types_supported, vec!["code"]);
    assert_eq!(metadata.response_modes_supported, vec!["query"]);
    assert_eq!(metadata.code_challenge_methods_supported, vec!["S256"]);
    assert!(
        metadata
            .claims_supported
            .iter()
            .any(|claim| claim == "auth_time")
    );
    assert_eq!(
        metadata.prompt_values_supported,
        vec!["none", "login", "consent"]
    );
    assert_eq!(
        metadata.display_values_supported,
        vec!["page", "popup", "touch", "wap"]
    );
    assert!(metadata.authorization_response_iss_parameter_supported);
    assert!(!metadata.request_parameter_supported);
    assert!(!metadata.request_uri_parameter_supported);
}

#[test]
fn authorization_response_preserves_existing_query() {
    let target = append_authorization_response_params(
        "https://app.example.com/callback?x=1",
        "code",
        Some("state value"),
        "https://id.example.com",
    );

    assert_eq!(
        target,
        "https://app.example.com/callback?x=1&code=code&iss=https%3A%2F%2Fid.example.com&state=state%20value"
    );
}

#[test]
fn authorization_error_response_preserves_state_and_issuer() {
    let target = append_authorization_error_response_params(
        "https://app.example.com/callback?x=1",
        "invalid_scope",
        Some("invalid scope"),
        Some("state value"),
        "https://id.example.com",
    );

    assert_eq!(
        target,
        "https://app.example.com/callback?x=1&error=invalid_scope&iss=https%3A%2F%2Fid.example.com&error_description=invalid%20scope&state=state%20value"
    );
}

#[test]
fn oauth_error_descriptions_are_rfc6749_visible_ascii() {
    let error = OAuthErrorBody::invalid_request("bad\n\"quoted\" café \\ value");

    let description = error.error_description.expect("description");
    assert_eq!(description, "bad  quoted  caf    value");
    assert!(description.chars().all(is_oauth_error_text_character));
}

#[test]
fn authorization_error_response_sanitizes_description_before_encoding() {
    let target = append_authorization_error_response_params(
        "https://app.example.com/callback",
        "invalid_request",
        Some("bad\n\"quoted\" café \\ value"),
        None,
        "https://id.example.com",
    );

    assert!(target.contains("error_description=bad%20%20quoted%20%20caf%20%20%20%20value"));
    assert!(!target.contains("%0A"));
    assert!(!target.contains("%22"));
    assert!(!target.contains("%5C"));
    assert!(!target.contains("%C3"));
}

#[test]
fn post_logout_redirect_preserves_existing_query_and_state() {
    let target = append_post_logout_redirect_params(
        "https://app.example.com/logout?from=rp",
        Some("state value"),
    );

    assert_eq!(
        target,
        "https://app.example.com/logout?from=rp&state=state%20value"
    );
    assert_eq!(
        append_post_logout_redirect_params("https://app.example.com/logout", None),
        "https://app.example.com/logout"
    );
}

#[test]
fn logout_id_token_hint_validates_signature_issuer_audience_and_kid() {
    let client = client();
    let signing = signing_material();
    let user = User::new(Uuid::new_v4(), "user@example.com", "User Example").unwrap();
    let scopes = vec![
        "openid".to_owned(),
        "profile".to_owned(),
        "email".to_owned(),
    ];
    let token = issue_id_token(IdTokenIssueRequest {
        issuer: "https://id.example.com/",
        client: &client,
        user: &user,
        scopes: &scopes,
        nonce: Some("nonce".to_owned()),
        auth_time: Some(OffsetDateTime::now_utc()),
        amr: vec!["pwd".to_owned()],
        acr: "urn:cairn:acr:password".to_owned(),
        groups: None,
        signing: &signing,
    })
    .unwrap();

    let claims =
        validate_logout_id_token_hint(&token, "https://id.example.com/", &client, &signing)
            .unwrap();
    assert_eq!(claims.iss, "https://id.example.com");
    assert_eq!(claims.aud, "web");
    assert_eq!(claims.sub, user.id.to_string());

    let mut wrong_client = client.clone();
    wrong_client.client_id = "other-client".to_owned();
    assert!(matches!(
        validate_logout_id_token_hint(&token, "https://id.example.com/", &wrong_client, &signing),
        Err(OidcError::InvalidIdTokenHint)
    ));
    assert!(matches!(
        validate_logout_id_token_hint(&token, "https://other.example.com", &client, &signing),
        Err(OidcError::InvalidIdTokenHint)
    ));

    let mut wrong_key = signing.clone();
    wrong_key.key_id = "rs256-other".to_owned();
    assert!(matches!(
        validate_logout_id_token_hint(&token, "https://id.example.com", &client, &wrong_key),
        Err(OidcError::InvalidIdTokenHint)
    ));

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(signing.key_id.clone());
    let expired = encode(
        &header,
        &IdTokenClaims {
            iss: "https://id.example.com".to_owned(),
            sub: user.id.to_string(),
            aud: client.client_id.clone(),
            exp: (OffsetDateTime::now_utc() - Duration::hours(1)).unix_timestamp(),
            iat: (OffsetDateTime::now_utc() - Duration::hours(2)).unix_timestamp(),
            auth_time: None,
            nonce: None,
            email: None,
            email_verified: None,
            name: None,
            amr: None,
            acr: None,
            groups: None,
        },
        &EncodingKey::from_rsa_pem(signing.private_key_pem.as_bytes()).unwrap(),
    )
    .unwrap();
    assert!(
        validate_logout_id_token_hint(&expired, "https://id.example.com", &client, &signing)
            .is_ok()
    );
}

#[test]
fn id_token_standard_claims_are_scope_gated() {
    let client = client();
    let signing = signing_material();
    let mut user = User::new(Uuid::new_v4(), "user@example.com", "User Example").unwrap();
    user.email_verified = true;
    let openid_only = vec!["openid".to_owned()];
    let openid_email_profile = vec![
        "openid".to_owned(),
        "email".to_owned(),
        "profile".to_owned(),
    ];

    let minimal = issue_id_token(IdTokenIssueRequest {
        issuer: "https://id.example.com",
        client: &client,
        user: &user,
        scopes: &openid_only,
        nonce: None,
        auth_time: None,
        amr: vec!["pwd".to_owned()],
        acr: "urn:cairn:acr:password".to_owned(),
        groups: None,
        signing: &signing,
    })
    .unwrap();
    let claims =
        validate_logout_id_token_hint(&minimal, "https://id.example.com", &client, &signing)
            .unwrap();
    assert!(claims.email.is_none());
    assert!(claims.email_verified.is_none());
    assert!(claims.name.is_none());

    let scoped = issue_id_token(IdTokenIssueRequest {
        issuer: "https://id.example.com",
        client: &client,
        user: &user,
        scopes: &openid_email_profile,
        nonce: None,
        auth_time: None,
        amr: vec!["pwd".to_owned()],
        acr: "urn:cairn:acr:password".to_owned(),
        groups: None,
        signing: &signing,
    })
    .unwrap();
    let claims =
        validate_logout_id_token_hint(&scoped, "https://id.example.com", &client, &signing)
            .unwrap();
    assert_eq!(claims.email.as_deref(), Some("user@example.com"));
    assert_eq!(claims.email_verified, Some(true));
    assert_eq!(claims.name.as_deref(), Some("User Example"));
}

#[test]
fn userinfo_standard_claims_are_scope_gated() {
    let mut user = User::new(Uuid::new_v4(), "user@example.com", "User Example").unwrap();
    user.email_verified = true;
    let openid_only = vec!["openid".to_owned()];
    let openid_email_profile = vec![
        "openid".to_owned(),
        "email".to_owned(),
        "profile".to_owned(),
        "groups".to_owned(),
    ];

    let minimal = userinfo(&user, &openid_only, None);
    assert!(minimal.get("email").is_none());
    assert!(minimal.get("email_verified").is_none());
    assert!(minimal.get("name").is_none());
    assert!(minimal.get("groups").is_none());

    let scoped = userinfo(
        &user,
        &openid_email_profile,
        Some(vec!["administrators".to_owned(), "engineering".to_owned()]),
    );
    assert_eq!(scoped["email"], json!("user@example.com"));
    assert_eq!(scoped["email_verified"], json!(true));
    assert_eq!(scoped["name"], json!("User Example"));
    assert_eq!(scoped["groups"], json!(["administrators", "engineering"]));
}

#[test]
fn key_encryption_key_requires_32_bytes() {
    let encoded = URL_SAFE_NO_PAD.encode([7_u8; 32]);
    assert!(KeyEncryptionKey::from_base64_url_no_pad(&encoded).is_ok());
    assert!(KeyEncryptionKey::from_base64_url_no_pad("short").is_err());
}

#[test]
fn secret_encryption_round_trips_with_metadata_binding() {
    let encoded = URL_SAFE_NO_PAD.encode([4_u8; 32]);
    let key = KeyEncryptionKey::from_base64_url_no_pad(&encoded).unwrap();
    let encrypted = encrypt_secret("delivery-token", &key, "aad").unwrap();

    assert_ne!(encrypted.ciphertext, b"delivery-token");
    assert_eq!(encrypted.nonce.len(), 12);
    assert_eq!(
        decrypt_secret(&encrypted, &key, "aad").unwrap(),
        "delivery-token"
    );
    assert!(matches!(
        decrypt_secret(&encrypted, &key, "different-aad"),
        Err(OidcError::SecretDecryption)
    ));
}

#[test]
fn signing_material_encrypts_and_decrypts_with_metadata_binding() {
    let encoded = URL_SAFE_NO_PAD.encode([9_u8; 32]);
    let key = KeyEncryptionKey::from_base64_url_no_pad(&encoded).unwrap();
    let signing = SigningMaterial {
        key_id: "rs256-test".to_owned(),
        private_key_pem: "opaque test private signing material".to_owned(),
        public_jwk: json!({
            "kty": "RSA",
            "kid": "rs256-test",
            "alg": "RS256",
            "use": "sig",
            "n": "abc",
            "e": "AQAB"
        }),
    };

    let stored = encrypt_signing_material(&signing, &key).unwrap();
    assert_ne!(
        stored.private_key_ciphertext,
        signing.private_key_pem.as_bytes()
    );

    let decrypted = decrypt_signing_material(&stored, &key).unwrap();
    assert_eq!(decrypted.key_id, signing.key_id);
    assert_eq!(decrypted.private_key_pem, signing.private_key_pem);

    let mut tampered = stored;
    tampered.kid = "rs256-other".to_owned();
    assert!(matches!(
        decrypt_signing_material(&tampered, &key),
        Err(OidcError::SigningKeyDecryption)
    ));
}

#[test]
fn signing_material_reencrypts_without_changing_metadata() {
    let old_key =
        KeyEncryptionKey::from_base64_url_no_pad(&URL_SAFE_NO_PAD.encode([9_u8; 32])).unwrap();
    let new_key =
        KeyEncryptionKey::from_base64_url_no_pad(&URL_SAFE_NO_PAD.encode([8_u8; 32])).unwrap();
    let signing = SigningMaterial {
        key_id: "rs256-retired".to_owned(),
        private_key_pem: "opaque retired private signing material".to_owned(),
        public_jwk: json!({
            "kty": "RSA",
            "kid": "rs256-retired",
            "alg": "RS256",
            "use": "sig",
            "n": "abc",
            "e": "AQAB"
        }),
    };
    let mut stored = encrypt_signing_material(&signing, &old_key).unwrap();
    stored.signing_active = false;
    stored.retired_at = Some(OffsetDateTime::now_utc());
    let original_created_at = stored.created_at;

    let reencrypted = reencrypt_signing_key_material(&stored, &old_key, &new_key).unwrap();

    assert_eq!(reencrypted.kid, stored.kid);
    assert_eq!(reencrypted.public_jwk, stored.public_jwk);
    assert_eq!(reencrypted.signing_active, stored.signing_active);
    assert_eq!(reencrypted.retired_at, stored.retired_at);
    assert_eq!(reencrypted.created_at, original_created_at);
    assert_ne!(
        reencrypted.private_key_ciphertext,
        stored.private_key_ciphertext
    );
    assert!(matches!(
        reencrypt_signing_key_material(&reencrypted, &old_key, &new_key),
        Err(OidcError::SigningKeyDecryption)
    ));
    let active_reencrypted = SigningKeyMaterial {
        signing_active: true,
        retired_at: None,
        ..reencrypted
    };
    let decrypted = decrypt_signing_material(&active_reencrypted, &new_key).unwrap();
    assert_eq!(decrypted.private_key_pem, signing.private_key_pem);
}
