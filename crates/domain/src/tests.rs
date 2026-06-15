use super::{
    DomainError, OidcClient, OidcClientStatus, OidcGrantType, RedirectUri, checked_string,
    normalize_email,
};
use time::OffsetDateTime;
use uuid::Uuid;

#[test]
fn redirect_uri_rejects_insecure_remote_http() {
    let result = RedirectUri::parse("http://example.com/callback");
    assert_eq!(result, Err(DomainError::InsecureRedirectUri));
}

#[test]
fn redirect_uri_allows_localhost_http() {
    let result = RedirectUri::parse("http://localhost:5173/callback");
    assert!(result.is_ok());
}

#[test]
fn redirect_uri_rejects_fragments() {
    for uri in [
        "https://app.example.com/callback#code",
        "http://localhost:5173/callback#state",
    ] {
        assert_eq!(
            RedirectUri::parse(uri),
            Err(DomainError::InsecureRedirectUri)
        );
    }
}

#[test]
fn redirect_uri_allows_loopback_http_with_numeric_ports() {
    assert!(RedirectUri::parse("http://127.0.0.1:5173/callback").is_ok());
    assert!(RedirectUri::parse("http://[::1]:5173/callback").is_ok());
}

#[test]
fn redirect_uri_rejects_localhost_http_host_confusion() {
    for uri in [
        "http://localhost/callback",
        "http://localhost:5173.evil.example/callback",
        "http://127.0.0.1:5173@evil.example/callback",
        "http://user@localhost:5173/callback",
        "http://localhost:not-a-port/callback",
        "http://localhost:99999/callback",
    ] {
        assert_eq!(
            RedirectUri::parse(uri),
            Err(DomainError::InsecureRedirectUri)
        );
    }
}

#[test]
fn redirect_matching_is_exact() {
    let client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        client_id: "client".to_owned(),
        client_secret_hash: None,
        consent_policy_template_id: None,
        name: "Client".to_owned(),
        redirect_uris: vec![RedirectUri::parse("https://app.example.com/callback").unwrap()],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec!["openid".to_owned()],
        grant_types: vec![OidcGrantType::AuthorizationCode],
        public_client: true,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: OffsetDateTime::now_utc(),
    };

    assert!(client.allows_redirect_uri("https://app.example.com/callback"));
    assert!(!client.allows_redirect_uri("https://app.example.com/callback/"));
}

#[test]
fn post_logout_redirect_matching_is_exact() {
    let client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: Uuid::new_v4(),
        client_id: "client".to_owned(),
        client_secret_hash: None,
        consent_policy_template_id: None,
        name: "Client".to_owned(),
        redirect_uris: vec![RedirectUri::parse("https://app.example.com/callback").unwrap()],
        post_logout_redirect_uris: vec![
            RedirectUri::parse("https://app.example.com/logout").unwrap(),
        ],
        allowed_scopes: vec!["openid".to_owned()],
        grant_types: vec![OidcGrantType::AuthorizationCode],
        public_client: true,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: OffsetDateTime::now_utc(),
    };

    assert!(client.allows_post_logout_redirect_uri("https://app.example.com/logout"));
    assert!(!client.allows_post_logout_redirect_uri("https://app.example.com/logout/"));
}

#[test]
fn shared_string_validation_trims_bounds_and_rejects_empty_values() {
    assert_eq!(
        checked_string("name", "  Example  ".to_owned(), 20).expect("valid string"),
        "Example"
    );
    assert_eq!(
        checked_string("name", "  ".to_owned(), 20),
        Err(DomainError::EmptyField { field: "name" })
    );
    assert_eq!(
        checked_string("name", "abcdef".to_owned(), 5),
        Err(DomainError::FieldTooLong {
            field: "name",
            max: 5
        })
    );
}

#[test]
fn email_normalization_is_lowercase_trimmed_and_structural() {
    assert_eq!(
        normalize_email("  PERSON@EXAMPLE.COM ".to_owned()).expect("valid email"),
        "person@example.com"
    );
    assert_eq!(
        normalize_email("person@example".to_owned()),
        Err(DomainError::InvalidEmail)
    );
    assert_eq!(
        normalize_email("person@@example.com".to_owned()),
        Err(DomainError::InvalidEmail)
    );
}
