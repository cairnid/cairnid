use super::{
    discovery::validate_discovery_metadata,
    jwks::validate_jwks_metadata,
    resources::{oidc_metadata_resource_url, oidc_metadata_smoke_issuer},
};
use serde_json::json;

#[test]
fn oidc_metadata_smoke_issuer_requires_https_origin() {
    let issuer =
        oidc_metadata_smoke_issuer("TEST_ISSUER", "https://id.example.com").expect("issuer");
    assert_eq!(issuer.as_str(), "https://id.example.com/");

    for value in [
        "",
        "http://id.example.com",
        "https://user:pass@id.example.com",
        "https://id.example.com/path",
        "https://id.example.com?debug=true",
        "https://id.example.com#fragment",
    ] {
        assert!(
            oidc_metadata_smoke_issuer("TEST_ISSUER", value).is_err(),
            "{value} should be rejected"
        );
    }
}

#[test]
fn oidc_metadata_resource_url_targets_discovery_and_jwks() {
    let issuer =
        oidc_metadata_smoke_issuer("TEST_ISSUER", "https://id.example.com").expect("issuer");

    assert_eq!(
        oidc_metadata_resource_url(&issuer, "/.well-known/openid-configuration")
            .expect("discovery URL")
            .as_str(),
        "https://id.example.com/.well-known/openid-configuration"
    );
    assert_eq!(
        oidc_metadata_resource_url(&issuer, "/.well-known/jwks.json")
            .expect("JWKS URL")
            .as_str(),
        "https://id.example.com/.well-known/jwks.json"
    );
}

#[test]
fn oidc_metadata_discovery_validation_accepts_strict_metadata() {
    let checks =
        validate_discovery_metadata("https://id.example.com", &strict_discovery_metadata())
            .expect("strict discovery");

    assert!(
        checks
            .iter()
            .any(|check| check.name == "discovery_pkce_s256")
    );
    assert!(checks.iter().any(|check| check.name == "discovery_rs256"));
}

#[test]
fn oidc_metadata_discovery_validation_rejects_legacy_grants() {
    let mut discovery = strict_discovery_metadata();
    discovery["grant_types_supported"] = json!([
        "authorization_code",
        "refresh_token",
        "client_credentials",
        "password"
    ]);

    let error = validate_discovery_metadata("https://id.example.com", &discovery)
        .expect_err("legacy grant rejected");

    assert!(error.to_string().contains("password"));
}

#[test]
fn oidc_metadata_jwks_validation_accepts_public_rs256_key() {
    let checks = validate_jwks_metadata(&public_jwks()).expect("public JWKS");

    assert!(
        checks
            .iter()
            .any(|check| check.name == "jwks_rs256_public_key_material")
    );
}

#[test]
fn oidc_metadata_jwks_validation_rejects_private_material() {
    let mut jwks = public_jwks();
    jwks["keys"][0]["d"] = json!("private-exponent");

    let error = validate_jwks_metadata(&jwks).expect_err("private material rejected");

    assert!(error.to_string().contains("private JWK field d"));
}

fn strict_discovery_metadata() -> serde_json::Value {
    json!({
        "issuer": "https://id.example.com",
        "authorization_endpoint": "https://id.example.com/oauth2/authorize",
        "token_endpoint": "https://id.example.com/oauth2/token",
        "userinfo_endpoint": "https://id.example.com/oauth2/userinfo",
        "end_session_endpoint": "https://id.example.com/oauth2/logout",
        "jwks_uri": "https://id.example.com/.well-known/jwks.json",
        "introspection_endpoint": "https://id.example.com/oauth2/introspect",
        "revocation_endpoint": "https://id.example.com/oauth2/revoke",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "groups", "offline_access"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat"],
        "acr_values_supported": ["urn:cairn:acr:password"],
        "prompt_values_supported": ["none", "login", "consent"],
        "display_values_supported": ["page", "popup", "touch", "wap"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
        "claims_parameter_supported": false,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "require_request_uri_registration": false
    })
}

fn public_jwks() -> serde_json::Value {
    json!({
        "keys": [
            {
                "kty": "RSA",
                "kid": "rs256-active",
                "use": "sig",
                "alg": "RS256",
                "n": "sXch6b8WfQ",
                "e": "AQAB"
            }
        ]
    })
}
