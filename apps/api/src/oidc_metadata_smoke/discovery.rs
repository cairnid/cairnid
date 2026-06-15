use serde_json::Value;

use super::{
    JWKS_PATH,
    types::{OidcMetadataSmokeCheck, OidcMetadataSmokeError},
    validation::{
        require_bool_field, require_endpoint, require_object, require_string_array_contains_all,
        require_string_array_excludes_all, require_string_array_only, require_string_field,
    },
};

pub(super) fn validate_discovery_metadata(
    issuer: &str,
    discovery: &Value,
) -> Result<Vec<OidcMetadataSmokeCheck>, OidcMetadataSmokeError> {
    require_object(discovery, "discovery")?;
    require_string_field(discovery, "issuer", issuer)?;
    require_endpoint(
        discovery,
        issuer,
        "authorization_endpoint",
        "/oauth2/authorize",
    )?;
    require_endpoint(discovery, issuer, "token_endpoint", "/oauth2/token")?;
    require_endpoint(discovery, issuer, "userinfo_endpoint", "/oauth2/userinfo")?;
    require_endpoint(discovery, issuer, "jwks_uri", JWKS_PATH)?;
    require_endpoint(
        discovery,
        issuer,
        "introspection_endpoint",
        "/oauth2/introspect",
    )?;
    require_endpoint(discovery, issuer, "revocation_endpoint", "/oauth2/revoke")?;
    require_endpoint(discovery, issuer, "end_session_endpoint", "/oauth2/logout")?;

    require_string_array_only(discovery, "response_types_supported", &["code"])?;
    require_string_array_only(discovery, "response_modes_supported", &["query"])?;
    require_string_array_contains_all(
        discovery,
        "grant_types_supported",
        &["authorization_code", "refresh_token", "client_credentials"],
    )?;
    require_string_array_excludes_all(
        discovery,
        "grant_types_supported",
        &["implicit", "password"],
    )?;
    require_string_array_contains_all(
        discovery,
        "scopes_supported",
        &["openid", "profile", "email", "groups", "offline_access"],
    )?;
    require_string_array_only(
        discovery,
        "id_token_signing_alg_values_supported",
        &["RS256"],
    )?;
    require_string_array_contains_all(
        discovery,
        "token_endpoint_auth_methods_supported",
        &["client_secret_basic", "client_secret_post", "none"],
    )?;
    require_string_array_only(discovery, "code_challenge_methods_supported", &["S256"])?;
    require_string_array_contains_all(
        discovery,
        "prompt_values_supported",
        &["none", "login", "consent"],
    )?;
    require_bool_field(
        discovery,
        "authorization_response_iss_parameter_supported",
        true,
    )?;
    require_bool_field(discovery, "claims_parameter_supported", false)?;
    require_bool_field(discovery, "request_parameter_supported", false)?;
    require_bool_field(discovery, "request_uri_parameter_supported", false)?;
    require_bool_field(discovery, "require_request_uri_registration", false)?;

    Ok(vec![
        OidcMetadataSmokeCheck {
            name: "discovery_issuer_matches",
            status: "passed",
            detail: "discovery issuer exactly matches the configured issuer origin".to_owned(),
        },
        OidcMetadataSmokeCheck {
            name: "discovery_endpoint_urls_match_issuer",
            status: "passed",
            detail: "discovery endpoint URLs are issuer-relative expected OIDC endpoints"
                .to_owned(),
        },
        OidcMetadataSmokeCheck {
            name: "discovery_strict_code_flow",
            status: "passed",
            detail:
                "discovery exposes only authorization code response type and query response mode"
                    .to_owned(),
        },
        OidcMetadataSmokeCheck {
            name: "discovery_refresh_and_client_credentials",
            status: "passed",
            detail: "discovery exposes authorization code, refresh token, and client credentials grants without legacy password or implicit grants"
                .to_owned(),
        },
        OidcMetadataSmokeCheck {
            name: "discovery_pkce_s256",
            status: "passed",
            detail: "discovery exposes PKCE S256 and does not advertise plain PKCE".to_owned(),
        },
        OidcMetadataSmokeCheck {
            name: "discovery_rs256",
            status: "passed",
            detail: "discovery exposes RS256 as the ID token signing algorithm".to_owned(),
        },
        OidcMetadataSmokeCheck {
            name: "discovery_request_objects_disabled",
            status: "passed",
            detail: "claims, request, and request_uri parameters are disabled in v1".to_owned(),
        },
        OidcMetadataSmokeCheck {
            name: "discovery_rfc9207_iss_supported",
            status: "passed",
            detail: "discovery advertises authorization response issuer parameter support"
                .to_owned(),
        },
    ])
}
