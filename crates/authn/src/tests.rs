use cairn_domain::PkceMethod;
use secrecy::SecretString;

use super::{
    AuthnError, TotpProfile, WebAuthnConfig, generate_secret, hash_password, hash_token,
    pkce_challenge, validate_pkce_code_challenge, validate_pkce_code_verifier, verify_password,
    verify_pkce, verify_token_hash,
};

#[test]
fn password_hash_round_trips() {
    let password = SecretString::from("correct horse battery staple".to_owned());
    let hash = hash_password(&password).unwrap();

    assert!(verify_password(&password, &hash).is_ok());
    assert!(verify_password(&SecretString::from("wrong".to_owned()), &hash).is_err());
}

#[test]
fn pkce_s256_matches_known_vector() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    assert!(validate_pkce_code_verifier(verifier).is_ok());
    assert!(validate_pkce_code_challenge(expected).is_ok());
    assert_eq!(pkce_challenge(verifier, PkceMethod::S256), expected);
    assert!(verify_pkce(verifier, expected, PkceMethod::S256).is_ok());
}

#[test]
fn pkce_values_must_match_rfc7636_syntax() {
    let too_short = "abc";
    let invalid_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO+/";
    let too_long = "a".repeat(129);

    assert!(matches!(
        validate_pkce_code_verifier(too_short),
        Err(AuthnError::InvalidPkceSyntax)
    ));
    assert!(matches!(
        validate_pkce_code_challenge(invalid_characters),
        Err(AuthnError::InvalidPkceSyntax)
    ));
    assert!(matches!(
        validate_pkce_code_verifier(&too_long),
        Err(AuthnError::InvalidPkceSyntax)
    ));
}

#[test]
fn token_hash_is_stable_and_not_plaintext() {
    let token = "sample-token";
    let hash = hash_token(token);

    assert_ne!(hash, token);
    assert!(verify_token_hash(token, &hash));
    assert!(!verify_token_hash("other-token", &hash));
    assert!(!verify_token_hash(token, &hash[..hash.len() - 1]));
}

#[test]
fn totp_profile_generates_and_verifies_current_code() {
    let secret = generate_secret(20);
    let profile = TotpProfile::new("Cairn Identity", "admin@example.com", secret);
    let totp = profile.build().unwrap();
    let code = totp.generate_current().unwrap();

    assert!(profile.verify_current(&code).unwrap());
    assert!(!profile.verify_current("000000").unwrap());
}

#[test]
fn webauthn_config_derives_rp_id_from_origin_host() {
    let config = WebAuthnConfig::from_origin("https://id.example.com:8443").unwrap();

    assert_eq!(config.relying_party_id, "id.example.com");
    assert_eq!(config.relying_party_origin, "https://id.example.com:8443");
    assert!(config.build().is_ok());
}
