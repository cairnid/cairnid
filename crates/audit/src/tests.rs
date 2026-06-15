use serde_json::json;

use super::redact_sensitive_metadata;

#[test]
fn redacts_nested_secrets() {
    let metadata = json!({
        "client_secret": "plain",
        "safe": "value",
        "nested": { "refresh_token": "token" }
    });

    let redacted = redact_sensitive_metadata(metadata);
    assert_eq!(redacted["client_secret"], "[redacted]");
    assert_eq!(redacted["nested"]["refresh_token"], "[redacted]");
    assert_eq!(redacted["safe"], "value");
}

#[test]
fn redacts_common_identity_secret_key_variants() {
    let metadata = json!({
        "Password": "plain",
        "new-password": "plain",
        "idToken": "jwt",
        "authorization.code": "code",
        "codeVerifier": "verifier",
        "csrf_token": "csrf",
        "totpCode": "123456",
        "recoveryCodes": ["one", "two"],
        "privateKeyPem": "pem",
        "CAIRN_KEY_ENCRYPTION_KEY": "kek",
        "preview_url": "https://id.example/reset-password?token=secret",
        "webauthn": {
            "clientDataJSON": "json",
            "attestationObject": "object",
            "authenticatorData": "data",
            "signature": "sig",
            "credential_id": "safe-public-id"
        }
    });

    let redacted = redact_sensitive_metadata(metadata);

    assert_eq!(redacted["Password"], "[redacted]");
    assert_eq!(redacted["new-password"], "[redacted]");
    assert_eq!(redacted["idToken"], "[redacted]");
    assert_eq!(redacted["authorization.code"], "[redacted]");
    assert_eq!(redacted["codeVerifier"], "[redacted]");
    assert_eq!(redacted["csrf_token"], "[redacted]");
    assert_eq!(redacted["totpCode"], "[redacted]");
    assert_eq!(redacted["recoveryCodes"], "[redacted]");
    assert_eq!(redacted["privateKeyPem"], "[redacted]");
    assert_eq!(redacted["CAIRN_KEY_ENCRYPTION_KEY"], "[redacted]");
    assert_eq!(redacted["preview_url"], "[redacted]");
    assert_eq!(redacted["webauthn"]["clientDataJSON"], "[redacted]");
    assert_eq!(redacted["webauthn"]["attestationObject"], "[redacted]");
    assert_eq!(redacted["webauthn"]["authenticatorData"], "[redacted]");
    assert_eq!(redacted["webauthn"]["signature"], "[redacted]");
    assert_eq!(redacted["webauthn"]["credential_id"], "safe-public-id");
}

#[test]
fn keeps_common_non_secret_identifiers_and_oauth_metadata() {
    let metadata = json!({
        "client_id": "public-client",
        "credential_id": "passkey-id",
        "key_id": "kid",
        "status_code": 200,
        "token_type_hint": "access_token",
        "redirect_uri": "https://app.example/callback"
    });

    let redacted = redact_sensitive_metadata(metadata);

    assert_eq!(redacted["client_id"], "public-client");
    assert_eq!(redacted["credential_id"], "passkey-id");
    assert_eq!(redacted["key_id"], "kid");
    assert_eq!(redacted["status_code"], 200);
    assert_eq!(redacted["token_type_hint"], "access_token");
    assert_eq!(redacted["redirect_uri"], "https://app.example/callback");
}
