use serde_json::Value;

pub fn redact_sensitive_metadata(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    if is_sensitive_metadata_key(&key) {
                        (key, Value::String("[redacted]".to_owned()))
                    } else {
                        (key, redact_sensitive_metadata(value))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(redact_sensitive_metadata).collect())
        }
        other => other,
    }
}

fn is_sensitive_metadata_key(key: &str) -> bool {
    let normalized = normalize_metadata_key(key);
    let compact = normalized.replace('_', "");

    matches!(
        normalized.as_str(),
        "password"
            | "secret"
            | "client_secret"
            | "token"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "authorization_code"
            | "code"
            | "code_verifier"
            | "mfa_code"
            | "totp_code"
            | "otp_code"
            | "recovery_code"
            | "recovery_codes"
            | "csrf_token"
            | "private_key"
            | "private_key_pem"
            | "signing_private_key"
            | "signing_private_key_pem"
            | "key_encryption_key"
            | "kek"
            | "preview_url"
            | "action_url"
            | "magic_link"
            | "verification_link"
            | "recovery_link"
            | "invitation_link"
            | "client_data_json"
            | "attestation_object"
            | "authenticator_data"
            | "signature"
    ) || matches!(
        compact.as_str(),
        "idtoken"
            | "authorizationcode"
            | "codeverifier"
            | "mfacode"
            | "totpcode"
            | "otpcode"
            | "recoverycode"
            | "recoverycodes"
            | "csrftoken"
            | "privatekey"
            | "privatekeypem"
            | "signingprivatekey"
            | "signingprivatekeypem"
            | "keyencryptionkey"
            | "previewurl"
            | "actionurl"
            | "magiclink"
            | "verificationlink"
            | "recoverylink"
            | "invitationlink"
            | "clientdatajson"
            | "attestationobject"
            | "authenticatordata"
    ) || normalized.ends_with("_password")
        || normalized.ends_with("_secret")
        || normalized.ends_with("_token")
        || normalized.ends_with("_private_key")
        || normalized.ends_with("_private_key_pem")
        || compact.contains("keyencryptionkey")
        || normalized.contains("recovery_code")
        || compact.contains("recoverycode")
}

fn normalize_metadata_key(key: &str) -> String {
    let mut normalized = String::with_capacity(key.len());
    let mut previous_was_separator = false;

    for character in key.chars() {
        if character.is_ascii_alphanumeric() {
            normalized.push(character.to_ascii_lowercase());
            previous_was_separator = false;
        } else if !previous_was_separator {
            normalized.push('_');
            previous_was_separator = true;
        }
    }

    normalized.trim_matches('_').to_owned()
}
