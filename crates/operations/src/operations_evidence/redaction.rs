use serde_json::Value;

const FORBIDDEN_TOKEN_FREE_RELEASE_EVIDENCE_FIELDS: &[&str] = &[
    "accesstoken",
    "apikey",
    "authorization",
    "authorizationheader",
    "authorizationheaders",
    "bearertoken",
    "clientsecret",
    "clientsecrets",
    "commandoutput",
    "cookie",
    "cookies",
    "idtoken",
    "password",
    "passwords",
    "privatekey",
    "providercredential",
    "providercredentials",
    "rawoutput",
    "rawsecret",
    "rawtoken",
    "refreshtoken",
    "requestheader",
    "requestheaders",
    "secret",
    "secrettoken",
    "sessioncookie",
    "setcookie",
    "stderr",
    "stdout",
];

pub(super) fn reject_forbidden_token_free_release_evidence_fields(
    value: &Value,
    path: &str,
    artifact_name: &str,
    failures: &mut Vec<String>,
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized_key = key
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .collect::<String>()
                    .to_ascii_lowercase();
                let child_path = if path == "$" {
                    format!("$.{key}")
                } else {
                    format!("{path}.{key}")
                };
                if FORBIDDEN_TOKEN_FREE_RELEASE_EVIDENCE_FIELDS.contains(&normalized_key.as_str()) {
                    failures.push(format!(
                        "{child_path} must not be present in token-free release evidence artifact {artifact_name}"
                    ));
                }
                reject_forbidden_token_free_release_evidence_fields(
                    child,
                    &child_path,
                    artifact_name,
                    failures,
                );
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_forbidden_token_free_release_evidence_fields(
                    child,
                    &format!("{path}[{index}]"),
                    artifact_name,
                    failures,
                );
            }
        }
        Value::String(text) => {
            if is_credential_shaped_token_free_value(text) {
                failures.push(format!(
                    "{path} value is credential-shaped in token-free release evidence artifact {artifact_name}"
                ));
            }
        }
        _ => {}
    }
}

fn is_credential_shaped_token_free_value(value: &str) -> bool {
    contains_raw_bearer_value(value) || contains_sensitive_assignment_value(value)
}

fn contains_raw_bearer_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    for (index, _) in lower.match_indices("bearer") {
        let after_bearer = index + "bearer".len();
        let Some(after) = lower[after_bearer..].chars().next() else {
            continue;
        };
        if !after.is_ascii_whitespace() {
            continue;
        }
        let before = &lower[..index];
        if !before.trim().is_empty() && !before.contains("authorization") {
            continue;
        }
        let candidate = credential_value_fragment(&value[after_bearer..]);
        if !credential_value_is_placeholder(candidate) {
            return true;
        }
    }
    false
}

fn contains_sensitive_assignment_value(value: &str) -> bool {
    let mut search_start = 0;
    while let Some(relative_index) = value[search_start..].find('=') {
        let equals_index = search_start + relative_index;
        let key = assignment_key_before(value, equals_index);
        if is_sensitive_assignment_key(key) {
            let candidate = credential_value_fragment(&value[equals_index + 1..]);
            if !credential_value_is_placeholder(candidate) {
                return true;
            }
        }
        search_start = equals_index + 1;
    }
    false
}

fn assignment_key_before(value: &str, equals_index: usize) -> &str {
    let before = &value[..equals_index];
    let mut start = before.len();
    for (index, character) in before.char_indices().rev() {
        if is_assignment_key_character(character) {
            start = index;
        } else {
            break;
        }
    }
    before[start..].trim()
}

fn is_assignment_key_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | ':' | '$')
}

fn is_sensitive_assignment_key(key: &str) -> bool {
    let normalized_key = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    matches!(
        normalized_key.as_str(),
        "clientsecret" | "password" | "secret" | "token"
    ) || normalized_key.ends_with("clientsecret")
        || normalized_key.ends_with("password")
        || normalized_key.ends_with("secret")
        || normalized_key.ends_with("token")
}

fn credential_value_fragment(value: &str) -> &str {
    let trimmed = value.trim_start_matches(|character: char| {
        character.is_ascii_whitespace() || matches!(character, '"' | '\'')
    });
    let end = trimmed
        .char_indices()
        .find_map(|(index, character)| {
            if character.is_ascii_whitespace()
                || matches!(character, '"' | '\'' | ',' | ';' | '}' | ']')
            {
                Some(index)
            } else {
                None
            }
        })
        .unwrap_or(trimmed.len());
    &trimmed[..end]
}

fn credential_value_is_placeholder(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches(|character| matches!(character, '"' | '\''));
    if value.is_empty() {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with('<') && lower.ends_with('>') {
        return true;
    }
    if lower.starts_with("${") && lower.ends_with('}') {
        return true;
    }
    if lower.starts_with('%') && lower.ends_with('%') {
        return true;
    }
    if lower.contains("placeholder") || lower.contains("redacted") {
        return true;
    }
    if value.chars().all(|character| character == '*') {
        return true;
    }
    matches!(
        lower.as_str(),
        "token"
            | "bearer-token"
            | "raw-token"
            | "secret"
            | "client-secret"
            | "password"
            | "value"
            | "example"
            | "example-token"
            | "old-token"
            | "new-token"
            | "old-or-new-token-during-rotation"
            | "old-or-invalid-token"
    )
}

pub(super) fn sanitize_release_evidence_failure(failure: String) -> String {
    if failure.contains("must not be present in token-free") {
        return failure;
    }

    let redacted_bearer = redact_case_insensitive_suffix(&failure, "bearer ");
    if redacted_bearer != failure {
        return redacted_bearer;
    }

    let lower = failure.to_ascii_lowercase();
    if let Some(index) = lower.find("got ") {
        let echoed_value = &lower[index + "got ".len()..];
        let secret_value_markers = [
            "access_token",
            "api_key",
            "apikey",
            "authorization:",
            "client_secret",
            "cookie:",
            "id_token",
            "password=",
            "private_key",
            "providercredential",
            "rawtoken",
            "refresh_token",
            "secret=",
            "token=",
        ];
        if secret_value_markers
            .iter()
            .any(|marker| echoed_value.contains(marker))
        {
            return format!("{}got <redacted>", &failure[..index]);
        }
    }

    const MAX_FAILURE_LENGTH: usize = 512;
    if failure.len() > MAX_FAILURE_LENGTH {
        return format!(
            "{}... <truncated>",
            failure.chars().take(MAX_FAILURE_LENGTH).collect::<String>()
        );
    }

    failure
}

fn redact_case_insensitive_suffix(value: &str, needle: &str) -> String {
    let lower = value.to_ascii_lowercase();
    let Some(index) = lower.find(needle) else {
        return value.to_owned();
    };
    let end = index + needle.len();
    format!("{}{}<redacted>", &value[..index], &value[index..end])
}

#[cfg(test)]
mod tests {
    use super::{
        reject_forbidden_token_free_release_evidence_fields, sanitize_release_evidence_failure,
    };
    use serde_json::json;

    #[test]
    fn token_free_release_evidence_rejects_nested_secret_field_names() {
        let value = json!({
            "status": "ok",
            "checks": [
                {
                    "name": "safe",
                    "client_secret": "must-not-appear",
                    "requestHeaders": {
                        "Authorization": "must-not-appear"
                    }
                }
            ]
        });
        let mut failures = Vec::new();

        reject_forbidden_token_free_release_evidence_fields(
            &value,
            "$",
            "oidc_metadata_smoke",
            &mut failures,
        );

        assert!(failures.iter().any(|failure| {
            failure.contains(
                "$.checks[0].client_secret must not be present in token-free release evidence artifact oidc_metadata_smoke",
            )
        }));
        assert!(failures.iter().any(|failure| {
            failure.contains(
                "$.checks[0].requestHeaders must not be present in token-free release evidence artifact oidc_metadata_smoke",
            )
        }));
        assert!(failures.iter().any(|failure| {
            failure.contains(
                "$.checks[0].requestHeaders.Authorization must not be present in token-free release evidence artifact oidc_metadata_smoke",
            )
        }));
    }

    #[test]
    fn release_evidence_failure_sanitizer_redacts_bearer_and_echoed_secret_values() {
        assert_eq!(
            sanitize_release_evidence_failure("provider returned got Bearer raw-value".to_owned()),
            "provider returned got Bearer <redacted>"
        );
        assert_eq!(
            sanitize_release_evidence_failure(
                "validator expected sanitized value, got client_secret=raw-value".to_owned(),
            ),
            "validator expected sanitized value, got <redacted>"
        );
    }

    #[test]
    fn release_evidence_failure_sanitizer_preserves_forbidden_field_paths_and_truncates_noise() {
        let forbidden_field =
            "$.rawToken must not be present in token-free release evidence artifact scim_smoke"
                .to_owned();
        assert_eq!(
            sanitize_release_evidence_failure(forbidden_field.clone()),
            forbidden_field
        );

        let sanitized = sanitize_release_evidence_failure("x".repeat(600));
        assert!(sanitized.ends_with("... <truncated>"));
        assert!(sanitized.len() < 600);
    }
}
