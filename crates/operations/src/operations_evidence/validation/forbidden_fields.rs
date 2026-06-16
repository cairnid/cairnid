use serde_json::Value;

const FORBIDDEN_SCIM_CONNECTOR_SMOKE_FIELDS: &[&str] = &[
    "authorization",
    "authorizationheader",
    "bearertoken",
    "clientsecret",
    "password",
    "providercredential",
    "providercredentials",
    "rawtoken",
    "secrettoken",
];

const FORBIDDEN_DEPENDENCY_POLICY_FIELDS: &[&str] = &[
    "authorization",
    "authorizationheader",
    "bearertoken",
    "clientsecret",
    "commandoutput",
    "cookie",
    "password",
    "rawoutput",
    "requestheader",
    "requestheaders",
    "secret",
    "stderr",
    "stdout",
    "token",
];

pub(in crate::operations_evidence) fn reject_forbidden_scim_connector_smoke_fields(
    value: &Value,
    path: &str,
    failures: &mut Vec<String>,
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized_key = normalized_json_field_name(key);
                let child_path = child_json_path(path, key);
                if FORBIDDEN_SCIM_CONNECTOR_SMOKE_FIELDS.contains(&normalized_key.as_str()) {
                    failures.push(format!(
                        "{child_path} must not be present in token-free connector smoke evidence"
                    ));
                }
                reject_forbidden_scim_connector_smoke_fields(child, &child_path, failures);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_forbidden_scim_connector_smoke_fields(
                    child,
                    &format!("{path}[{index}]"),
                    failures,
                );
            }
        }
        _ => {}
    }
}

pub(in crate::operations_evidence) fn reject_forbidden_dependency_policy_fields(
    value: &Value,
    path: &str,
    failures: &mut Vec<String>,
) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized_key = normalized_json_field_name(key);
                let child_path = child_json_path(path, key);
                if FORBIDDEN_DEPENDENCY_POLICY_FIELDS.contains(&normalized_key.as_str()) {
                    failures.push(format!(
                        "{child_path} must not be present in token-free dependency-policy evidence"
                    ));
                }
                reject_forbidden_dependency_policy_fields(child, &child_path, failures);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_forbidden_dependency_policy_fields(
                    child,
                    &format!("{path}[{index}]"),
                    failures,
                );
            }
        }
        _ => {}
    }
}

fn normalized_json_field_name(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn child_json_path(parent: &str, key: &str) -> String {
    if parent == "$" {
        format!("$.{key}")
    } else {
        format!("{parent}.{key}")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        reject_forbidden_dependency_policy_fields, reject_forbidden_scim_connector_smoke_fields,
    };
    use serde_json::json;

    #[test]
    fn artifact_specific_forbidden_field_rejection_normalizes_field_names() {
        let value = json!({
            "request-headers": {
                "AuthorizationHeader": "secret"
            },
            "checks": [
                {
                    "raw_token": "secret"
                }
            ]
        });
        let mut scim_failures = Vec::new();
        let mut dependency_failures = Vec::new();

        reject_forbidden_scim_connector_smoke_fields(&value, "$", &mut scim_failures);
        reject_forbidden_dependency_policy_fields(&value, "$", &mut dependency_failures);

        assert!(scim_failures.iter().any(|failure| {
            failure.contains(
                "$.request-headers.AuthorizationHeader must not be present in token-free connector smoke evidence",
            )
        }));
        assert!(scim_failures.iter().any(|failure| {
            failure.contains(
                "$.checks[0].raw_token must not be present in token-free connector smoke evidence",
            )
        }));
        assert!(dependency_failures.iter().any(|failure| {
            failure.contains(
                "$.request-headers must not be present in token-free dependency-policy evidence",
            )
        }));
    }
}
