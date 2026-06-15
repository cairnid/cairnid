use super::constants::FORBIDDEN_OPENID_RESULT_FIELDS;
use serde_json::Value;

pub(super) fn reject_forbidden_openid_result_fields(
    value: &Value,
    path: &str,
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
                if FORBIDDEN_OPENID_RESULT_FIELDS.contains(&normalized_key.as_str()) {
                    failures.push(format!(
                        "{child_path} must not be present in token-free OpenID result evidence"
                    ));
                }
                reject_forbidden_openid_result_fields(child, &child_path, failures);
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_forbidden_openid_result_fields(child, &format!("{path}[{index}]"), failures);
            }
        }
        _ => {}
    }
}
