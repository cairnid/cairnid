use super::path::value_at_path;
use serde_json::Value;
use std::collections::BTreeSet;
use uuid::Uuid;

pub(in crate::operations_evidence) fn require_uuid_at_path(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) -> Option<Uuid> {
    let field = path.join(".");
    match value_at_path(value, path).and_then(Value::as_str) {
        Some(actual) => match Uuid::parse_str(actual) {
            Ok(uuid) => Some(uuid),
            Err(_) => {
                failures.push(format!("{field} must be a UUID"));
                None
            }
        },
        None => {
            failures.push(format!("{field} must be a UUID"));
            None
        }
    }
}

pub(in crate::operations_evidence) fn require_uuid_array_exact_len(
    value: &Value,
    path: &[&'static str],
    expected_len: usize,
    failures: &mut Vec<String>,
) -> Option<BTreeSet<Uuid>> {
    let field = path.join(".");
    let Some(values) = value_at_path(value, path).and_then(Value::as_array) else {
        failures.push(format!("{field} must be an array of UUIDs"));
        return None;
    };
    if values.len() != expected_len {
        failures.push(format!(
            "{field} must contain exactly {expected_len} UUIDs, got {}",
            values.len()
        ));
    }

    let mut uuids = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        let Some(actual) = value.as_str() else {
            failures.push(format!("{field}[{index}] must be a UUID string"));
            continue;
        };
        match Uuid::parse_str(actual) {
            Ok(uuid) => {
                if !uuids.insert(uuid) {
                    failures.push(format!("{field}[{index}] duplicates UUID {uuid}"));
                }
            }
            Err(_) => failures.push(format!("{field}[{index}] must be a UUID string")),
        }
    }

    Some(uuids)
}

pub(in crate::operations_evidence) fn validate_optional_uuid(
    value: &Value,
    path: &[&'static str],
    failures: &mut Vec<String>,
) {
    match value_at_path(value, path) {
        Some(Value::Null) | None => {}
        Some(Value::String(candidate)) if Uuid::parse_str(candidate).is_ok() => {}
        Some(Value::String(_)) => {
            failures.push(format!("{} must be a UUID or null", path.join(".")))
        }
        Some(_) => failures.push(format!("{} must be a UUID string or null", path.join("."))),
    }
}

#[cfg(test)]
mod tests {
    use super::require_uuid_array_exact_len;
    use serde_json::json;

    #[test]
    fn uuid_array_validation_reports_wrong_length_duplicates_and_invalid_values() {
        let duplicate = "01890d6f-109f-767a-96cb-2927626f45b1";
        let value = json!({
            "ids": [
                duplicate,
                duplicate,
                "not-a-uuid"
            ]
        });
        let mut failures = Vec::new();

        let parsed = require_uuid_array_exact_len(&value, &["ids"], 2, &mut failures)
            .expect("array is present");

        assert_eq!(parsed.len(), 1);
        assert!(
            failures
                .iter()
                .any(|failure| { failure.contains("ids must contain exactly 2 UUIDs, got 3") })
        );
        assert!(
            failures
                .iter()
                .any(|failure| { failure.contains("ids[1] duplicates UUID") })
        );
        assert!(
            failures
                .iter()
                .any(|failure| { failure.contains("ids[2] must be a UUID string") })
        );
    }
}
