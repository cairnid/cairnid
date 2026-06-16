use super::super::validation::{
    reject_non_empty_array, require_bool, require_non_empty_string_at_path,
    require_rfc3339_timestamp, require_string, require_u64_at_path,
};
use serde_json::Value;

pub(in crate::operations_evidence) fn validate_key_encryption_rotation(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "rotated", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "key-encryption rotation",
        checks,
        failures,
    );

    let signing_keys = require_u64_at_path(value, &["signing_keys"], failures);
    require_u64_at_path(value, &["email_delivery_tokens"], failures);

    match signing_keys {
        Some(count) if count >= 1 => {
            checks.push("key-encryption rotation re-encrypted signing keys".to_owned());
        }
        Some(count) => failures.push(format!(
            "signing_keys must be at least 1 for production KEK rotation evidence, got {count}"
        )),
        None => {}
    }
}

pub(in crate::operations_evidence) fn validate_signing_key_rotation(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "rotated", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "signing-key rotation",
        checks,
        failures,
    );
    require_non_empty_string_at_path(value, &["active_kid"], failures);
    require_bool(value, &["active"], true, failures);

    if failures.is_empty() {
        checks.push("signing-key rotation produced an active database key".to_owned());
    }
}
