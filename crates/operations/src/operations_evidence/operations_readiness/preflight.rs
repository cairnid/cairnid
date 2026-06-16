use super::super::validation::{
    require_bool, require_empty_array, require_i64_at_least, require_i64_exact, require_string,
};
use serde_json::Value;

pub(in crate::operations_evidence) fn validate_operations_preflight(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "ok", failures);
    require_string(value, "environment", "production", failures);
    require_empty_array(value, "failures", failures);
    require_i64_at_least(value, &["database", "applied_migrations"], 1, failures);
    require_bool(
        value,
        &["signing", "database_active_key_decryptable"],
        true,
        failures,
    );
    require_i64_at_least(
        value,
        &["signing", "lifecycle", "active_key_count"],
        1,
        failures,
    );
    require_i64_exact(
        value,
        &["signing", "lifecycle", "active_key_count"],
        1,
        failures,
    );
    require_i64_at_least(value, &["signing", "active_jwks_count"], 1, failures);
    require_bool(
        value,
        &["email_delivery", "production_ready"],
        true,
        failures,
    );
    require_i64_exact(value, &["email_delivery", "queue", "failed"], 0, failures);
    require_bool(
        value,
        &["openid_conformance", "issuer_https_origin_ready"],
        true,
        failures,
    );
    require_bool(
        value,
        &["openid_conformance", "static_client_environment_ready"],
        true,
        failures,
    );
    checks.push("production preflight is ready".to_owned());
}
