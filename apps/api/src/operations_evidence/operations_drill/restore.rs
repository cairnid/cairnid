use super::super::validation::{
    non_empty_string_at_path, require_bool, require_empty_array, require_i64_at_least,
    require_rfc3339_timestamp, require_string, require_uuid_at_path, value_at_path,
};
use serde_json::Value;

pub(in crate::operations_evidence) fn validate_restore_drill(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_string(value, "status", "ok", failures);
    require_empty_array(value, "failures", failures);
    require_rfc3339_timestamp(value, "completed_at", "restore drill", checks, failures);
    require_bool(value, &["database", "reachable"], true, failures);
    require_bool(value, &["database", "migrations_present"], true, failures);
    require_i64_at_least(value, &["database", "applied_migrations"], 1, failures);
    require_uuid_at_path(value, &["organization_id"], failures);
    require_bool(
        value,
        &["signing", "signing_source_available"],
        true,
        failures,
    );

    let restored_database_key_ready =
        non_empty_string_at_path(value, &["signing", "active_database_kid"])
            && value_at_path(value, &["signing", "active_database_key_decryptable"])
                .and_then(Value::as_bool)
                .is_some_and(|ready| ready)
            && value_at_path(value, &["signing", "active_jwks_count"])
                .and_then(Value::as_i64)
                .is_some_and(|count| count >= 1);
    let legacy_signing_ready = value_at_path(value, &["signing", "legacy_env_configured"])
        .and_then(Value::as_bool)
        .is_some_and(|configured| configured);

    if restored_database_key_ready {
        checks.push("restored database signing key and JWKS are ready".to_owned());
    } else if legacy_signing_ready {
        checks.push("legacy signing material is ready for restored environment".to_owned());
    } else {
        failures.push(
            "restore drill must prove a decryptable active database signing key with JWKS material or configured legacy signing material"
                .to_owned(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::validate_restore_drill;
    use serde_json::json;

    const ORG_ID: &str = "01890d6f-109f-767a-96cb-2927626f4500";

    #[test]
    fn restore_drill_accepts_database_signing_key_evidence() {
        let value = json!({
            "status": "ok",
            "organization_id": ORG_ID,
            "completed_at": "2026-06-07T12:00:00Z",
            "failures": [],
            "database": {
                "reachable": true,
                "migrations_present": true,
                "applied_migrations": 12
            },
            "signing": {
                "signing_source_available": true,
                "active_database_kid": "rs256-active",
                "active_database_key_decryptable": true,
                "active_jwks_count": 1,
                "legacy_env_configured": false
            }
        });
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_restore_drill(&value, &mut checks, &mut failures);

        assert!(failures.is_empty(), "{failures:?}");
        assert!(checks.contains(&"restored database signing key and JWKS are ready".to_owned()));
    }
}
