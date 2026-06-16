use super::*;
use serde_json::{Value, json};

#[test]
fn operations_preflight_accepts_production_ready_receipt() {
    let value = production_preflight();
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_operations_preflight(&value, &mut checks, &mut failures);

    assert!(failures.is_empty());
    assert!(checks.contains(&"production preflight is ready".to_owned()));
}

#[test]
fn operations_preflight_rejects_failed_email_queue() {
    let mut value = production_preflight();
    value["email_delivery"]["queue"]["failed"] = json!(2);
    value["openid_conformance"]["issuer_https_origin_ready"] = json!(false);
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_operations_preflight(&value, &mut checks, &mut failures);

    assert!(
        failures
            .iter()
            .any(|failure| { failure == "email_delivery.queue.failed must be 0, got 2" })
    );
    assert!(failures.iter().any(|failure| {
        failure == "openid_conformance.issuer_https_origin_ready must be true, got false"
    }));
}

#[test]
fn dependency_policy_accepts_complete_token_free_receipt() {
    let value = dependency_policy_check();
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_dependency_policy_check(&value, &mut checks, &mut failures);

    assert!(failures.is_empty());
    assert!(
        checks.contains(
            &"dependency policy checks passed without archived command output".to_owned()
        )
    );
}

#[test]
fn dependency_policy_rejects_archived_output_and_missing_bun_audit_check() {
    let mut value = dependency_policy_check();
    value["checks"] = json!([
        dependency_policy_tool_check("cargo_deny", "cargo deny check"),
        {
            "name": "cargo_audit",
            "command": "cargo audit",
            "status": "failed",
            "exit_code": 1,
            "tool_version": "cargo-audit 0.21.0",
            "stdout": "full audit output must not be archived",
            "stdout_bytes": 12,
            "stderr_bytes": 34
        }
    ]);
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_dependency_policy_check(&value, &mut checks, &mut failures);

    assert!(
        failures
            .iter()
            .any(|failure| { failure.contains("$.checks[1].stdout must not be present") })
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure == "checks[cargo_audit].status must be passed, got failed")
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure == "checks must include bun_audit")
    );
}

fn production_preflight() -> Value {
    json!({
        "status": "ok",
        "environment": "production",
        "database": {
            "applied_migrations": 42
        },
        "signing": {
            "database_active_key_decryptable": true,
            "active_jwks_count": 1,
            "lifecycle": {
                "active_key_count": 1
            }
        },
        "email_delivery": {
            "production_ready": true,
            "queue": {
                "failed": 0
            }
        },
        "openid_conformance": {
            "issuer_https_origin_ready": true,
            "static_client_environment_ready": true
        },
        "failures": []
    })
}

fn dependency_policy_check() -> Value {
    json!({
        "status": "ok",
        "completed_at": "2026-06-07T12:00:00Z",
        "workspace": {
            "cargo_lock_present": true,
            "bun_lock_present": true,
            "package_json_present": true,
            "deny_toml_present": true,
            "cargo_audit_config_present": true,
            "dependency_docs_present": true
        },
        "checks": [
            dependency_policy_tool_check("cargo_deny", "cargo deny check"),
            dependency_policy_tool_check("cargo_audit", "cargo audit"),
            dependency_policy_tool_check("bun_audit", "bun run audit")
        ],
        "failures": []
    })
}

fn dependency_policy_tool_check(name: &str, command: &str) -> Value {
    json!({
        "name": name,
        "command": command,
        "status": "passed",
        "exit_code": 0,
        "tool_version": format!("{name} 1.0.0"),
        "stdout_bytes": 123,
        "stderr_bytes": 0
    })
}
