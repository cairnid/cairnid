use super::super::validation::{
    reject_forbidden_dependency_policy_fields, require_bool, require_empty_array,
    require_rfc3339_timestamp, require_string, require_u64_at_path,
};
use serde_json::Value;

#[derive(Debug, Clone, Copy)]
struct RequiredDependencyPolicyCheck {
    name: &'static str,
    command: &'static str,
}

const REQUIRED_DEPENDENCY_POLICY_CHECKS: &[RequiredDependencyPolicyCheck] = &[
    RequiredDependencyPolicyCheck {
        name: "cargo_deny",
        command: "cargo deny check",
    },
    RequiredDependencyPolicyCheck {
        name: "cargo_audit",
        command: "cargo audit",
    },
    RequiredDependencyPolicyCheck {
        name: "bun_audit",
        command: "bun run audit",
    },
];

pub(in crate::operations_evidence) fn validate_dependency_policy_check(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    reject_forbidden_dependency_policy_fields(value, "$", failures);
    require_string(value, "status", "ok", failures);
    require_empty_array(value, "failures", failures);
    require_rfc3339_timestamp(value, "completed_at", "dependency policy", checks, failures);
    require_bool(value, &["workspace", "cargo_lock_present"], true, failures);
    require_bool(value, &["workspace", "bun_lock_present"], true, failures);
    require_bool(
        value,
        &["workspace", "package_json_present"],
        true,
        failures,
    );
    require_bool(value, &["workspace", "deny_toml_present"], true, failures);
    require_bool(
        value,
        &["workspace", "cargo_audit_config_present"],
        true,
        failures,
    );
    require_bool(
        value,
        &["workspace", "dependency_docs_present"],
        true,
        failures,
    );

    let Some(check_reports) = value.get("checks").and_then(Value::as_array) else {
        failures.push("checks must be an array".to_owned());
        return;
    };

    for required in REQUIRED_DEPENDENCY_POLICY_CHECKS {
        let Some(check_report) = check_reports
            .iter()
            .find(|check| check.get("name").and_then(Value::as_str) == Some(required.name))
        else {
            failures.push(format!("checks must include {}", required.name));
            continue;
        };
        validate_dependency_policy_tool_check(check_report, *required, failures);
    }

    if failures.is_empty() {
        checks.push("dependency policy checks passed without archived command output".to_owned());
    }
}

fn validate_dependency_policy_tool_check(
    value: &Value,
    required: RequiredDependencyPolicyCheck,
    failures: &mut Vec<String>,
) {
    let prefix = format!("checks[{}]", required.name);
    match value.get("command").and_then(Value::as_str) {
        Some(command) if command == required.command => {}
        Some(command) => failures.push(format!(
            "{prefix}.command must be {}, got {command}",
            required.command
        )),
        None => failures.push(format!("{prefix}.command must be {}", required.command)),
    }
    match value.get("status").and_then(Value::as_str) {
        Some("passed") => {}
        Some(status) => failures.push(format!("{prefix}.status must be passed, got {status}")),
        None => failures.push(format!("{prefix}.status must be passed")),
    }
    match value.get("exit_code").and_then(Value::as_i64) {
        Some(0) => {}
        Some(exit_code) => failures.push(format!("{prefix}.exit_code must be 0, got {exit_code}")),
        None => failures.push(format!("{prefix}.exit_code must be 0")),
    }
    if value
        .get("tool_version")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        failures.push(format!("{prefix}.tool_version must be a non-empty string"));
    }
    if value.get("failure").is_some() {
        failures.push(format!(
            "{prefix}.failure must be absent on passed evidence"
        ));
    }
    require_u64_at_path(value, &["stdout_bytes"], failures);
    require_u64_at_path(value, &["stderr_bytes"], failures);
}
