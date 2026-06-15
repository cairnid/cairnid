use super::super::validation::{
    reject_non_empty_array, require_bool, require_https_origin_at_path, require_i64_at_least,
    require_i64_exact, require_non_empty_string_at_path_dynamic, require_rfc3339_timestamp,
    require_string, require_string_at_path,
};
use serde_json::Value;

pub(super) fn validate(value: &Value, checks: &mut Vec<String>, failures: &mut Vec<String>) {
    require_string(value, "status", "ok", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_https_origin_at_path(value, &["base_url"], failures);
    require_https_origin_at_path(value, &["hostile_origin"], failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "browser-origin smoke",
        checks,
        failures,
    );
    require_i64_at_least(value, &["routes_checked"], 1, failures);

    let Some(checks_value) = value.get("checks").and_then(Value::as_array) else {
        failures.push("checks must be a non-empty array".to_owned());
        return;
    };
    if checks_value.is_empty() {
        failures.push("checks must be a non-empty array".to_owned());
        return;
    }
    if value
        .get("routes_checked")
        .and_then(Value::as_u64)
        .is_some_and(|routes_checked| routes_checked as usize != checks_value.len())
    {
        failures.push("routes_checked must match checks length".to_owned());
    }

    for (index, check) in checks_value.iter().enumerate() {
        let path = format!("checks[{index}]");
        require_non_empty_string_at_path_dynamic(check, &path, &["name"], failures);
        require_string_at_path(check, &["status"], "passed", failures);
        match check.get("method").and_then(Value::as_str) {
            Some("POST" | "PUT" | "PATCH" | "DELETE") => {}
            Some(method) => failures.push(format!(
                "{path}.method must be POST, PUT, PATCH, or DELETE, got {method}"
            )),
            None => failures.push(format!("{path}.method must be POST, PUT, PATCH, or DELETE")),
        }
        match check.get("path").and_then(Value::as_str) {
            Some(path_value) if path_value.starts_with("/api/v1/") => {}
            Some(path_value) => failures.push(format!(
                "{path}.path must be a /api/v1/ route, got {path_value}"
            )),
            None => failures.push(format!("{path}.path must be a /api/v1/ route")),
        }
        require_i64_exact(check, &["origin_status"], 403, failures);
        require_i64_exact(check, &["referer_status"], 403, failures);
        require_bool(check, &["no_store"], true, failures);
        require_bool(check, &["pragma_no_cache"], true, failures);
        require_bool(check, &["content_type_options_nosniff"], true, failures);
    }

    if failures.is_empty() {
        checks.push("browser-origin smoke rejected hostile Origin and Referer".to_owned());
        checks.push("browser-origin smoke covered mutating /api/v1 route classes".to_owned());
    }
}
