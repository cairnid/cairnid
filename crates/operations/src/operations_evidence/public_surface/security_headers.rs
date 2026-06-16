use super::super::validation::{
    reject_non_empty_array, require_bool, require_https_origin_at_path, require_i64_exact,
    require_rfc3339_timestamp, require_string, require_string_at_path,
};
use serde_json::Value;

pub(super) fn validate(value: &Value, checks: &mut Vec<String>, failures: &mut Vec<String>) {
    require_string(value, "status", "ok", failures);
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    require_https_origin_at_path(value, &["api_base_url"], failures);
    require_https_origin_at_path(value, &["web_base_url"], failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "security-header smoke",
        checks,
        failures,
    );

    let Some(checks_value) = value.get("checks").and_then(Value::as_array) else {
        failures.push("checks must be a non-empty array".to_owned());
        return;
    };
    if checks_value.is_empty() {
        failures.push("checks must be a non-empty array".to_owned());
        return;
    }

    let mut saw_api = false;
    let mut saw_web = false;
    for (index, check) in checks_value.iter().enumerate() {
        let path = format!("checks[{index}]");
        match check.get("service").and_then(Value::as_str) {
            Some("api") => saw_api = true,
            Some("web") => saw_web = true,
            Some(service) => {
                failures.push(format!("{path}.service must be api or web, got {service}"))
            }
            None => failures.push(format!("{path}.service must be api or web")),
        }
        match check.get("path").and_then(Value::as_str) {
            Some(path_value) if path_value.starts_with('/') => {}
            Some(path_value) => {
                failures.push(format!("{path}.path must start with /, got {path_value}"))
            }
            None => failures.push(format!("{path}.path must start with /")),
        }
        require_string_at_path(check, &["status"], "passed", failures);
        require_i64_exact(check, &["status_code"], 200, failures);
        require_bool(check, &["content_security_policy"], true, failures);
        require_bool(check, &["strict_transport_security"], true, failures);
        require_bool(check, &["x_content_type_options_nosniff"], true, failures);
        require_bool(check, &["x_frame_options_deny"], true, failures);
        require_bool(check, &["referrer_policy_no_referrer"], true, failures);
        require_bool(check, &["permissions_policy_restrictive"], true, failures);
        require_bool(
            check,
            &["cross_origin_opener_policy_same_origin"],
            true,
            failures,
        );
        if matches!(
            check.get("cache_control_no_store"),
            Some(value) if !value.is_null() && value.as_bool() != Some(true)
        ) {
            failures.push(format!(
                "{path}.cache_control_no_store must be true or null when present"
            ));
        }
    }
    if !saw_api {
        failures.push("checks must include an api service response".to_owned());
    }
    if !saw_web {
        failures.push("checks must include a web service response".to_owned());
    }

    if failures.is_empty() {
        checks.push("API and web security headers passed deployed smoke".to_owned());
    }
}
