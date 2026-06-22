use super::super::validation::{
    reject_non_empty_array, require_bool, require_https_origin_at_path, require_i64_exact,
    require_rfc3339_timestamp, require_string, require_string_at_path,
};
use serde_json::Value;

// Mirrors apps/api/src/security_header_smoke/targets.rs for release evidence validation.
const EXPECTED_SECURITY_HEADER_TARGETS: [(&str, &str); 4] = [
    ("api", "/healthz"),
    ("api", "/.well-known/openid-configuration"),
    ("web", "/healthz"),
    ("web", "/login"),
];

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

    let mut seen_targets = Vec::new();
    let mut covered_expected_targets = Vec::new();
    for (index, check) in checks_value.iter().enumerate() {
        let path = format!("checks[{index}]");
        let service_value = check.get("service").and_then(Value::as_str);
        let service_is_valid = match service_value {
            Some("api" | "web") => true,
            Some(service) => {
                failures.push(format!("{path}.service must be api or web, got {service}"));
                false
            }
            None => {
                failures.push(format!("{path}.service must be api or web"));
                false
            }
        };
        let path_value = check.get("path").and_then(Value::as_str);
        let path_is_valid = match path_value {
            Some(path_value) if path_value.starts_with('/') => true,
            Some(path_value) => {
                failures.push(format!("{path}.path must start with /, got {path_value}"));
                false
            }
            None => {
                failures.push(format!("{path}.path must start with /"));
                false
            }
        };
        if let (Some(service), Some(target_path)) = (service_value, path_value) {
            if let Some((_, _, first_index)) =
                seen_targets.iter().find(|(seen_service, seen_path, _)| {
                    *seen_service == service && *seen_path == target_path
                })
            {
                failures.push(format!(
                    "{path} duplicates checks[{first_index}] for {service} {target_path}"
                ));
            } else {
                seen_targets.push((service, target_path, index));
            }

            if service_is_valid && path_is_valid {
                if is_expected_security_header_target(service, target_path) {
                    if !covered_expected_targets
                        .iter()
                        .any(|(covered_service, covered_path)| {
                            *covered_service == service && *covered_path == target_path
                        })
                    {
                        covered_expected_targets.push((service, target_path));
                    }
                } else {
                    failures.push(format!(
                        "{path} must target one of the deployed security-header smoke paths, got {service} {target_path}"
                    ));
                }
            }
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

    for (service, target_path) in EXPECTED_SECURITY_HEADER_TARGETS {
        if !covered_expected_targets
            .iter()
            .any(|(covered_service, covered_path)| {
                *covered_service == service && *covered_path == target_path
            })
        {
            failures.push(format!(
                "checks must include deployed security-header check for {service} {target_path}"
            ));
        }
    }

    if failures.is_empty() {
        checks.push("API and web security headers passed deployed smoke".to_owned());
    }
}

fn is_expected_security_header_target(service: &str, target_path: &str) -> bool {
    EXPECTED_SECURITY_HEADER_TARGETS
        .iter()
        .any(|(expected_service, expected_path)| {
            *expected_service == service && *expected_path == target_path
        })
}
