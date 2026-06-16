use super::constants::OPENID_CERTIFICATION_HOST;
use crate::operations_evidence::validation::value_at_path;
use serde_json::Value;

pub(super) fn require_openid_plan_name(
    value: &Value,
    expected_plan_name: &'static str,
    failures: &mut Vec<String>,
) {
    match openid_plan_name(value) {
        Some(actual) if actual == expected_plan_name => {}
        Some(actual) => failures.push(format!(
            "plan name must be {expected_plan_name}, got {actual}"
        )),
        None => failures.push(format!("plan name must be {expected_plan_name}")),
    }
}

fn openid_plan_name(value: &Value) -> Option<&str> {
    value
        .get("plan_name")
        .or_else(|| value.get("planName"))
        .or_else(|| value.get("test_plan"))
        .or_else(|| value.get("testPlan"))
        .or_else(|| value_at_path(value, &["plan", "name"]))
        .or_else(|| value_at_path(value, &["plan", "planName"]))
        .or_else(|| value_at_path(value, &["planInfo", "planName"]))
        .or_else(|| value_at_path(value, &["planInfo", "plan_name"]))
        .and_then(Value::as_str)
}

pub(super) fn validate_openid_finished_status_result(
    value: &Value,
    path: &str,
    failures: &mut Vec<String>,
) {
    let Some((status, result)) = openid_status_result(value) else {
        failures.push(format!("{path}.status and {path}.result must be present"));
        return;
    };

    if !status.eq_ignore_ascii_case("FINISHED") {
        failures.push(format!("{path}.status must be FINISHED, got {status}"));
    }

    if !(result.eq_ignore_ascii_case("PASSED") || result.eq_ignore_ascii_case("WARNING")) {
        failures.push(format!(
            "{path}.result must be PASSED or WARNING, got {result}"
        ));
    }
}

fn openid_status_result(value: &Value) -> Option<(&str, &str)> {
    status_result_fields(value)
        .or_else(|| value.get("testInfo").and_then(status_result_fields))
        .or_else(|| value_at_path(value, &["testInfo", "testInfo"]).and_then(status_result_fields))
        .or_else(|| value.get("export").and_then(status_result_fields))
        .or_else(|| value_at_path(value, &["export", "testInfo"]).and_then(status_result_fields))
        .or_else(|| {
            value_at_path(value, &["export", "testInfo", "testInfo"]).and_then(status_result_fields)
        })
}

fn status_result_fields(value: &Value) -> Option<(&str, &str)> {
    let status = value.get("status").and_then(Value::as_str)?;
    let result = value.get("result").and_then(Value::as_str)?;
    Some((status, result))
}

pub(super) fn require_openid_certification_url_at_path(
    value: &Value,
    path: &[&'static str],
    label: &str,
    failures: &mut Vec<String>,
) {
    let Some(url) = value_at_path(value, path).and_then(Value::as_str) else {
        failures.push(format!("{label} must be an OpenID certification HTTPS URL"));
        return;
    };
    require_openid_certification_url(label, url, failures);
}

pub(super) fn require_openid_certification_url(
    label: &str,
    value: &str,
    failures: &mut Vec<String>,
) {
    match url::Url::parse(value) {
        Ok(url)
            if url.scheme() == "https"
                && url.host_str() == Some(OPENID_CERTIFICATION_HOST)
                && url.username().is_empty()
                && url.password().is_none() => {}
        Ok(_) => failures.push(format!(
            "{label} must be an HTTPS URL on {OPENID_CERTIFICATION_HOST} without credentials"
        )),
        Err(_) => failures.push(format!("{label} must be a valid OpenID certification URL")),
    }
}
