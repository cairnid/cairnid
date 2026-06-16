use super::common::{
    require_openid_certification_url, require_openid_plan_name,
    validate_openid_finished_status_result,
};
use crate::operations_evidence::validation::require_rfc3339_timestamp;
use serde_json::Value;

pub(super) fn validate_openid_normalized_result(
    value: &Value,
    profile_name: &'static str,
    expected_plan_name: &'static str,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    match value.get("source").and_then(Value::as_str) {
        Some(
            "openid-conformance-suite"
            | "OpenID Foundation conformance suite"
            | "oidf-conformance-suite",
        ) => {
            checks.push("OpenID conformance result identifies suite source".to_owned());
        }
        Some(source) => failures.push(format!(
            "source must be openid-conformance-suite, got {source}"
        )),
        None => failures.push("source must be openid-conformance-suite".to_owned()),
    }
    require_openid_plan_name(value, expected_plan_name, failures);
    require_rfc3339_timestamp(
        value,
        "completed_at",
        "OpenID conformance result",
        checks,
        failures,
    );
    validate_openid_finished_status_result(value, "OpenID conformance result", failures);

    match value
        .get("certification_profile")
        .or_else(|| value.get("profile"))
        .and_then(Value::as_str)
    {
        Some(actual_profile) if actual_profile != profile_name => failures.push(format!(
            "certification_profile must be {profile_name}, got {actual_profile}"
        )),
        Some(_) | None => {}
    }

    match value
        .get("published_result_url")
        .or_else(|| value.get("result_url"))
        .or_else(|| value.get("url"))
        .and_then(Value::as_str)
    {
        Some(url) => require_openid_certification_url("published_result_url", url, failures),
        None => failures.push(
            "published_result_url must be present for normalized OpenID conformance result"
                .to_owned(),
        ),
    }

    if failures.is_empty() {
        checks.push(format!("{profile_name} OpenID conformance result passed"));
    }
}
