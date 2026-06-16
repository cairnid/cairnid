use super::common::{
    require_openid_certification_url_at_path, require_openid_plan_name,
    validate_openid_finished_status_result,
};
use crate::operations_evidence::validation::{
    require_non_empty_string_at_path_dynamic, require_openid_export_timestamp_at_path,
    value_at_path,
};
use serde_json::Value;

pub(super) fn validate_openid_plan_export(
    value: &Value,
    profile_name: &'static str,
    expected_plan_name: &'static str,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    require_openid_plan_name(value, expected_plan_name, failures);
    if require_openid_export_timestamp_at_path(value, &["exportedAt"], "exportedAt", failures) {
        checks.push("OpenID conformance plan export timestamp is valid".to_owned());
    }
    require_openid_certification_url_at_path(value, &["exportedFrom"], "exportedFrom", failures);

    validate_plan_modules(value, checks, failures);
    validate_test_log_exports(value, failures);

    if failures.is_empty() {
        checks.push(format!(
            "{profile_name} OpenID conformance plan export passed"
        ));
    }
}

fn validate_plan_modules(value: &Value, checks: &mut Vec<String>, failures: &mut Vec<String>) {
    if let Some(modules) = value_at_path(value, &["planInfo", "modules"]).and_then(Value::as_array)
    {
        let mut modules_with_instances = 0_usize;
        for (index, module) in modules.iter().enumerate() {
            match module.get("instances").and_then(Value::as_array) {
                Some(instances) if !instances.is_empty() => modules_with_instances += 1,
                Some(_) | None => failures.push(format!(
                    "planInfo.modules[{index}].instances must include a completed test instance"
                )),
            }
        }
        if modules_with_instances > 0 {
            checks.push("OpenID conformance plan lists completed module instances".to_owned());
        }
    }
}

fn validate_test_log_exports(value: &Value, failures: &mut Vec<String>) {
    let Some(test_exports) = value.get("testLogExports").and_then(Value::as_array) else {
        failures.push("testLogExports must be a non-empty array".to_owned());
        return;
    };
    if test_exports.is_empty() {
        failures.push("testLogExports must be a non-empty array".to_owned());
        return;
    }

    for (index, test_export) in test_exports.iter().enumerate() {
        validate_test_export(index, test_export, failures);
    }
}

fn validate_test_export(index: usize, test_export: &Value, failures: &mut Vec<String>) {
    let path = format!("testLogExports[{index}]");
    require_non_empty_string_at_path_dynamic(test_export, &path, &["testId"], failures);
    require_non_empty_string_at_path_dynamic(test_export, &path, &["testModuleName"], failures);
    let Some(export) = test_export.get("export") else {
        failures.push(format!("{path}.export must be present"));
        return;
    };
    require_openid_export_timestamp_at_path(
        export,
        &["exportedAt"],
        &format!("{path}.export.exportedAt"),
        failures,
    );
    require_openid_certification_url_at_path(
        export,
        &["exportedFrom"],
        &format!("{path}.export.exportedFrom"),
        failures,
    );
    validate_openid_finished_status_result(export, &format!("{path}.export"), failures);
}
