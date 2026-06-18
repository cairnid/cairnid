use super::common::{
    require_openid_certification_url_at_path, require_openid_plan_name,
    validate_openid_finished_status_result,
};
use crate::operations_evidence::validation::{
    require_non_empty_string_at_path_dynamic, require_openid_export_timestamp_at_path,
    value_at_path,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

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

    let expected_logs = validate_plan_modules(value, checks, failures);
    validate_test_log_exports(value, expected_logs.as_ref(), failures);

    if failures.is_empty() {
        checks.push(format!(
            "{profile_name} OpenID conformance plan export passed"
        ));
    }
}

fn validate_plan_modules(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) -> Option<BTreeMap<String, String>> {
    let Some(modules) = value_at_path(value, &["planInfo", "modules"]).and_then(Value::as_array)
    else {
        failures.push("planInfo.modules must be a non-empty array".to_owned());
        return None;
    };
    if modules.is_empty() {
        failures.push("planInfo.modules must be a non-empty array".to_owned());
        return None;
    }
    let mut expected_logs = BTreeMap::new();
    for (index, module) in modules.iter().enumerate() {
        let module_name = module
            .get("testModule")
            .or_else(|| module.get("testModuleName"))
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty());
        let instances = module.get("instances").and_then(Value::as_array);
        match (module_name, instances) {
            (Some(module_name), Some(instances)) if !instances.is_empty() => {
                let Some(latest_instance) = instances
                    .iter()
                    .rev()
                    .find_map(Value::as_str)
                    .filter(|instance| !instance.trim().is_empty())
                else {
                    failures.push(format!(
                        "planInfo.modules[{index}].instances must include a completed test instance"
                    ));
                    continue;
                };
                expected_logs.insert(latest_instance.to_owned(), module_name.to_owned());
            }
            (_, Some(_)) | (_, None) => failures.push(format!(
                "planInfo.modules[{index}].instances must include a completed test instance"
            )),
        }
    }
    if expected_logs.is_empty() {
        failures.push("planInfo.modules must include completed module instances".to_owned());
        return None;
    }
    checks.push("OpenID conformance plan lists completed module instances".to_owned());
    Some(expected_logs)
}

fn validate_test_log_exports(
    value: &Value,
    expected_logs: Option<&BTreeMap<String, String>>,
    failures: &mut Vec<String>,
) {
    let Some(test_exports) = value.get("testLogExports").and_then(Value::as_array) else {
        failures.push("testLogExports must be a non-empty array".to_owned());
        return;
    };
    if test_exports.is_empty() {
        failures.push("testLogExports must be a non-empty array".to_owned());
        return;
    }

    let mut seen_logs = BTreeSet::new();
    for (index, test_export) in test_exports.iter().enumerate() {
        validate_test_export(index, test_export, expected_logs, &mut seen_logs, failures);
    }
    if let Some(expected_logs) = expected_logs {
        for (test_id, module_name) in expected_logs {
            if !seen_logs.contains(test_id) {
                failures.push(format!(
                    "testLogExports must include module {module_name} instance {test_id}"
                ));
            }
        }
    }
}

fn validate_test_export(
    index: usize,
    test_export: &Value,
    expected_logs: Option<&BTreeMap<String, String>>,
    seen_logs: &mut BTreeSet<String>,
    failures: &mut Vec<String>,
) {
    let path = format!("testLogExports[{index}]");
    require_non_empty_string_at_path_dynamic(test_export, &path, &["testId"], failures);
    require_non_empty_string_at_path_dynamic(test_export, &path, &["testModuleName"], failures);
    let test_id = test_export
        .get("testId")
        .and_then(Value::as_str)
        .filter(|test_id| !test_id.trim().is_empty());
    let module_name = test_export
        .get("testModuleName")
        .and_then(Value::as_str)
        .filter(|module_name| !module_name.trim().is_empty());
    if let (Some(expected_logs), Some(test_id), Some(module_name)) =
        (expected_logs, test_id, module_name)
    {
        match expected_logs.get(test_id) {
            Some(expected_module) if expected_module == module_name => {
                if !seen_logs.insert(test_id.to_owned()) {
                    failures.push(format!("{path}.testId duplicates module instance {test_id}"));
                }
            }
            Some(expected_module) => failures.push(format!(
                "{path}.testModuleName must be {expected_module} for module instance {test_id}, got {module_name}"
            )),
            None => failures.push(format!(
                "{path}.testId must match a planInfo.modules instance, got {test_id}"
            )),
        }
    }
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
