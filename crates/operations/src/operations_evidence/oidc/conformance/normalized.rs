use super::common::{
    OIDF_EXPORT_NORMALIZER, OIDF_EXPORT_PROVENANCE_SCHEMA, require_openid_certification_url,
    require_openid_plan_name, validate_openid_finished_status_result,
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

    validate_oidf_export_provenance(value, checks, failures);

    if failures.is_empty() {
        checks.push(format!("{profile_name} OpenID conformance result passed"));
    }
}

fn validate_oidf_export_provenance(
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    let failure_count = failures.len();
    let Some(provenance) = value.get("oidf_export_provenance") else {
        failures.push(
            "oidf_export_provenance must be present and emitted by oidcc-normalize-export"
                .to_owned(),
        );
        return;
    };

    require_string_field(
        provenance,
        "schema",
        OIDF_EXPORT_PROVENANCE_SCHEMA,
        "oidf_export_provenance.schema",
        failures,
    );
    require_string_field(
        provenance,
        "normalizer",
        OIDF_EXPORT_NORMALIZER,
        "oidf_export_provenance.normalizer",
        failures,
    );

    match provenance.get("source_format").and_then(Value::as_str) {
        Some("zip" | "directory") => {}
        Some(source_format) => failures.push(format!(
            "oidf_export_provenance.source_format must be zip or directory, got {source_format}"
        )),
        None => failures
            .push("oidf_export_provenance.source_format must be zip or directory".to_owned()),
    }

    match provenance.get("exported_from").and_then(Value::as_str) {
        Some(exported_from) => require_openid_certification_url(
            "oidf_export_provenance.exported_from",
            exported_from,
            failures,
        ),
        None => failures.push(
            "oidf_export_provenance.exported_from must be an OpenID certification HTTPS URL"
                .to_owned(),
        ),
    }

    require_non_empty_string(
        provenance,
        "suite_version",
        "oidf_export_provenance.suite_version",
        failures,
    );

    let plan_module_count = require_positive_usize(
        provenance,
        "plan_module_count",
        "oidf_export_provenance.plan_module_count",
        failures,
    );
    let test_log_count = require_positive_usize(
        provenance,
        "test_log_count",
        "oidf_export_provenance.test_log_count",
        failures,
    );
    if let (Some(plan_module_count), Some(test_log_count)) = (plan_module_count, test_log_count)
        && test_log_count != plan_module_count
    {
        failures.push(format!(
            "oidf_export_provenance.test_log_count must match plan_module_count, got {test_log_count}"
        ));
    }

    let module_names = validate_module_names(provenance, plan_module_count, failures);
    validate_selected_instances(
        provenance,
        plan_module_count,
        module_names.as_deref(),
        failures,
    );
    require_sha256_hex(
        provenance,
        "plan_modules_sha256",
        "oidf_export_provenance.plan_modules_sha256",
        failures,
    );
    require_sha256_hex(
        provenance,
        "test_logs_sha256",
        "oidf_export_provenance.test_logs_sha256",
        failures,
    );

    if failures.len() == failure_count {
        checks.push("OpenID conformance result includes OIDF export provenance".to_owned());
    }
}

fn require_string_field(
    value: &Value,
    key: &str,
    expected: &str,
    label: &str,
    failures: &mut Vec<String>,
) {
    match value.get(key).and_then(Value::as_str) {
        Some(actual) if actual == expected => {}
        Some(actual) => failures.push(format!("{label} must be {expected}, got {actual}")),
        None => failures.push(format!("{label} must be {expected}")),
    }
}

fn require_non_empty_string(value: &Value, key: &str, label: &str, failures: &mut Vec<String>) {
    match value.get(key).and_then(Value::as_str) {
        Some(actual) if !actual.trim().is_empty() => {}
        Some(_) | None => failures.push(format!("{label} must be a non-empty string")),
    }
}

fn require_positive_usize(
    value: &Value,
    key: &str,
    label: &str,
    failures: &mut Vec<String>,
) -> Option<usize> {
    match value.get(key).and_then(Value::as_u64) {
        Some(count) if count > 0 => match usize::try_from(count) {
            Ok(count) => Some(count),
            Err(_) => {
                failures.push(format!("{label} is too large"));
                None
            }
        },
        Some(_) | None => {
            failures.push(format!("{label} must be a positive integer"));
            None
        }
    }
}

fn validate_module_names(
    provenance: &Value,
    plan_module_count: Option<usize>,
    failures: &mut Vec<String>,
) -> Option<Vec<String>> {
    let Some(module_names) = provenance.get("module_names").and_then(Value::as_array) else {
        failures.push("oidf_export_provenance.module_names must be a non-empty array".to_owned());
        return None;
    };
    if module_names.is_empty() {
        failures.push("oidf_export_provenance.module_names must be a non-empty array".to_owned());
        return None;
    }
    if let Some(plan_module_count) = plan_module_count
        && module_names.len() != plan_module_count
    {
        failures.push(format!(
            "oidf_export_provenance.module_names length must match plan_module_count, got {}",
            module_names.len()
        ));
    }

    let mut previous = None;
    let mut names = Vec::new();
    for (index, module_name) in module_names.iter().enumerate() {
        let Some(module_name) = module_name
            .as_str()
            .map(str::trim)
            .filter(|module_name| !module_name.is_empty())
        else {
            failures.push(format!(
                "oidf_export_provenance.module_names[{index}] must be a non-empty string"
            ));
            continue;
        };
        if let Some(previous) = previous
            && previous > module_name
        {
            failures.push("oidf_export_provenance.module_names must be sorted".to_owned());
            break;
        }
        names.push(module_name.to_owned());
        previous = Some(module_name);
    }
    Some(names)
}

fn validate_selected_instances(
    provenance: &Value,
    plan_module_count: Option<usize>,
    module_names: Option<&[String]>,
    failures: &mut Vec<String>,
) {
    let Some(instances) = provenance
        .get("selected_instances")
        .and_then(Value::as_array)
    else {
        failures
            .push("oidf_export_provenance.selected_instances must be a non-empty array".to_owned());
        return;
    };
    if instances.is_empty() {
        failures
            .push("oidf_export_provenance.selected_instances must be a non-empty array".to_owned());
        return;
    }
    if let Some(plan_module_count) = plan_module_count
        && instances.len() != plan_module_count
    {
        failures.push(format!(
            "oidf_export_provenance.selected_instances length must match plan_module_count, got {}",
            instances.len()
        ));
    }

    let mut selected_module_names = Vec::new();
    let mut previous = None;
    for (index, instance) in instances.iter().enumerate() {
        let Some(module_name) = instance
            .get("module_name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|module_name| !module_name.is_empty())
        else {
            failures.push(format!(
                "oidf_export_provenance.selected_instances[{index}].module_name must be a non-empty string"
            ));
            continue;
        };
        let Some(test_id) = instance
            .get("test_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|test_id| !test_id.is_empty())
        else {
            failures.push(format!(
                "oidf_export_provenance.selected_instances[{index}].test_id must be a non-empty string"
            ));
            continue;
        };
        let current = (module_name, test_id);
        if let Some(previous) = previous
            && previous > current
        {
            failures.push("oidf_export_provenance.selected_instances must be sorted".to_owned());
            break;
        }
        selected_module_names.push(module_name.to_owned());
        previous = Some(current);
    }

    if let Some(module_names) = module_names
        && selected_module_names != module_names
    {
        failures.push(
            "oidf_export_provenance.selected_instances module_name values must match module_names"
                .to_owned(),
        );
    }
}

fn require_sha256_hex(value: &Value, key: &str, label: &str, failures: &mut Vec<String>) {
    match value.get(key).and_then(Value::as_str) {
        Some(hash)
            if hash.len() == 64 && hash.chars().all(|character| character.is_ascii_hexdigit()) => {}
        Some(_) | None => {
            failures.push(format!("{label} must be a 64-character SHA-256 hex digest"))
        }
    }
}
