mod common;
mod constants;
mod normalized;
mod plan_export;
mod redaction;

use self::{
    normalized::validate_openid_normalized_result, plan_export::validate_openid_plan_export,
    redaction::reject_forbidden_openid_result_fields,
};
use crate::operations_evidence::validation::{reject_non_empty_array, reject_true_bool};
use serde_json::Value;

pub(in crate::operations_evidence) fn validate_openid_conformance_result(
    value: &Value,
    profile_name: &'static str,
    expected_plan_name: &'static str,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    reject_non_empty_array(value, "failures", failures);
    reject_non_empty_array(value, "errors", failures);
    reject_true_bool(value, "failed", failures);
    reject_forbidden_openid_result_fields(value, "$", failures);

    if value.get("testLogExports").is_some() || value.get("planInfo").is_some() {
        validate_openid_plan_export(value, profile_name, expected_plan_name, checks, failures);
    } else {
        validate_openid_normalized_result(
            value,
            profile_name,
            expected_plan_name,
            checks,
            failures,
        );
    }
}

#[cfg(test)]
mod tests;
