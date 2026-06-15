use serde_json::Value;

pub(in crate::operations_evidence) fn reject_non_empty_array(
    value: &Value,
    field: &'static str,
    failures: &mut Vec<String>,
) {
    if value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty())
    {
        failures.push(format!("{field} must be empty or absent"));
    }
}

pub(in crate::operations_evidence) fn reject_true_bool(
    value: &Value,
    field: &'static str,
    failures: &mut Vec<String>,
) {
    if value
        .get(field)
        .and_then(Value::as_bool)
        .is_some_and(|value| value)
    {
        failures.push(format!("{field} must be false or absent"));
    }
}
