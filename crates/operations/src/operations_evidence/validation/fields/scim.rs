use serde_json::Value;

pub(in crate::operations_evidence) fn require_scim_mapping(
    value: &Value,
    resource: &'static str,
    scim_attribute: &'static str,
    failures: &mut Vec<String>,
) {
    let Some(mappings) = value.get("recommended_mappings").and_then(Value::as_array) else {
        failures.push("recommended_mappings must be an array".to_owned());
        return;
    };
    if !mappings.iter().any(|mapping| {
        mapping.get("resource").and_then(Value::as_str) == Some(resource)
            && mapping.get("scim_attribute").and_then(Value::as_str) == Some(scim_attribute)
            && mapping
                .get("connector_attribute")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            && mapping
                .get("note")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
    }) {
        failures.push(format!(
            "recommended_mappings must include {resource} mapping for {scim_attribute}"
        ));
    }
}
