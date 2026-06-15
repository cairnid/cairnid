use serde_json::{Value, json};

pub(in crate::http::scim_metadata) fn scim_schema_attribute(
    name: &str,
    value_type: &str,
    required: bool,
    case_exact: bool,
    uniqueness: &str,
    description: &str,
) -> Value {
    json!({
        "name": name,
        "type": value_type,
        "multiValued": false,
        "description": description,
        "required": required,
        "caseExact": case_exact,
        "mutability": "readWrite",
        "returned": "default",
        "uniqueness": uniqueness
    })
}
