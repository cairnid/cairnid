use serde_json::{Value, json};

use super::super::{
    AppState,
    scim_protocol::{SCIM_GROUP_SCHEMA, SCIM_SCHEMA_SCHEMA, SCIM_USER_SCHEMA, scim_location},
};
use super::attributes::scim_schema_attribute;

pub(in crate::http) fn scim_user_schema_resource(state: &AppState) -> Value {
    json!({
        "schemas": [SCIM_SCHEMA_SCHEMA],
        "id": SCIM_USER_SCHEMA,
        "name": "User",
        "description": "Cairn Identity SCIM user subset",
        "attributes": [
            scim_schema_attribute("userName", "string", true, true, "server", "User login identifier; mapped to normalized email."),
            scim_schema_attribute("externalId", "string", false, false, "server", "Provisioning client's stable external identifier."),
            scim_schema_attribute("displayName", "string", false, false, "none", "Display name shown in Cairn Identity."),
            scim_schema_attribute("active", "boolean", false, false, "none", "Whether the account is active for runtime access."),
            json!({
                "name": "name",
                "type": "complex",
                "multiValued": false,
                "description": "Structured display name subset.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
                "subAttributes": [
                    scim_schema_attribute("formatted", "string", false, false, "none", "Formatted display name."),
                    scim_schema_attribute("givenName", "string", false, false, "none", "Accepted for compatibility and folded into displayName when needed."),
                    scim_schema_attribute("familyName", "string", false, false, "none", "Accepted for compatibility and folded into displayName when needed.")
                ]
            }),
            json!({
                "name": "emails",
                "type": "complex",
                "multiValued": true,
                "description": "Email addresses. Cairn Identity stores one primary work email.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
                "subAttributes": [
                    scim_schema_attribute("value", "string", false, false, "none", "Email address value."),
                    scim_schema_attribute("type", "string", false, false, "none", "Email type."),
                    scim_schema_attribute("primary", "boolean", false, false, "none", "Primary email marker.")
                ]
            })
        ],
        "meta": {
            "resourceType": "Schema",
            "location": scim_location(state, &format!("Schemas/{SCIM_USER_SCHEMA}"))
        }
    })
}

pub(in crate::http) fn scim_group_schema_resource(state: &AppState) -> Value {
    json!({
        "schemas": [SCIM_SCHEMA_SCHEMA],
        "id": SCIM_GROUP_SCHEMA,
        "name": "Group",
        "description": "Cairn Identity SCIM group subset with user members only.",
        "attributes": [
            scim_schema_attribute("displayName", "string", true, false, "none", "Human-readable group name."),
            scim_schema_attribute("externalId", "string", false, false, "server", "Provisioning client's stable external identifier."),
            json!({
                "name": "members",
                "type": "complex",
                "multiValued": true,
                "description": "User members. Nested group members are not accepted in this release.",
                "required": false,
                "caseExact": false,
                "mutability": "readWrite",
                "returned": "default",
                "uniqueness": "none",
                "subAttributes": [
                    scim_schema_attribute("value", "string", false, false, "none", "User resource identifier."),
                    scim_schema_attribute("$ref", "reference", false, false, "none", "User resource location."),
                    scim_schema_attribute("display", "string", false, false, "none", "User display name."),
                    scim_schema_attribute("type", "string", false, false, "none", "Member resource type; only User is supported.")
                ]
            })
        ],
        "meta": {
            "resourceType": "Schema",
            "location": scim_location(state, &format!("Schemas/{SCIM_GROUP_SCHEMA}"))
        }
    })
}
