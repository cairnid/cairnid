use serde_json::{Value, json};

use super::super::{
    AppState,
    scim_protocol::{
        SCIM_GROUP_SCHEMA, SCIM_RESOURCE_TYPE_SCHEMA, SCIM_USER_SCHEMA, scim_location,
    },
};

pub(in crate::http) fn scim_user_resource_type(state: &AppState) -> Value {
    json!({
        "schemas": [SCIM_RESOURCE_TYPE_SCHEMA],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "description": "Cairn Identity user accounts",
        "schema": SCIM_USER_SCHEMA,
        "schemaExtensions": [],
        "meta": {
            "resourceType": "ResourceType",
            "location": scim_location(state, "ResourceTypes/User")
        }
    })
}

pub(in crate::http) fn scim_group_resource_type(state: &AppState) -> Value {
    json!({
        "schemas": [SCIM_RESOURCE_TYPE_SCHEMA],
        "id": "Group",
        "name": "Group",
        "endpoint": "/Groups",
        "description": "Cairn Identity groups with user members",
        "schema": SCIM_GROUP_SCHEMA,
        "schemaExtensions": [],
        "meta": {
            "resourceType": "ResourceType",
            "location": scim_location(state, "ResourceTypes/Group")
        }
    })
}
