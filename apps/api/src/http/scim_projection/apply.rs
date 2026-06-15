use serde_json::{Value, json};

use super::{paths::ScimProjectionPath, types::ScimProjection};

pub(in crate::http) fn scim_apply_projection(
    resource: Value,
    projection: &ScimProjection,
) -> Value {
    match projection {
        ScimProjection::Default => resource,
        ScimProjection::Include(paths) => scim_include_projection(&resource, paths),
        ScimProjection::Exclude(paths) => scim_exclude_projection(resource, paths),
    }
}

fn scim_include_projection(resource: &Value, paths: &[ScimProjectionPath]) -> Value {
    let mut projected = json!({});
    scim_copy_top_attribute(resource, &mut projected, "schemas");
    scim_copy_top_attribute(resource, &mut projected, "id");

    for path in paths {
        scim_copy_projection_path(resource, &mut projected, path);
    }

    projected
}

fn scim_exclude_projection(mut resource: Value, paths: &[ScimProjectionPath]) -> Value {
    for path in paths {
        scim_remove_projection_path(&mut resource, path);
    }
    resource
}

fn scim_copy_projection_path(source: &Value, target: &mut Value, path: &ScimProjectionPath) {
    if path.is_always_returned() {
        scim_copy_top_attribute(source, target, path.top);
        return;
    }

    let Some(sub_attribute) = path.sub else {
        scim_copy_top_attribute(source, target, path.top);
        return;
    };

    match source.get(path.top) {
        Some(Value::Object(source_object)) => {
            let Some(value) = source_object.get(sub_attribute) else {
                return;
            };
            let target_object = target
                .as_object_mut()
                .expect("SCIM projected resource is a JSON object");
            let entry = target_object
                .entry(path.top.to_owned())
                .or_insert_with(|| json!({}));
            if let Value::Object(target_sub_object) = entry {
                target_sub_object.insert(sub_attribute.to_owned(), value.clone());
            }
        }
        Some(Value::Array(source_array)) => {
            let target_object = target
                .as_object_mut()
                .expect("SCIM projected resource is a JSON object");
            let entry = target_object
                .entry(path.top.to_owned())
                .or_insert_with(|| Value::Array(vec![json!({}); source_array.len()]));
            if let Value::Array(target_array) = entry {
                if target_array.len() != source_array.len() {
                    *target_array = vec![json!({}); source_array.len()];
                }
                for (index, source_item) in source_array.iter().enumerate() {
                    let Some(value) = source_item
                        .as_object()
                        .and_then(|object| object.get(sub_attribute))
                    else {
                        continue;
                    };
                    if let Some(Value::Object(target_item)) = target_array.get_mut(index) {
                        target_item.insert(sub_attribute.to_owned(), value.clone());
                    }
                }
                scim_remove_empty_projected_array(target_object, path.top);
            }
        }
        _ => {}
    }
}

fn scim_copy_top_attribute(source: &Value, target: &mut Value, attribute: &'static str) {
    let Some(value) = source.get(attribute) else {
        return;
    };
    target
        .as_object_mut()
        .expect("SCIM projected resource is a JSON object")
        .insert(attribute.to_owned(), value.clone());
}

fn scim_remove_projection_path(resource: &mut Value, path: &ScimProjectionPath) {
    if path.is_always_returned() {
        return;
    }
    let Some(resource_object) = resource.as_object_mut() else {
        return;
    };

    let Some(sub_attribute) = path.sub else {
        resource_object.remove(path.top);
        return;
    };

    match resource_object.get_mut(path.top) {
        Some(Value::Object(object)) => {
            object.remove(sub_attribute);
            if object.is_empty() {
                resource_object.remove(path.top);
            }
        }
        Some(Value::Array(items)) => {
            for item in items.iter_mut() {
                if let Some(object) = item.as_object_mut() {
                    object.remove(sub_attribute);
                }
            }
            if items
                .iter()
                .all(|item| item.as_object().is_some_and(serde_json::Map::is_empty))
            {
                resource_object.remove(path.top);
            }
        }
        _ => {}
    }
}

fn scim_remove_empty_projected_array(
    target_object: &mut serde_json::Map<String, Value>,
    attribute: &'static str,
) {
    let remove = target_object
        .get(attribute)
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .all(|item| item.as_object().is_some_and(serde_json::Map::is_empty))
        });
    if remove {
        target_object.remove(attribute);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::http::scim_protocol::{SCIM_GROUP_SCHEMA, SCIM_USER_SCHEMA};

    #[test]
    fn include_projection_preserves_required_and_selected_nested_values() {
        let resource = json!({
            "schemas": [SCIM_USER_SCHEMA],
            "id": "user-id",
            "userName": "user@example.com",
            "emails": [
                { "value": "user@example.com", "type": "work", "primary": true }
            ],
            "meta": { "location": "https://id.example.com/scim/v2/Users/user-id" }
        });

        let projected = scim_apply_projection(
            resource,
            &ScimProjection::Include(vec![
                ScimProjectionPath::top("userName"),
                ScimProjectionPath::sub("emails", "value"),
                ScimProjectionPath::sub("meta", "location"),
            ]),
        );

        assert_eq!(projected["schemas"], json!([SCIM_USER_SCHEMA]));
        assert_eq!(projected["id"], json!("user-id"));
        assert_eq!(projected["userName"], json!("user@example.com"));
        assert_eq!(
            projected["emails"],
            json!([{ "value": "user@example.com" }])
        );
        assert_eq!(
            projected["meta"]["location"],
            json!("https://id.example.com/scim/v2/Users/user-id")
        );
    }

    #[test]
    fn exclude_projection_never_removes_required_identifiers() {
        let resource = json!({
            "schemas": [SCIM_GROUP_SCHEMA],
            "id": "group-id",
            "displayName": "Engineering",
            "members": [
                { "value": "user-id", "display": "User", "type": "User" }
            ],
            "meta": { "location": "https://id.example.com/scim/v2/Groups/group-id" }
        });

        let projected = scim_apply_projection(
            resource,
            &ScimProjection::Exclude(vec![
                ScimProjectionPath::top("schemas"),
                ScimProjectionPath::top("id"),
                ScimProjectionPath::sub("members", "display"),
                ScimProjectionPath::sub("members", "type"),
                ScimProjectionPath::top("meta"),
            ]),
        );

        assert_eq!(projected["schemas"], json!([SCIM_GROUP_SCHEMA]));
        assert_eq!(projected["id"], json!("group-id"));
        assert_eq!(projected["members"], json!([{ "value": "user-id" }]));
        assert!(projected.get("meta").is_none());
    }
}
