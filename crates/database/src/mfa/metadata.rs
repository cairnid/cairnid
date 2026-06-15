use serde_json::{Value, json};

pub(super) fn metadata_with_status(mut metadata: Value, status: &str) -> Value {
    match metadata.as_object_mut() {
        Some(object) => {
            object.insert("status".to_owned(), json!(status));
            metadata
        }
        None => json!({ "status": status }),
    }
}
