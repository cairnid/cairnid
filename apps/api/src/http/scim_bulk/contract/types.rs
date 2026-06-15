use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::http) struct ScimBulkRequest {
    #[serde(default)]
    pub(in crate::http::scim_bulk) schemas: Vec<String>,
    #[serde(default)]
    pub(in crate::http::scim_bulk) fail_on_errors: Option<usize>,
    #[serde(rename = "Operations", default)]
    pub(in crate::http::scim_bulk) operations: Vec<ScimBulkOperationRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::http::scim_bulk) struct ScimBulkOperationRequest {
    pub(in crate::http::scim_bulk) method: String,
    #[serde(default)]
    pub(in crate::http::scim_bulk) bulk_id: Option<String>,
    pub(in crate::http::scim_bulk) path: String,
    #[serde(default)]
    pub(in crate::http::scim_bulk) data: Option<Value>,
}

#[derive(Debug)]
pub(in crate::http::scim_bulk) struct ScimBulkJobOperation {
    pub(in crate::http::scim_bulk) method: String,
    pub(in crate::http::scim_bulk) bulk_id: Option<String>,
    pub(in crate::http::scim_bulk) operation: ScimBulkOperationRequest,
}
