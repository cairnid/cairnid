use serde::Deserialize;
use serde_json::Value;

use super::super::scim_protocol::{SCIM_PATCH_MAX_OPERATIONS, SCIM_PATCH_OP_SCHEMA, ScimError};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::http) struct ScimPatchRequest {
    #[serde(default)]
    pub(super) schemas: Vec<String>,
    #[serde(rename = "Operations", default)]
    pub(super) operations: Vec<ScimPatchOperation>,
}

impl ScimPatchRequest {
    pub(in crate::http) fn operation_count(&self) -> usize {
        self.operations.len()
    }

    pub(super) fn into_validated_operations(self) -> Result<Vec<ScimPatchOperation>, ScimError> {
        self.validate()?;
        Ok(self.operations)
    }

    fn validate(&self) -> Result<(), ScimError> {
        if !self
            .schemas
            .iter()
            .any(|schema| schema == SCIM_PATCH_OP_SCHEMA)
        {
            return Err(ScimError::invalid_value(
                "SCIM PATCH request must include PatchOp schema",
            ));
        }
        if self.operations.is_empty() {
            return Err(ScimError::invalid_value(
                "SCIM PATCH request must include at least one operation",
            ));
        }
        if self.operations.len() > SCIM_PATCH_MAX_OPERATIONS {
            return Err(ScimError::invalid_value("too many SCIM PATCH operations"));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScimPatchOperation {
    pub(super) op: String,
    #[serde(default)]
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) value: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScimPatchOp {
    Add,
    Replace,
    Remove,
}

impl ScimPatchOp {
    pub(super) fn parse(value: &str) -> Result<Self, ScimError> {
        if value.eq_ignore_ascii_case("add") {
            Ok(Self::Add)
        } else if value.eq_ignore_ascii_case("replace") {
            Ok(Self::Replace)
        } else if value.eq_ignore_ascii_case("remove") {
            Ok(Self::Remove)
        } else {
            Err(ScimError::invalid_value("unsupported SCIM PATCH op"))
        }
    }
}
