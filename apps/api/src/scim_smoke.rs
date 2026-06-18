mod bulk;
mod checks;
mod groups;
mod helpers;
mod http;
mod runner;
mod types;
mod users;

pub use self::types::{ScimSmokeCheck, ScimSmokeError, ScimSmokeInputs, ScimSmokeReport};

pub(in crate::scim_smoke) use self::checks::*;
pub(in crate::scim_smoke) use self::runner::ScimSmokeRun;

const SCIM_CONTENT_TYPE: &str = "application/scim+json";
const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const SCIM_PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SCIM_SEARCH_REQUEST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
const SCIM_BULK_REQUEST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
const SCIM_BULK_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";

pub async fn run_scim_smoke_from_env() -> Result<ScimSmokeReport, ScimSmokeError> {
    runner::run_scim_smoke_from_env().await
}
