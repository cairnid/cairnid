mod request;
mod response;
#[cfg(test)]
mod tests;
mod types;

pub(in crate::http::scim_bulk) use self::request::{
    ScimBulkMethod, ScimBulkPath, scim_bulk_data, scim_bulk_expect_no_data, scim_bulk_path,
    scim_required_bulk_id,
};
pub(super) use self::request::{
    scim_bulk_fail_on_errors, scim_bulk_job_operations, validate_scim_bulk_ids,
};
pub(super) use self::response::{
    scim_bulk_error_response, scim_bulk_limit_response, scim_bulk_success_response,
};
pub(super) use self::types::ScimBulkJobOperation;
pub(in crate::http::scim_bulk) use self::types::ScimBulkOperationRequest;
pub(in crate::http) use self::types::ScimBulkRequest;
