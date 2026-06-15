pub(in crate::http) const SCIM_JSON_BODY_MAX_BYTES: usize = 256 * 1024;
pub(in crate::http) const SCIM_QUERY_MAX_BYTES: usize = 2048;
pub(in crate::http) const SCIM_DEFAULT_COUNT: i64 = 100;
pub(in crate::http) const SCIM_MAX_COUNT: i64 = 200;
pub(in crate::http) const SCIM_MAX_START_INDEX: i64 = 10_000;
pub(in crate::http) const SCIM_USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub(in crate::http) const SCIM_GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub(in crate::http) const SCIM_SCHEMA_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";
pub(in crate::http) const SCIM_RESOURCE_TYPE_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ResourceType";
pub(in crate::http) const SCIM_SERVICE_PROVIDER_CONFIG_SCHEMA: &str =
    "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
pub(in crate::http) const SCIM_LIST_RESPONSE_SCHEMA: &str =
    "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub(in crate::http) const SCIM_ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
pub(in crate::http) const SCIM_PATCH_OP_SCHEMA: &str =
    "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub(in crate::http) const SCIM_SEARCH_REQUEST_SCHEMA: &str =
    "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
pub(in crate::http) const SCIM_BULK_REQUEST_SCHEMA: &str =
    "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
pub(in crate::http) const SCIM_BULK_RESPONSE_SCHEMA: &str =
    "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
pub(in crate::http) const SCIM_PATCH_MAX_OPERATIONS: usize = 20;
pub(in crate::http) const SCIM_BULK_MAX_OPERATIONS: usize = 50;
pub(in crate::http) const SCIM_GROUP_MAX_MEMBERS: usize = 500;
pub(in crate::http) const SCIM_PROJECTION_MAX_ATTRIBUTES: usize = 20;
