mod apply;
mod paths;
mod query;
mod types;

pub(super) use self::apply::scim_apply_projection;
#[cfg(test)]
pub(super) use self::paths::ScimProjectionPath;
pub(super) use self::paths::{
    ScimResourceKind, ScimSearchAttributes, scim_projection_paths, strip_scim_group_schema_prefix,
    strip_scim_user_schema_prefix,
};
pub(super) use self::query::{
    scim_projection_from_query, scim_resource_projection_query, scim_search_projection_paths,
};
pub(super) use self::types::ScimProjection;
