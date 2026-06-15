mod kind;
mod profile;
mod smoke_template;
#[cfg(test)]
mod tests;
mod types;
mod validation;

pub use self::{profile::scim_connector_profile, smoke_template::scim_connector_smoke_template};

pub const REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS: &[&str] = &[
    "connector_enabled",
    "service_provider_config",
    "user_create",
    "user_exact_filter",
    "user_search_request",
    "user_projection",
    "user_patch",
    "user_replace",
    "group_create",
    "group_exact_filter",
    "group_search_request",
    "group_projection",
    "group_patch_members",
    "group_replace",
    "bulk_forward_reference",
    "user_deactivation",
    "group_delete",
    "token_rotation_acceptance",
    "retired_token_rejection",
];
