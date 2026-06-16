mod connector_profile;
mod connector_smoke;
mod smoke;

pub(super) const REQUIRED_SCIM_CONNECTOR_SMOKE_CHECKS: &[&str] = &[
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
#[cfg(test)]
pub(super) use connector_profile::expected_scim_connector_display_name;
pub(super) use connector_profile::validate_scim_connector_profile;
pub(super) use connector_smoke::validate_scim_connector_smoke;
#[cfg(test)]
pub(super) use smoke::REQUIRED_SCIM_SMOKE_CHECKS;
pub(super) use smoke::validate_scim_smoke;
