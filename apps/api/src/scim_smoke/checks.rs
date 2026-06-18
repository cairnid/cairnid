pub(in crate::scim_smoke) const CHECK_SECONDARY_TOKEN: &str = "secondary_token";
pub(in crate::scim_smoke) const CHECK_REJECTED_TOKEN: &str = "rejected_token";
pub(in crate::scim_smoke) const CHECK_SERVICE_PROVIDER_CONFIG: &str = "service_provider_config";
pub(in crate::scim_smoke) const CHECK_SCHEMAS: &str = "schemas";
pub(in crate::scim_smoke) const CHECK_RESOURCE_TYPES: &str = "resource_types";
pub(in crate::scim_smoke) const CHECK_USER_CREATE: &str = "user_create";
pub(in crate::scim_smoke) const CHECK_USER_FILTER: &str = "user_filter";
pub(in crate::scim_smoke) const CHECK_USER_SEARCH_REQUEST: &str = "user_search_request";
pub(in crate::scim_smoke) const CHECK_USER_PROJECTION: &str = "user_projection";
pub(in crate::scim_smoke) const CHECK_USER_PATCH: &str = "user_patch";
pub(in crate::scim_smoke) const CHECK_USER_REPLACE: &str = "user_replace";
pub(in crate::scim_smoke) const CHECK_GROUP_CREATE: &str = "group_create";
pub(in crate::scim_smoke) const CHECK_GROUP_FILTER: &str = "group_filter";
pub(in crate::scim_smoke) const CHECK_GROUP_SEARCH_REQUEST: &str = "group_search_request";
pub(in crate::scim_smoke) const CHECK_GROUP_PROJECTION: &str = "group_projection";
pub(in crate::scim_smoke) const CHECK_GROUP_PATCH: &str = "group_patch";
pub(in crate::scim_smoke) const CHECK_GROUP_REPLACE: &str = "group_replace";
pub(in crate::scim_smoke) const CHECK_GROUP_DELETE: &str = "group_delete";
pub(in crate::scim_smoke) const CHECK_BULK_MUTATIONS: &str = "bulk_mutations";
pub(in crate::scim_smoke) const CHECK_USER_DELETE: &str = "user_delete";
pub(in crate::scim_smoke) const CHECK_USER_SOFT_DELETE: &str = "user_soft_delete";

pub(in crate::scim_smoke) const REQUIRED_SCIM_SMOKE_CHECKS: &[&str] = &[
    CHECK_SECONDARY_TOKEN,
    CHECK_REJECTED_TOKEN,
    CHECK_SERVICE_PROVIDER_CONFIG,
    CHECK_SCHEMAS,
    CHECK_RESOURCE_TYPES,
    CHECK_USER_CREATE,
    CHECK_USER_FILTER,
    CHECK_USER_SEARCH_REQUEST,
    CHECK_USER_PROJECTION,
    CHECK_USER_PATCH,
    CHECK_USER_REPLACE,
    CHECK_GROUP_CREATE,
    CHECK_GROUP_FILTER,
    CHECK_GROUP_SEARCH_REQUEST,
    CHECK_GROUP_PROJECTION,
    CHECK_GROUP_PATCH,
    CHECK_GROUP_REPLACE,
    CHECK_GROUP_DELETE,
    CHECK_BULK_MUTATIONS,
    CHECK_USER_DELETE,
    CHECK_USER_SOFT_DELETE,
];

#[cfg(test)]
mod tests {
    use super::REQUIRED_SCIM_SMOKE_CHECKS;
    use std::collections::BTreeSet;

    #[test]
    fn required_scim_smoke_checks_are_unique() {
        let unique = REQUIRED_SCIM_SMOKE_CHECKS.iter().collect::<BTreeSet<_>>();

        assert_eq!(unique.len(), REQUIRED_SCIM_SMOKE_CHECKS.len());
    }
}
