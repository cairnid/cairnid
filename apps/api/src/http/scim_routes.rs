mod groups;
mod metadata;
mod users;

pub(super) use self::{
    groups::{
        scim_create_group, scim_delete_group, scim_get_group, scim_list_groups, scim_patch_group,
        scim_replace_group, scim_search_groups,
    },
    metadata::{
        scim_resource_type, scim_resource_types, scim_schema, scim_schemas,
        scim_service_provider_config,
    },
    users::{
        scim_create_user, scim_delete_user, scim_get_user, scim_list_users, scim_patch_user,
        scim_replace_user, scim_search_users,
    },
};
