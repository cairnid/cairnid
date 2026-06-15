mod create;
mod delete;
mod lookup;
mod update;

pub(in crate::http) use self::create::scim_create_group_operation;
pub(in crate::http) use self::delete::scim_delete_group_operation;
pub(in crate::http) use self::lookup::scim_get_tenant_group;
pub(in crate::http) use self::update::{scim_patch_group_operation, scim_replace_group_operation};
