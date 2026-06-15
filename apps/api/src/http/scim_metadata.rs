mod attributes;
mod resource_types;
mod schemas;

pub(super) use self::resource_types::{scim_group_resource_type, scim_user_resource_type};
pub(super) use self::schemas::{scim_group_schema_resource, scim_user_schema_resource};

#[cfg(test)]
mod tests;
