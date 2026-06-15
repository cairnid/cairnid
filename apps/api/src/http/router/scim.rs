use axum::{
    Router,
    routing::{get, post},
};

use crate::http::{
    AppState,
    scim_bulk::scim_bulk,
    scim_routes::{
        scim_create_group, scim_create_user, scim_delete_group, scim_delete_user, scim_get_group,
        scim_get_user, scim_list_groups, scim_list_users, scim_patch_group, scim_patch_user,
        scim_replace_group, scim_replace_user, scim_resource_type, scim_resource_types,
        scim_schema, scim_schemas, scim_search_groups, scim_search_users,
        scim_service_provider_config,
    },
};

pub(super) fn scim_api_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(scim_service_provider_config),
        )
        .route("/scim/v2/Schemas", get(scim_schemas))
        .route("/scim/v2/Schemas/{schema_id}", get(scim_schema))
        .route("/scim/v2/ResourceTypes", get(scim_resource_types))
        .route(
            "/scim/v2/ResourceTypes/{resource_type}",
            get(scim_resource_type),
        )
        .route("/scim/v2/Bulk", post(scim_bulk))
        .route("/scim/v2/Users/.search", post(scim_search_users))
        .route(
            "/scim/v2/Users",
            get(scim_list_users).post(scim_create_user),
        )
        .route(
            "/scim/v2/Users/{user_id}",
            get(scim_get_user)
                .put(scim_replace_user)
                .patch(scim_patch_user)
                .delete(scim_delete_user),
        )
        .route("/scim/v2/Groups/.search", post(scim_search_groups))
        .route(
            "/scim/v2/Groups",
            get(scim_list_groups).post(scim_create_group),
        )
        .route(
            "/scim/v2/Groups/{group_id}",
            get(scim_get_group)
                .put(scim_replace_group)
                .patch(scim_patch_group)
                .delete(scim_delete_group),
        )
}
