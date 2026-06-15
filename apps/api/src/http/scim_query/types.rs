use cairn_database::{ScimGroupListFilter, ScimUserListFilter};
use serde::Deserialize;

use super::super::scim_projection::{ScimProjection, ScimSearchAttributes};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct ScimUserListQuery {
    pub(in crate::http) start_index: i64,
    pub(in crate::http) count: i64,
    pub(in crate::http) filter: ScimUserListFilter,
    pub(in crate::http) projection: ScimProjection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct ScimGroupListQuery {
    pub(in crate::http) start_index: i64,
    pub(in crate::http) count: i64,
    pub(in crate::http) filter: ScimGroupListFilter,
    pub(in crate::http) projection: ScimProjection,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::http) struct ScimSearchRequest {
    pub(in crate::http::scim_query) schemas: Vec<String>,
    #[serde(default)]
    pub(in crate::http::scim_query) attributes: Option<ScimSearchAttributes>,
    #[serde(default)]
    pub(in crate::http::scim_query) excluded_attributes: Option<ScimSearchAttributes>,
    #[serde(default)]
    pub(in crate::http::scim_query) filter: Option<String>,
    #[serde(default)]
    pub(in crate::http::scim_query) sort_by: Option<String>,
    #[serde(default)]
    pub(in crate::http::scim_query) sort_order: Option<String>,
    #[serde(default)]
    pub(in crate::http::scim_query) start_index: Option<i64>,
    #[serde(default)]
    pub(in crate::http::scim_query) count: Option<i64>,
}
