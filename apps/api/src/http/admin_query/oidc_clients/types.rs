use cairn_database::OidcClientListFilter;

use super::super::pagination::AdminListQuery;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct AdminOidcClientListQuery {
    pub(in crate::http) page: AdminListQuery,
    pub(in crate::http) filter: OidcClientListFilter,
}
