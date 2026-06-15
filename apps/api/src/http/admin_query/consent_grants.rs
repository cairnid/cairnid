mod admin;
mod common;
mod session;
#[cfg(test)]
mod tests;

use cairn_database::ConsentGrantListFilter;

use super::pagination::AdminListQuery;

pub(in crate::http) use self::admin::admin_consent_grant_list_query;
pub(in crate::http) use self::session::session_consent_grant_list_query;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct AdminConsentGrantListQuery {
    pub(in crate::http) page: AdminListQuery,
    pub(in crate::http) filter: ConsentGrantListFilter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::http) struct SessionConsentGrantListQuery {
    pub(in crate::http) page: AdminListQuery,
    pub(in crate::http) filter: ConsentGrantListFilter,
}
