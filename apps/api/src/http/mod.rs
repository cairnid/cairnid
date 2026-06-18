mod account_lifecycle;
mod account_routes;
mod admin_audit;
mod admin_groups;
mod admin_oidc;
mod admin_query;
mod admin_users;
mod api_contract;
mod api_response;
mod app_settings;
mod auth_routes;
mod authorization;
mod browser_sessions;
mod client_policy;
mod content_type;
mod cookies;
mod end_session;
mod mfa;
mod mfa_routes;
mod oauth_client;
mod oauth_http;
mod oauth_routes;
mod oauth_token;
mod oidc_browser_routes;
mod public_metadata;
mod request_body;
mod request_context;
mod router;
mod scim_auth;
mod scim_bulk;
mod scim_input;
mod scim_metadata;
mod scim_operations;
mod scim_projection;
mod scim_protocol;
mod scim_query;
mod scim_resource;
mod scim_routes;
mod security;
mod session_auth;
mod session_routes;
mod urlencoded;

use crate::config::ApiConfig;
use api_response::ApiError;
use cairn_database::Database;
use cairn_domain::OrganizationId;
use request_body::bounded_request_body;
pub use router::build_router;
use time::Duration;

const LOGIN_RATE_LIMIT_MAX_ATTEMPTS: i64 = 5;
const LOGIN_RATE_LIMIT_WINDOW: Duration = Duration::minutes(15);
const LOGIN_RATE_LIMIT_BLOCK: Duration = Duration::minutes(15);
const REAUTHENTICATION_RATE_LIMIT_MAX_ATTEMPTS: i64 = 5;
const REAUTHENTICATION_RATE_LIMIT_WINDOW: Duration = Duration::minutes(15);
const REAUTHENTICATION_RATE_LIMIT_BLOCK: Duration = Duration::minutes(15);
const BOOTSTRAP_RATE_LIMIT_MAX_ATTEMPTS: i64 = 5;
const BOOTSTRAP_RATE_LIMIT_WINDOW: Duration = Duration::hours(1);
const BOOTSTRAP_RATE_LIMIT_BLOCK: Duration = Duration::minutes(30);
const ACCOUNT_RECOVERY_RATE_LIMIT_MAX_ATTEMPTS: i64 = 3;
const ACCOUNT_RECOVERY_RATE_LIMIT_WINDOW: Duration = Duration::hours(1);
const ACCOUNT_RECOVERY_RATE_LIMIT_BLOCK: Duration = Duration::hours(1);
const SESSION_LIST_LIMIT: i64 = 100;
const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_BYTES: usize = 12;
const WEBAUTHN_CHALLENGE_TTL: Duration = Duration::minutes(5);
const TOTP_ENROLLMENT_TTL: Duration = Duration::minutes(10);
const CONSENT_AUTHORIZATION_TTL: Duration = Duration::minutes(5);
const MFA_DESTRUCTIVE_ACTION_MAX_AGE: Duration = Duration::minutes(15);
const ADMINISTRATORS_GROUP_SLUG: &str = "administrators";
const ADMINISTRATORS_GROUP_DISPLAY_NAME: &str = "Administrators";
const OAUTH_QUERY_MAX_BYTES: usize = 8 * 1024;
const OAUTH_FORM_BODY_MAX_BYTES: usize = 16 * 1024;
const API_JSON_BODY_MAX_BYTES: usize = 256 * 1024;
const ADMIN_LIST_QUERY_MAX_BYTES: usize = 512;
const ADMIN_LIST_DEFAULT_LIMIT: i64 = 100;
const ADMIN_LIST_MAX_LIMIT: i64 = 250;
const ADMIN_GROUP_MEMBERSHIP_LIST_MAX_LIMIT: i64 = 500;
const ADMIN_AUDIT_EXPORT_DEFAULT_LIMIT: i64 = 1000;

#[derive(Debug, Clone)]
pub struct AppState {
    pub database: Database,
    pub organization_id: OrganizationId,
    pub config: ApiConfig,
}

#[cfg(test)]
mod tests;
