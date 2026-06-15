use axum::{
    Router,
    routing::{delete, get, post, put},
};

use crate::http::{
    AppState,
    admin_audit::{export_audit_events, list_audit_events},
    admin_groups::{
        create_group, delete_group_membership, list_group_memberships, list_groups,
        upsert_group_membership,
    },
    admin_oidc::{
        create_client, create_consent_policy_template, list_client_consent_grants, list_clients,
        list_consent_policy_templates, revoke_client_consent_grant, rotate_client_secret,
        update_client_status,
    },
    admin_users::{
        create_user, list_admin_user_browser_sessions, list_admin_user_security_events, list_users,
        request_admin_user_email_verification, request_admin_user_password_recovery,
        revoke_admin_user_browser_session, update_user_status,
    },
    app_settings::settings,
};

pub(super) fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/{user_id}/status", put(update_user_status))
        .route(
            "/api/v1/users/{user_id}/email-verification/request",
            post(request_admin_user_email_verification),
        )
        .route(
            "/api/v1/users/{user_id}/password-recovery/request",
            post(request_admin_user_password_recovery),
        )
        .route(
            "/api/v1/users/{user_id}/security-events",
            get(list_admin_user_security_events),
        )
        .route(
            "/api/v1/users/{user_id}/browser-sessions",
            get(list_admin_user_browser_sessions),
        )
        .route(
            "/api/v1/users/{user_id}/browser-sessions/{session_id}",
            delete(revoke_admin_user_browser_session),
        )
        .route("/api/v1/groups", get(list_groups).post(create_group))
        .route(
            "/api/v1/groups/{group_id}/memberships",
            get(list_group_memberships),
        )
        .route(
            "/api/v1/groups/{group_id}/memberships/{user_id}",
            put(upsert_group_membership).delete(delete_group_membership),
        )
        .route(
            "/api/v1/oidc/consent-policy-templates",
            get(list_consent_policy_templates).post(create_consent_policy_template),
        )
        .route(
            "/api/v1/oidc/clients",
            get(list_clients).post(create_client),
        )
        .route(
            "/api/v1/oidc/clients/{client_id}/secret/rotate",
            post(rotate_client_secret),
        )
        .route(
            "/api/v1/oidc/clients/{client_id}/status",
            put(update_client_status),
        )
        .route(
            "/api/v1/oidc/clients/{client_id}/consent-grants",
            get(list_client_consent_grants),
        )
        .route(
            "/api/v1/oidc/clients/{client_id}/consent-grants/{grant_id}",
            delete(revoke_client_consent_grant),
        )
        .route("/api/v1/audit-events", get(list_audit_events))
        .route("/api/v1/audit-events/export", get(export_audit_events))
        .route("/api/v1/settings", get(settings))
}
