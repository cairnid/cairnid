use axum::{
    Router,
    routing::{delete, get, post},
};

use crate::http::{
    AppState,
    account_routes::{
        accept_invitation, complete_password_recovery, confirm_email_verification,
        create_invitation, request_email_verification, request_password_recovery,
    },
    auth_routes::{bootstrap, change_password, csrf_token, login, reauthenticate},
    mfa_routes::{
        confirm_totp_mfa, finish_webauthn_mfa, list_session_mfa_credentials,
        regenerate_session_recovery_codes, revoke_session_mfa_credential, start_totp_mfa,
        start_webauthn_mfa,
    },
    session_routes::{
        create_consent, list_browser_sessions, list_security_activity, list_session_consent_grants,
        logout, me, revoke_browser_session, revoke_session_consent_grant,
    },
};

pub(super) fn session_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/bootstrap", post(bootstrap))
        .route("/api/v1/consent", post(create_consent))
        .route("/api/v1/invitations", post(create_invitation))
        .route("/api/v1/invitations/accept", post(accept_invitation))
        .route(
            "/api/v1/session/email-verification/request",
            post(request_email_verification),
        )
        .route(
            "/api/v1/session/email-verification/confirm",
            post(confirm_email_verification),
        )
        .route("/api/v1/session/login", post(login))
        .route("/api/v1/session/reauthenticate", post(reauthenticate))
        .route("/api/v1/session/password/change", post(change_password))
        .route("/api/v1/session/logout", post(logout))
        .route("/api/v1/session/me", get(me))
        .route(
            "/api/v1/session/browser-sessions",
            get(list_browser_sessions),
        )
        .route(
            "/api/v1/session/browser-sessions/{session_id}",
            delete(revoke_browser_session),
        )
        .route(
            "/api/v1/session/consent-grants",
            get(list_session_consent_grants),
        )
        .route(
            "/api/v1/session/consent-grants/{grant_id}",
            delete(revoke_session_consent_grant),
        )
        .route(
            "/api/v1/session/security-activity",
            get(list_security_activity),
        )
        .route(
            "/api/v1/session/mfa/credentials",
            get(list_session_mfa_credentials),
        )
        .route(
            "/api/v1/session/mfa/credentials/{credential_id}",
            delete(revoke_session_mfa_credential),
        )
        .route(
            "/api/v1/session/mfa/recovery-codes/regenerate",
            post(regenerate_session_recovery_codes),
        )
        .route("/api/v1/session/mfa/totp/start", post(start_totp_mfa))
        .route("/api/v1/session/mfa/totp/confirm", post(confirm_totp_mfa))
        .route(
            "/api/v1/session/mfa/webauthn/start",
            post(start_webauthn_mfa),
        )
        .route(
            "/api/v1/session/mfa/webauthn/finish",
            post(finish_webauthn_mfa),
        )
        .route(
            "/api/v1/session/password-recovery/request",
            post(request_password_recovery),
        )
        .route(
            "/api/v1/session/password-recovery/complete",
            post(complete_password_recovery),
        )
        .route("/api/v1/session/csrf", get(csrf_token))
}
