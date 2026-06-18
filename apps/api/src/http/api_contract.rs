#![allow(dead_code)]

use serde::Serialize;
use time::OffsetDateTime;

pub(crate) const API_CONTRACT_SCHEMA_VERSION: &str = "cairnid.api_contract.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ApiMethod {
    Delete,
    Get,
    Post,
    Put,
}

impl ApiMethod {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "DELETE",
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }

    #[cfg(test)]
    const fn router_pattern(self) -> &'static str {
        match self {
            Self::Delete => "delete(",
            Self::Get => "get(",
            Self::Post => "post(",
            Self::Put => "put(",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiAudience {
    Admin,
    Browser,
}

impl ApiAudience {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Browser => "browser",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiSchema {
    None,
    Json(&'static str),
    Ndjson(&'static str),
    Query(&'static str),
}

impl ApiSchema {
    pub(crate) const fn name(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Json(name) | Self::Ndjson(name) | Self::Query(name) => Some(name),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApiRouteContract {
    pub(crate) method: ApiMethod,
    pub(crate) path: &'static str,
    pub(crate) audience: ApiAudience,
    pub(crate) handler: &'static str,
    pub(crate) request_schema: ApiSchema,
    pub(crate) response_schema: ApiSchema,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct ApiContractReport {
    pub(crate) schema_version: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) generated_at: OffsetDateTime,
    pub(crate) routes: Vec<ApiRouteContractReport>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct ApiRouteContractReport {
    pub(crate) method: &'static str,
    pub(crate) path: &'static str,
    pub(crate) audience: &'static str,
    pub(crate) handler: &'static str,
    pub(crate) request_contract_label: Option<&'static str>,
    pub(crate) response_contract_label: Option<&'static str>,
}

pub(crate) fn browser_admin_api_routes() -> &'static [ApiRouteContract] {
    BROWSER_ADMIN_API_ROUTES
}

pub(crate) fn api_contract_report(generated_at: OffsetDateTime) -> ApiContractReport {
    ApiContractReport {
        schema_version: API_CONTRACT_SCHEMA_VERSION,
        generated_at,
        routes: browser_admin_api_routes()
            .iter()
            .map(ApiRouteContractReport::from_route)
            .collect(),
    }
}

impl ApiRouteContractReport {
    const fn from_route(route: &ApiRouteContract) -> Self {
        Self {
            method: route.method.as_str(),
            path: route.path,
            audience: route.audience.as_str(),
            handler: route.handler,
            request_contract_label: route.request_schema.name(),
            response_contract_label: route.response_schema.name(),
        }
    }
}

const fn route(
    method: ApiMethod,
    path: &'static str,
    audience: ApiAudience,
    handler: &'static str,
    request_schema: ApiSchema,
    response_schema: ApiSchema,
) -> ApiRouteContract {
    ApiRouteContract {
        method,
        path,
        audience,
        handler,
        request_schema,
        response_schema,
    }
}

const BROWSER_ADMIN_API_ROUTES: &[ApiRouteContract] = &[
    route(
        ApiMethod::Post,
        "/api/v1/bootstrap",
        ApiAudience::Admin,
        "bootstrap",
        ApiSchema::Json("BootstrapRequest"),
        ApiSchema::Json("User"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/consent",
        ApiAudience::Browser,
        "create_consent",
        ApiSchema::Json("CreateConsentRequest"),
        ApiSchema::Json("ConsentGrant"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/invitations",
        ApiAudience::Admin,
        "create_invitation",
        ApiSchema::Json("CreateInvitationRequest"),
        ApiSchema::Json("AccountLifecycleDeliveryResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/invitations/accept",
        ApiAudience::Browser,
        "accept_invitation",
        ApiSchema::Json("AcceptInvitationRequest"),
        ApiSchema::Json("StatusOkResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/email-verification/request",
        ApiAudience::Browser,
        "request_email_verification",
        ApiSchema::None,
        ApiSchema::Json("AccountLifecycleDeliveryResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/email-verification/confirm",
        ApiAudience::Browser,
        "confirm_email_verification",
        ApiSchema::Json("AccountTokenRequest"),
        ApiSchema::Json("StatusOkResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/login",
        ApiAudience::Browser,
        "login",
        ApiSchema::Json("LoginRequest"),
        ApiSchema::Json("LoginResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/reauthenticate",
        ApiAudience::Browser,
        "reauthenticate",
        ApiSchema::Json("ReauthenticateRequest"),
        ApiSchema::Json("ReauthenticationResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/password/change",
        ApiAudience::Browser,
        "change_password",
        ApiSchema::Json("ChangePasswordRequest"),
        ApiSchema::Json("ChangePasswordResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/logout",
        ApiAudience::Browser,
        "logout",
        ApiSchema::None,
        ApiSchema::Json("StatusOkResponse"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/session/me",
        ApiAudience::Browser,
        "me",
        ApiSchema::None,
        ApiSchema::Json("User"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/session/browser-sessions",
        ApiAudience::Browser,
        "list_browser_sessions",
        ApiSchema::None,
        ApiSchema::Json("BrowserSessionListResponse"),
    ),
    route(
        ApiMethod::Delete,
        "/api/v1/session/browser-sessions/{session_id}",
        ApiAudience::Browser,
        "revoke_browser_session",
        ApiSchema::None,
        ApiSchema::Json("BrowserSessionRevocationResponse"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/session/consent-grants",
        ApiAudience::Browser,
        "list_session_consent_grants",
        ApiSchema::Query("SessionConsentGrantListQuery"),
        ApiSchema::Json("ListPage<SessionConsentGrantSummary>"),
    ),
    route(
        ApiMethod::Delete,
        "/api/v1/session/consent-grants/{grant_id}",
        ApiAudience::Browser,
        "revoke_session_consent_grant",
        ApiSchema::None,
        ApiSchema::Json("AdminConsentGrantRevocationResponse"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/session/mfa/credentials",
        ApiAudience::Browser,
        "list_session_mfa_credentials",
        ApiSchema::None,
        ApiSchema::Json("MfaCredentialListResponse"),
    ),
    route(
        ApiMethod::Delete,
        "/api/v1/session/mfa/credentials/{credential_id}",
        ApiAudience::Browser,
        "revoke_session_mfa_credential",
        ApiSchema::None,
        ApiSchema::Json("MfaCredentialSummary"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/mfa/recovery-codes/regenerate",
        ApiAudience::Browser,
        "regenerate_session_recovery_codes",
        ApiSchema::None,
        ApiSchema::Json("RecoveryCodeRegenerationResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/mfa/totp/start",
        ApiAudience::Browser,
        "start_totp_mfa",
        ApiSchema::Json("StartTotpMfaRequest"),
        ApiSchema::Json("TotpMfaStartResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/mfa/totp/confirm",
        ApiAudience::Browser,
        "confirm_totp_mfa",
        ApiSchema::Json("ConfirmTotpMfaRequest"),
        ApiSchema::Json("TotpMfaConfirmationResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/mfa/webauthn/start",
        ApiAudience::Browser,
        "start_webauthn_mfa",
        ApiSchema::Json("StartWebAuthnMfaRequest"),
        ApiSchema::Json("WebAuthnMfaStartResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/mfa/webauthn/finish",
        ApiAudience::Browser,
        "finish_webauthn_mfa",
        ApiSchema::Json("FinishWebAuthnMfaRequest"),
        ApiSchema::Json("WebAuthnMfaFinishResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/password-recovery/request",
        ApiAudience::Browser,
        "request_password_recovery",
        ApiSchema::Json("PasswordRecoveryRequest"),
        ApiSchema::Json("PasswordRecoveryRequestResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/session/password-recovery/complete",
        ApiAudience::Browser,
        "complete_password_recovery",
        ApiSchema::Json("CompletePasswordRecoveryRequest"),
        ApiSchema::Json("PasswordRecoveryCompleteResponse"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/session/csrf",
        ApiAudience::Browser,
        "csrf_token",
        ApiSchema::None,
        ApiSchema::Json("CsrfTokenResponse"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/users",
        ApiAudience::Admin,
        "list_users",
        ApiSchema::Query("AdminUserListQuery"),
        ApiSchema::Json("ListPage<User>"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/users",
        ApiAudience::Admin,
        "create_user",
        ApiSchema::Json("CreateUserRequest"),
        ApiSchema::Json("User"),
    ),
    route(
        ApiMethod::Put,
        "/api/v1/users/{user_id}/status",
        ApiAudience::Admin,
        "update_user_status",
        ApiSchema::Json("UpdateUserStatusRequest"),
        ApiSchema::Json("User"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/users/{user_id}/email-verification/request",
        ApiAudience::Admin,
        "request_admin_user_email_verification",
        ApiSchema::None,
        ApiSchema::Json("AccountLifecycleDeliveryResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/users/{user_id}/password-recovery/request",
        ApiAudience::Admin,
        "request_admin_user_password_recovery",
        ApiSchema::None,
        ApiSchema::Json("AccountLifecycleDeliveryResponse"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/users/{user_id}/security-events",
        ApiAudience::Admin,
        "list_admin_user_security_events",
        ApiSchema::Query("AdminListQuery"),
        ApiSchema::Json("ListPage<AuditEvent>"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/users/{user_id}/browser-sessions",
        ApiAudience::Admin,
        "list_admin_user_browser_sessions",
        ApiSchema::None,
        ApiSchema::Json("BrowserSessionListResponse"),
    ),
    route(
        ApiMethod::Delete,
        "/api/v1/users/{user_id}/browser-sessions/{session_id}",
        ApiAudience::Admin,
        "revoke_admin_user_browser_session",
        ApiSchema::None,
        ApiSchema::Json("BrowserSessionRevocationResponse"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/groups",
        ApiAudience::Admin,
        "list_groups",
        ApiSchema::Query("AdminListQuery"),
        ApiSchema::Json("ListPage<Group>"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/groups",
        ApiAudience::Admin,
        "create_group",
        ApiSchema::Json("CreateGroupRequest"),
        ApiSchema::Json("Group"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/groups/{group_id}/memberships",
        ApiAudience::Admin,
        "list_group_memberships",
        ApiSchema::Query("AdminListQuery"),
        ApiSchema::Json("ListPage<Membership>"),
    ),
    route(
        ApiMethod::Put,
        "/api/v1/groups/{group_id}/memberships/{user_id}",
        ApiAudience::Admin,
        "upsert_group_membership",
        ApiSchema::Json("UpsertGroupMembershipRequest"),
        ApiSchema::Json("Membership"),
    ),
    route(
        ApiMethod::Delete,
        "/api/v1/groups/{group_id}/memberships/{user_id}",
        ApiAudience::Admin,
        "delete_group_membership",
        ApiSchema::None,
        ApiSchema::Json("DeletedStatusResponse"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/oidc/consent-policy-templates",
        ApiAudience::Admin,
        "list_consent_policy_templates",
        ApiSchema::Query("AdminListQuery"),
        ApiSchema::Json("ListPage<ConsentPolicyTemplate>"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/oidc/consent-policy-templates",
        ApiAudience::Admin,
        "create_consent_policy_template",
        ApiSchema::Json("CreateConsentPolicyTemplateRequest"),
        ApiSchema::Json("ConsentPolicyTemplate"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/oidc/clients",
        ApiAudience::Admin,
        "list_clients",
        ApiSchema::Query("AdminOidcClientListQuery"),
        ApiSchema::Json("ListPage<AdminOidcClient>"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/oidc/clients",
        ApiAudience::Admin,
        "create_client",
        ApiSchema::Json("CreateClientRequest"),
        ApiSchema::Json("CreateOidcClientResponse"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/oidc/clients/{client_id}",
        ApiAudience::Admin,
        "get_client",
        ApiSchema::None,
        ApiSchema::Json("AdminOidcClient"),
    ),
    route(
        ApiMethod::Put,
        "/api/v1/oidc/clients/{client_id}",
        ApiAudience::Admin,
        "update_client",
        ApiSchema::Json("UpdateClientRequest"),
        ApiSchema::Json("UpdateOidcClientResponse"),
    ),
    route(
        ApiMethod::Post,
        "/api/v1/oidc/clients/{client_id}/secret/rotate",
        ApiAudience::Admin,
        "rotate_client_secret",
        ApiSchema::None,
        ApiSchema::Json("RotateClientSecretResponse"),
    ),
    route(
        ApiMethod::Put,
        "/api/v1/oidc/clients/{client_id}/status",
        ApiAudience::Admin,
        "update_client_status",
        ApiSchema::Json("UpdateClientStatusRequest"),
        ApiSchema::Json("UpdateOidcClientStatusResponse"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/oidc/clients/{client_id}/consent-grants",
        ApiAudience::Admin,
        "list_client_consent_grants",
        ApiSchema::Query("AdminConsentGrantListQuery"),
        ApiSchema::Json("ListPage<AdminConsentGrantSummary>"),
    ),
    route(
        ApiMethod::Delete,
        "/api/v1/oidc/clients/{client_id}/consent-grants/{grant_id}",
        ApiAudience::Admin,
        "revoke_client_consent_grant",
        ApiSchema::None,
        ApiSchema::Json("AdminConsentGrantRevocationResponse"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/audit-events",
        ApiAudience::Admin,
        "list_audit_events",
        ApiSchema::Query("AdminAuditEventListQuery"),
        ApiSchema::Json("ListPage<AuditEvent>"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/audit-events/export",
        ApiAudience::Admin,
        "export_audit_events",
        ApiSchema::Query("AdminAuditEventListQuery"),
        ApiSchema::Ndjson("AuditEvent"),
    ),
    route(
        ApiMethod::Get,
        "/api/v1/settings",
        ApiAudience::Admin,
        "settings",
        ApiSchema::None,
        ApiSchema::Json("AdminSettingsResponse"),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use time::format_description::well_known::Rfc3339;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct RouteEntry {
        method: ApiMethod,
        path: &'static str,
        handler: &'static str,
    }

    #[test]
    fn manifest_covers_session_and_admin_router_routes() {
        let mut manifest_routes = manifest_route_keys();
        let mut router_routes = router_route_keys();
        manifest_routes.sort();
        router_routes.sort();

        assert_eq!(BROWSER_ADMIN_API_ROUTES.len(), 51);
        assert_eq!(manifest_routes, router_routes);
    }

    #[test]
    fn manifest_excludes_protocol_and_scim_surfaces() {
        for route in browser_admin_api_routes() {
            assert!(
                route.path.starts_with("/api/v1/"),
                "{} {} must remain in the browser/admin API namespace",
                route.method.as_str(),
                route.path
            );
            assert!(!route.path.starts_with("/oauth2/"));
            assert!(!route.path.starts_with("/.well-known/"));
            assert!(!route.path.starts_with("/scim/"));
            assert_ne!(route.path, "/healthz");
        }
    }

    #[test]
    fn manifest_schema_labels_are_explicit_and_safe() {
        for route in BROWSER_ADMIN_API_ROUTES {
            assert!(
                !route.handler.is_empty(),
                "{} {} must record the handler name",
                route.method.as_str(),
                route.path
            );
            assert!(
                !matches!(route.request_schema, ApiSchema::Ndjson(_)),
                "{} {} cannot accept NDJSON request bodies",
                route.method.as_str(),
                route.path
            );
            assert!(
                !matches!(route.response_schema, ApiSchema::None | ApiSchema::Query(_)),
                "{} {} must record a concrete response schema",
                route.method.as_str(),
                route.path
            );

            assert_safe_schema_label(route.request_schema);
            assert_safe_schema_label(route.response_schema);
        }
    }

    #[test]
    fn manifest_keeps_audience_labels_explicit() {
        assert!(
            browser_admin_api_routes()
                .iter()
                .any(|route| route.audience == ApiAudience::Browser)
        );
        assert!(
            browser_admin_api_routes()
                .iter()
                .any(|route| route.audience == ApiAudience::Admin)
        );
    }

    #[test]
    fn api_contract_export_json_covers_checked_manifest() {
        let report = api_contract_report(test_generated_at());
        let json = serde_json::to_value(&report).expect("serializable API contract report");
        let generated_at = json["generated_at"]
            .as_str()
            .expect("generated_at is serialized");
        OffsetDateTime::parse(generated_at, &Rfc3339).expect("generated_at is RFC3339");
        assert_eq!(json["schema_version"], API_CONTRACT_SCHEMA_VERSION);

        let routes = json["routes"].as_array().expect("routes array");
        assert_eq!(routes.len(), BROWSER_ADMIN_API_ROUTES.len());

        let exported_routes = exported_route_keys(routes);
        let manifest_routes = BROWSER_ADMIN_API_ROUTES
            .iter()
            .map(expected_exported_route)
            .collect::<Vec<_>>();

        assert_eq!(exported_routes, manifest_routes);
    }

    #[test]
    fn api_contract_export_json_excludes_protocol_scim_and_health_routes() {
        let report = api_contract_report(test_generated_at());
        let json = serde_json::to_value(&report).expect("serializable API contract report");
        let routes = json["routes"].as_array().expect("routes array");

        let exported_paths = routes
            .iter()
            .map(|route| route["path"].as_str().expect("route path"))
            .collect::<Vec<_>>();

        for path in exported_paths {
            assert!(
                path.starts_with("/api/v1/"),
                "{path} must remain in the browser/admin API namespace"
            );
            assert!(!path.starts_with("/oauth2/"));
            assert!(!path.starts_with("/.well-known/"));
            assert!(!path.starts_with("/scim/"));
            assert_ne!(path, "/healthz");
        }
    }

    fn manifest_route_keys() -> Vec<RouteEntry> {
        browser_admin_api_routes()
            .iter()
            .map(|route| RouteEntry {
                method: route.method,
                path: route.path,
                handler: route.handler,
            })
            .collect()
    }

    fn router_route_keys() -> Vec<RouteEntry> {
        let mut routes = routes_from_router_source(include_str!("router/session.rs"));
        routes.extend(routes_from_router_source(include_str!("router/admin.rs")));
        routes
    }

    fn routes_from_router_source(source: &'static str) -> Vec<RouteEntry> {
        let mut routes = Vec::new();
        let mut tail = source;

        while let Some(route_start) = tail.find(".route(") {
            let route_source = &tail[route_start..];
            let route_end = route_source[1..]
                .find("\n        .route(")
                .map(|next| next + 1)
                .unwrap_or(route_source.len());
            let route_block = &route_source[..route_end];
            let path = route_path(route_block).expect("router route path");

            for method in [
                ApiMethod::Delete,
                ApiMethod::Get,
                ApiMethod::Post,
                ApiMethod::Put,
            ] {
                if let Some(handler) = route_handler(route_block, method) {
                    routes.push(RouteEntry {
                        method,
                        path,
                        handler,
                    });
                }
            }

            tail = &route_source[route_end..];
        }

        routes
    }

    fn route_path(route_block: &'static str) -> Option<&'static str> {
        let first_quote = route_block.find('"')?;
        let after_first_quote = &route_block[first_quote + 1..];
        let end_quote = after_first_quote.find('"')?;
        Some(&after_first_quote[..end_quote])
    }

    fn route_handler(route_block: &'static str, method: ApiMethod) -> Option<&'static str> {
        let method_start = route_block.find(method.router_pattern())?;
        let after_method = &route_block[method_start + method.router_pattern().len()..];
        let end = after_method
            .find(|character: char| !(character == '_' || character.is_ascii_alphanumeric()))?;
        Some(&after_method[..end])
    }

    fn expected_exported_route(route: &ApiRouteContract) -> serde_json::Value {
        serde_json::json!({
            "method": route.method.as_str(),
            "path": route.path,
            "audience": route.audience.as_str(),
            "handler": route.handler,
            "request_contract_label": route.request_schema.name(),
            "response_contract_label": route.response_schema.name(),
        })
    }

    fn exported_route_keys(routes: &[serde_json::Value]) -> Vec<serde_json::Value> {
        routes
            .iter()
            .map(|route| {
                serde_json::json!({
                    "method": route["method"],
                    "path": route["path"],
                    "audience": route["audience"],
                    "handler": route["handler"],
                    "request_contract_label": route["request_contract_label"],
                    "response_contract_label": route["response_contract_label"],
                })
            })
            .collect()
    }

    fn test_generated_at() -> OffsetDateTime {
        OffsetDateTime::parse("2026-06-18T12:00:00Z", &Rfc3339).expect("test timestamp")
    }

    fn assert_safe_schema_label(schema: ApiSchema) {
        let Some(name) = schema.name() else {
            return;
        };
        assert!(!name.is_empty());
        assert_ne!(name, "unknownJson");

        let lower = name.to_ascii_lowercase();
        for forbidden in [
            "token_hash",
            "client_secret_hash",
            "cookie",
            "ciphertext",
            "nonce",
            "private_key",
            "database",
        ] {
            assert!(
                !lower.contains(forbidden),
                "schema label {name} exposes an internal surface marker"
            );
        }
    }
}
