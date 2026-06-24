#![allow(dead_code)]

use serde::Serialize;
use time::OffsetDateTime;

pub(crate) const API_CONTRACT_SCHEMA_VERSION: &str = "cairnid.api_contract.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ApiMethod {
    Delete,
    Get,
    Patch,
    Post,
    Put,
}

impl ApiMethod {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "DELETE",
            Self::Get => "GET",
            Self::Patch => "PATCH",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }

    #[cfg(test)]
    const fn router_pattern(self) -> &'static str {
        match self {
            Self::Delete => "delete(",
            Self::Get => "get(",
            Self::Patch => "patch(",
            Self::Post => "post(",
            Self::Put => "put(",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiAudience {
    Admin,
    Browser,
    Health,
    Protocol,
    Scim,
}

impl ApiAudience {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Browser => "browser",
            Self::Health => "health",
            Self::Protocol => "protocol",
            Self::Scim => "scim",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiSchema {
    Empty(&'static str),
    Form(&'static str),
    None,
    Json(&'static str),
    Ndjson(&'static str),
    Query(&'static str),
    Redirect(&'static str),
}

impl ApiSchema {
    pub(crate) const fn name(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Empty(name)
            | Self::Form(name)
            | Self::Json(name)
            | Self::Ndjson(name)
            | Self::Query(name)
            | Self::Redirect(name) => Some(name),
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

pub(crate) fn api_contract_routes() -> &'static [ApiRouteContract] {
    API_CONTRACT_ROUTES
}

pub(crate) fn api_contract_report(generated_at: OffsetDateTime) -> ApiContractReport {
    ApiContractReport {
        schema_version: API_CONTRACT_SCHEMA_VERSION,
        generated_at,
        routes: api_contract_routes()
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

const API_CONTRACT_ROUTES: &[ApiRouteContract] = &[
    route(
        ApiMethod::Get,
        "/healthz",
        ApiAudience::Health,
        "healthz",
        ApiSchema::None,
        ApiSchema::Json("HealthStatusResponse"),
    ),
    route(
        ApiMethod::Get,
        "/.well-known/openid-configuration",
        ApiAudience::Protocol,
        "openid_configuration",
        ApiSchema::None,
        ApiSchema::Json("ProviderMetadata"),
    ),
    route(
        ApiMethod::Get,
        "/.well-known/jwks.json",
        ApiAudience::Protocol,
        "jwks",
        ApiSchema::None,
        ApiSchema::Json("JwkSet"),
    ),
    route(
        ApiMethod::Get,
        "/oauth2/authorize",
        ApiAudience::Protocol,
        "authorize",
        ApiSchema::Query("AuthorizationRequest"),
        ApiSchema::Redirect("OAuthAuthorizationRedirect"),
    ),
    route(
        ApiMethod::Post,
        "/oauth2/authorize",
        ApiAudience::Protocol,
        "authorize",
        ApiSchema::Form("AuthorizationRequest"),
        ApiSchema::Redirect("OAuthAuthorizationRedirect"),
    ),
    route(
        ApiMethod::Get,
        "/oauth2/logout",
        ApiAudience::Protocol,
        "end_session",
        ApiSchema::Query("EndSessionRequest"),
        ApiSchema::Redirect("EndSessionResponse"),
    ),
    route(
        ApiMethod::Post,
        "/oauth2/logout",
        ApiAudience::Protocol,
        "end_session_post",
        ApiSchema::Form("EndSessionRequest"),
        ApiSchema::Redirect("EndSessionResponse"),
    ),
    route(
        ApiMethod::Post,
        "/oauth2/token",
        ApiAudience::Protocol,
        "token",
        ApiSchema::Form("TokenRequest"),
        ApiSchema::Json("TokenResponse"),
    ),
    route(
        ApiMethod::Get,
        "/oauth2/userinfo",
        ApiAudience::Protocol,
        "userinfo_route",
        ApiSchema::None,
        ApiSchema::Json("UserInfoResponse"),
    ),
    route(
        ApiMethod::Post,
        "/oauth2/userinfo",
        ApiAudience::Protocol,
        "userinfo_route",
        ApiSchema::Form("UserInfoRequest"),
        ApiSchema::Json("UserInfoResponse"),
    ),
    route(
        ApiMethod::Post,
        "/oauth2/introspect",
        ApiAudience::Protocol,
        "introspect",
        ApiSchema::Form("IntrospectionRequest"),
        ApiSchema::Json("IntrospectionResponse"),
    ),
    route(
        ApiMethod::Post,
        "/oauth2/revoke",
        ApiAudience::Protocol,
        "revoke",
        ApiSchema::Form("RevocationRequest"),
        ApiSchema::Empty("OAuthRevocationResponse"),
    ),
    route(
        ApiMethod::Get,
        "/scim/v2/ServiceProviderConfig",
        ApiAudience::Scim,
        "scim_service_provider_config",
        ApiSchema::None,
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"),
    ),
    route(
        ApiMethod::Get,
        "/scim/v2/Schemas",
        ApiAudience::Scim,
        "scim_schemas",
        ApiSchema::None,
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:ListResponse"),
    ),
    route(
        ApiMethod::Get,
        "/scim/v2/Schemas/{schema_id}",
        ApiAudience::Scim,
        "scim_schema",
        ApiSchema::None,
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:Schema"),
    ),
    route(
        ApiMethod::Get,
        "/scim/v2/ResourceTypes",
        ApiAudience::Scim,
        "scim_resource_types",
        ApiSchema::None,
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:ListResponse"),
    ),
    route(
        ApiMethod::Get,
        "/scim/v2/ResourceTypes/{resource_type}",
        ApiAudience::Scim,
        "scim_resource_type",
        ApiSchema::None,
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:ResourceType"),
    ),
    route(
        ApiMethod::Post,
        "/scim/v2/Bulk",
        ApiAudience::Scim,
        "scim_bulk",
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:BulkRequest"),
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:BulkResponse"),
    ),
    route(
        ApiMethod::Post,
        "/scim/v2/Users/.search",
        ApiAudience::Scim,
        "scim_search_users",
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:SearchRequest"),
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:ListResponse"),
    ),
    route(
        ApiMethod::Get,
        "/scim/v2/Users",
        ApiAudience::Scim,
        "scim_list_users",
        ApiSchema::Query("ScimUserListQuery"),
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:ListResponse"),
    ),
    route(
        ApiMethod::Post,
        "/scim/v2/Users",
        ApiAudience::Scim,
        "scim_create_user",
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:User"),
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:User"),
    ),
    route(
        ApiMethod::Get,
        "/scim/v2/Users/{user_id}",
        ApiAudience::Scim,
        "scim_get_user",
        ApiSchema::Query("ScimUserResourceQuery"),
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:User"),
    ),
    route(
        ApiMethod::Put,
        "/scim/v2/Users/{user_id}",
        ApiAudience::Scim,
        "scim_replace_user",
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:User"),
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:User"),
    ),
    route(
        ApiMethod::Patch,
        "/scim/v2/Users/{user_id}",
        ApiAudience::Scim,
        "scim_patch_user",
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:User"),
    ),
    route(
        ApiMethod::Delete,
        "/scim/v2/Users/{user_id}",
        ApiAudience::Scim,
        "scim_delete_user",
        ApiSchema::None,
        ApiSchema::Empty("ScimNoContentResponse"),
    ),
    route(
        ApiMethod::Post,
        "/scim/v2/Groups/.search",
        ApiAudience::Scim,
        "scim_search_groups",
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:SearchRequest"),
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:ListResponse"),
    ),
    route(
        ApiMethod::Get,
        "/scim/v2/Groups",
        ApiAudience::Scim,
        "scim_list_groups",
        ApiSchema::Query("ScimGroupListQuery"),
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:ListResponse"),
    ),
    route(
        ApiMethod::Post,
        "/scim/v2/Groups",
        ApiAudience::Scim,
        "scim_create_group",
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:Group"),
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:Group"),
    ),
    route(
        ApiMethod::Get,
        "/scim/v2/Groups/{group_id}",
        ApiAudience::Scim,
        "scim_get_group",
        ApiSchema::Query("ScimGroupResourceQuery"),
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:Group"),
    ),
    route(
        ApiMethod::Put,
        "/scim/v2/Groups/{group_id}",
        ApiAudience::Scim,
        "scim_replace_group",
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:Group"),
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:Group"),
    ),
    route(
        ApiMethod::Patch,
        "/scim/v2/Groups/{group_id}",
        ApiAudience::Scim,
        "scim_patch_group",
        ApiSchema::Json("urn:ietf:params:scim:api:messages:2.0:PatchOp"),
        ApiSchema::Json("urn:ietf:params:scim:schemas:core:2.0:Group"),
    ),
    route(
        ApiMethod::Delete,
        "/scim/v2/Groups/{group_id}",
        ApiAudience::Scim,
        "scim_delete_group",
        ApiSchema::None,
        ApiSchema::Empty("ScimNoContentResponse"),
    ),
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
        "/api/v1/session/security-activity",
        ApiAudience::Browser,
        "list_security_activity",
        ApiSchema::Query("SessionSecurityActivityListQuery"),
        ApiSchema::Json("ListPage<SessionSecurityActivityEvent>"),
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
    fn manifest_covers_public_router_routes() {
        let mut manifest_routes = manifest_route_keys();
        let mut router_routes = router_route_keys();
        manifest_routes.sort();
        router_routes.sort();

        assert_eq!(API_CONTRACT_ROUTES.len(), 84);
        assert_eq!(manifest_routes, router_routes);
    }

    #[test]
    fn manifest_includes_protocol_scim_and_health_surfaces() {
        assert_has_route(ApiMethod::Get, "/healthz");
        assert_has_route(ApiMethod::Get, "/.well-known/openid-configuration");
        assert_has_route(ApiMethod::Get, "/.well-known/jwks.json");
        assert_has_route(ApiMethod::Get, "/oauth2/authorize");
        assert_has_route(ApiMethod::Post, "/oauth2/authorize");
        assert_has_route(ApiMethod::Post, "/oauth2/token");
        assert_has_route(ApiMethod::Get, "/oauth2/userinfo");
        assert_has_route(ApiMethod::Post, "/oauth2/userinfo");
        assert_has_route(ApiMethod::Post, "/oauth2/introspect");
        assert_has_route(ApiMethod::Post, "/oauth2/revoke");
        assert_has_route(ApiMethod::Get, "/oauth2/logout");
        assert_has_route(ApiMethod::Post, "/oauth2/logout");
        assert_has_route(ApiMethod::Get, "/scim/v2/ServiceProviderConfig");
        assert_has_route(ApiMethod::Get, "/scim/v2/Schemas");
        assert_has_route(ApiMethod::Get, "/scim/v2/ResourceTypes");
        assert_has_route(ApiMethod::Post, "/scim/v2/Bulk");
        assert_has_route(ApiMethod::Patch, "/scim/v2/Users/{user_id}");
        assert_has_route(ApiMethod::Patch, "/scim/v2/Groups/{group_id}");
    }

    #[test]
    fn manifest_schema_labels_are_explicit_and_safe() {
        for route in API_CONTRACT_ROUTES {
            assert!(
                !route.handler.is_empty(),
                "{} {} must record the handler name",
                route.method.as_str(),
                route.path
            );
            assert!(
                !matches!(
                    route.request_schema,
                    ApiSchema::Empty(_) | ApiSchema::Ndjson(_) | ApiSchema::Redirect(_)
                ),
                "{} {} cannot use a response-only request contract label",
                route.method.as_str(),
                route.path
            );
            assert!(
                !matches!(
                    route.response_schema,
                    ApiSchema::None | ApiSchema::Form(_) | ApiSchema::Query(_)
                ),
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
        for audience in [
            ApiAudience::Admin,
            ApiAudience::Browser,
            ApiAudience::Health,
            ApiAudience::Protocol,
            ApiAudience::Scim,
        ] {
            assert!(
                api_contract_routes()
                    .iter()
                    .any(|route| route.audience == audience),
                "{} audience must have at least one checked route",
                audience.as_str()
            );
        }
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
        assert_eq!(routes.len(), API_CONTRACT_ROUTES.len());

        let exported_routes = exported_route_keys(routes);
        let manifest_routes = API_CONTRACT_ROUTES
            .iter()
            .map(expected_exported_route)
            .collect::<Vec<_>>();

        assert_eq!(exported_routes, manifest_routes);
    }

    #[test]
    fn api_contract_export_json_includes_protocol_scim_and_health_routes() {
        let report = api_contract_report(test_generated_at());
        let json = serde_json::to_value(&report).expect("serializable API contract report");
        let routes = json["routes"].as_array().expect("routes array");

        let exported_route_keys = routes
            .iter()
            .map(|route| {
                (
                    route["method"].as_str().expect("route method"),
                    route["path"].as_str().expect("route path"),
                )
            })
            .collect::<Vec<_>>();

        for (method, path) in [
            ("GET", "/healthz"),
            ("GET", "/.well-known/openid-configuration"),
            ("GET", "/.well-known/jwks.json"),
            ("GET", "/oauth2/authorize"),
            ("POST", "/oauth2/token"),
            ("GET", "/oauth2/userinfo"),
            ("POST", "/oauth2/introspect"),
            ("GET", "/scim/v2/ServiceProviderConfig"),
            ("POST", "/scim/v2/Bulk"),
            ("PATCH", "/scim/v2/Users/{user_id}"),
            ("PATCH", "/scim/v2/Groups/{group_id}"),
        ] {
            assert!(
                exported_route_keys.contains(&(method, path)),
                "{method} {path} must be exported"
            );
        }
    }

    fn manifest_route_keys() -> Vec<RouteEntry> {
        api_contract_routes()
            .iter()
            .map(|route| RouteEntry {
                method: route.method,
                path: route.path,
                handler: route.handler,
            })
            .collect()
    }

    fn router_route_keys() -> Vec<RouteEntry> {
        let mut routes = routes_from_router_source(include_str!("router/protocol.rs"));
        routes.extend(routes_from_router_source(include_str!("router/scim.rs")));
        routes.extend(routes_from_router_source(include_str!("router/session.rs")));
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

            if route_block.contains("userinfo_route()") {
                routes.push(RouteEntry {
                    method: ApiMethod::Get,
                    path,
                    handler: "userinfo_route",
                });
                routes.push(RouteEntry {
                    method: ApiMethod::Post,
                    path,
                    handler: "userinfo_route",
                });
            }

            for method in [
                ApiMethod::Delete,
                ApiMethod::Get,
                ApiMethod::Patch,
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

    fn assert_has_route(method: ApiMethod, path: &'static str) {
        assert!(
            api_contract_routes()
                .iter()
                .any(|route| route.method == method && route.path == path),
            "{} {path} must be in the checked API contract",
            method.as_str()
        );
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
