#[derive(Debug, Clone, Copy)]
pub(super) struct BrowserOriginMutationRoute {
    pub(super) name: &'static str,
    pub(super) method: &'static str,
    pub(super) path: &'static str,
}

pub(super) fn browser_origin_mutation_routes() -> &'static [BrowserOriginMutationRoute] {
    &[
        BrowserOriginMutationRoute {
            name: "bootstrap",
            method: "POST",
            path: "api/v1/bootstrap",
        },
        BrowserOriginMutationRoute {
            name: "consent",
            method: "POST",
            path: "api/v1/consent",
        },
        BrowserOriginMutationRoute {
            name: "invitation create",
            method: "POST",
            path: "api/v1/invitations",
        },
        BrowserOriginMutationRoute {
            name: "invitation accept",
            method: "POST",
            path: "api/v1/invitations/accept",
        },
        BrowserOriginMutationRoute {
            name: "email verification request",
            method: "POST",
            path: "api/v1/session/email-verification/request",
        },
        BrowserOriginMutationRoute {
            name: "email verification confirm",
            method: "POST",
            path: "api/v1/session/email-verification/confirm",
        },
        BrowserOriginMutationRoute {
            name: "login",
            method: "POST",
            path: "api/v1/session/login",
        },
        BrowserOriginMutationRoute {
            name: "reauthenticate",
            method: "POST",
            path: "api/v1/session/reauthenticate",
        },
        BrowserOriginMutationRoute {
            name: "password change",
            method: "POST",
            path: "api/v1/session/password/change",
        },
        BrowserOriginMutationRoute {
            name: "logout",
            method: "POST",
            path: "api/v1/session/logout",
        },
        BrowserOriginMutationRoute {
            name: "current-user browser session revoke",
            method: "DELETE",
            path: "api/v1/session/browser-sessions/00000000-0000-4000-8000-000000000001",
        },
        BrowserOriginMutationRoute {
            name: "current-user consent revoke",
            method: "DELETE",
            path: "api/v1/session/consent-grants/00000000-0000-4000-8000-000000000002",
        },
        BrowserOriginMutationRoute {
            name: "MFA credential revoke",
            method: "DELETE",
            path: "api/v1/session/mfa/credentials/00000000-0000-4000-8000-000000000003",
        },
        BrowserOriginMutationRoute {
            name: "recovery-code regeneration",
            method: "POST",
            path: "api/v1/session/mfa/recovery-codes/regenerate",
        },
        BrowserOriginMutationRoute {
            name: "TOTP enrollment start",
            method: "POST",
            path: "api/v1/session/mfa/totp/start",
        },
        BrowserOriginMutationRoute {
            name: "TOTP enrollment confirm",
            method: "POST",
            path: "api/v1/session/mfa/totp/confirm",
        },
        BrowserOriginMutationRoute {
            name: "WebAuthn enrollment start",
            method: "POST",
            path: "api/v1/session/mfa/webauthn/start",
        },
        BrowserOriginMutationRoute {
            name: "WebAuthn enrollment finish",
            method: "POST",
            path: "api/v1/session/mfa/webauthn/finish",
        },
        BrowserOriginMutationRoute {
            name: "password recovery request",
            method: "POST",
            path: "api/v1/session/password-recovery/request",
        },
        BrowserOriginMutationRoute {
            name: "password recovery complete",
            method: "POST",
            path: "api/v1/session/password-recovery/complete",
        },
        BrowserOriginMutationRoute {
            name: "admin user create",
            method: "POST",
            path: "api/v1/users",
        },
        BrowserOriginMutationRoute {
            name: "admin user status",
            method: "PUT",
            path: "api/v1/users/00000000-0000-4000-8000-000000000004/status",
        },
        BrowserOriginMutationRoute {
            name: "admin user email verification",
            method: "POST",
            path: "api/v1/users/00000000-0000-4000-8000-000000000004/email-verification/request",
        },
        BrowserOriginMutationRoute {
            name: "admin user password recovery",
            method: "POST",
            path: "api/v1/users/00000000-0000-4000-8000-000000000004/password-recovery/request",
        },
        BrowserOriginMutationRoute {
            name: "admin user browser session revoke",
            method: "DELETE",
            path: "api/v1/users/00000000-0000-4000-8000-000000000004/browser-sessions/00000000-0000-4000-8000-000000000001",
        },
        BrowserOriginMutationRoute {
            name: "admin group create",
            method: "POST",
            path: "api/v1/groups",
        },
        BrowserOriginMutationRoute {
            name: "admin group membership upsert",
            method: "PUT",
            path: "api/v1/groups/00000000-0000-4000-8000-000000000005/memberships/00000000-0000-4000-8000-000000000004",
        },
        BrowserOriginMutationRoute {
            name: "admin group membership delete",
            method: "DELETE",
            path: "api/v1/groups/00000000-0000-4000-8000-000000000005/memberships/00000000-0000-4000-8000-000000000004",
        },
        BrowserOriginMutationRoute {
            name: "admin consent policy template create",
            method: "POST",
            path: "api/v1/oidc/consent-policy-templates",
        },
        BrowserOriginMutationRoute {
            name: "admin OIDC client create",
            method: "POST",
            path: "api/v1/oidc/clients",
        },
        BrowserOriginMutationRoute {
            name: "admin OIDC client secret rotation",
            method: "POST",
            path: "api/v1/oidc/clients/00000000-0000-4000-8000-000000000006/secret/rotate",
        },
        BrowserOriginMutationRoute {
            name: "admin OIDC client status",
            method: "PUT",
            path: "api/v1/oidc/clients/00000000-0000-4000-8000-000000000006/status",
        },
        BrowserOriginMutationRoute {
            name: "admin OIDC consent revoke",
            method: "DELETE",
            path: "api/v1/oidc/clients/00000000-0000-4000-8000-000000000006/consent-grants/00000000-0000-4000-8000-000000000002",
        },
    ]
}
