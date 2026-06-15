use super::DatabaseError;
use cairn_domain::{
    AccountTokenKind, AuditActorKind, ConsentGrantMode, MembershipRole, MfaKind, OidcClientStatus,
    OidcGrantType, PkceMethod, UserStatus, WebAuthnChallengeKind,
};

pub(crate) fn user_status_to_str(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "active",
        UserStatus::Suspended => "suspended",
        UserStatus::Locked => "locked",
    }
}

pub(crate) fn user_status_from_str(value: &str) -> Result<UserStatus, DatabaseError> {
    match value {
        "active" => Ok(UserStatus::Active),
        "suspended" => Ok(UserStatus::Suspended),
        "locked" => Ok(UserStatus::Locked),
        other => Err(DatabaseError::InvalidEnum(other.to_owned())),
    }
}

pub(crate) fn oidc_client_status_to_str(status: OidcClientStatus) -> &'static str {
    match status {
        OidcClientStatus::Active => "active",
        OidcClientStatus::Disabled => "disabled",
    }
}

pub(crate) fn oidc_client_status_from_str(value: &str) -> Result<OidcClientStatus, DatabaseError> {
    match value {
        "active" => Ok(OidcClientStatus::Active),
        "disabled" => Ok(OidcClientStatus::Disabled),
        other => Err(DatabaseError::InvalidEnum(other.to_owned())),
    }
}

pub(crate) fn account_token_kind_to_str(kind: AccountTokenKind) -> &'static str {
    match kind {
        AccountTokenKind::EmailVerification => "email_verification",
        AccountTokenKind::PasswordRecovery => "password_recovery",
        AccountTokenKind::Invitation => "invitation",
    }
}

pub(crate) fn account_token_kind_from_str(value: &str) -> Result<AccountTokenKind, DatabaseError> {
    match value {
        "email_verification" => Ok(AccountTokenKind::EmailVerification),
        "password_recovery" => Ok(AccountTokenKind::PasswordRecovery),
        "invitation" => Ok(AccountTokenKind::Invitation),
        other => Err(DatabaseError::InvalidEnum(other.to_owned())),
    }
}

pub(crate) fn pkce_method_to_str(method: PkceMethod) -> &'static str {
    match method {
        PkceMethod::S256 => "S256",
    }
}

pub(crate) fn pkce_method_from_str(value: &str) -> Result<PkceMethod, DatabaseError> {
    match value {
        "S256" => Ok(PkceMethod::S256),
        other => Err(DatabaseError::InvalidEnum(other.to_owned())),
    }
}

pub(crate) fn oidc_grant_type_to_str(grant_type: OidcGrantType) -> &'static str {
    grant_type.as_protocol_value()
}

pub(crate) fn consent_grant_mode_to_str(mode: ConsentGrantMode) -> &'static str {
    match mode {
        ConsentGrantMode::RequiredOnce => "required_once",
        ConsentGrantMode::AlwaysRequired => "always_required",
    }
}

pub(crate) fn consent_grant_mode_from_str(value: &str) -> Result<ConsentGrantMode, DatabaseError> {
    match value {
        "required_once" => Ok(ConsentGrantMode::RequiredOnce),
        "always_required" => Ok(ConsentGrantMode::AlwaysRequired),
        other => Err(DatabaseError::InvalidEnum(other.to_owned())),
    }
}

pub(crate) fn audit_actor_kind_to_str(kind: AuditActorKind) -> &'static str {
    match kind {
        AuditActorKind::User => "user",
        AuditActorKind::Client => "client",
        AuditActorKind::System => "system",
    }
}

pub(crate) fn audit_actor_kind_from_str(value: &str) -> Result<AuditActorKind, DatabaseError> {
    match value {
        "user" => Ok(AuditActorKind::User),
        "client" => Ok(AuditActorKind::Client),
        "system" => Ok(AuditActorKind::System),
        other => Err(DatabaseError::InvalidEnum(other.to_owned())),
    }
}

pub(crate) fn membership_role_to_str(role: MembershipRole) -> &'static str {
    match role {
        MembershipRole::Member => "member",
        MembershipRole::Owner => "owner",
    }
}

pub(crate) fn membership_role_from_str(value: &str) -> Result<MembershipRole, DatabaseError> {
    match value {
        "member" => Ok(MembershipRole::Member),
        "owner" => Ok(MembershipRole::Owner),
        other => Err(DatabaseError::InvalidEnum(other.to_owned())),
    }
}

pub(crate) fn mfa_kind_to_str(kind: MfaKind) -> &'static str {
    match kind {
        MfaKind::Totp => "totp",
        MfaKind::WebAuthn => "web_authn",
        MfaKind::RecoveryCode => "recovery_code",
    }
}

pub(crate) fn mfa_kind_from_str(value: &str) -> Result<MfaKind, DatabaseError> {
    match value {
        "totp" => Ok(MfaKind::Totp),
        "web_authn" => Ok(MfaKind::WebAuthn),
        "recovery_code" => Ok(MfaKind::RecoveryCode),
        other => Err(DatabaseError::InvalidEnum(other.to_owned())),
    }
}

pub(crate) fn webauthn_challenge_kind_to_str(kind: WebAuthnChallengeKind) -> &'static str {
    match kind {
        WebAuthnChallengeKind::Registration => "registration",
        WebAuthnChallengeKind::Authentication => "authentication",
    }
}

pub(crate) fn webauthn_challenge_kind_from_str(
    value: &str,
) -> Result<WebAuthnChallengeKind, DatabaseError> {
    match value {
        "registration" => Ok(WebAuthnChallengeKind::Registration),
        "authentication" => Ok(WebAuthnChallengeKind::Authentication),
        other => Err(DatabaseError::InvalidEnum(other.to_owned())),
    }
}
