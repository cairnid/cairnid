use axum::http::StatusCode;
use cairn_domain::{AuthSession, OrganizationId, UserId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::super::{MFA_DESTRUCTIVE_ACTION_MAX_AGE, api_response::ApiError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::http) enum MfaVerificationMethod {
    Totp,
    RecoveryCode,
    WebAuthn,
}

impl MfaVerificationMethod {
    fn acr(self) -> &'static str {
        match self {
            Self::Totp => "urn:cairn:acr:password+totp",
            Self::RecoveryCode => "urn:cairn:acr:password+recovery_code",
            Self::WebAuthn => "urn:cairn:acr:password+webauthn",
        }
    }

    fn amr(self) -> Vec<String> {
        match self {
            Self::Totp => vec!["pwd".to_owned(), "otp".to_owned()],
            Self::RecoveryCode => vec!["pwd".to_owned(), "recovery".to_owned()],
            Self::WebAuthn => vec!["pwd".to_owned(), "mfa".to_owned(), "user".to_owned()],
        }
    }
}

fn session_has_mfa_proof(session: &AuthSession) -> bool {
    matches!(
        session.acr.as_str(),
        "urn:cairn:acr:password+totp"
            | "urn:cairn:acr:password+recovery_code"
            | "urn:cairn:acr:password+webauthn"
    ) || session
        .amr
        .iter()
        .any(|method| matches!(method.as_str(), "otp" | "recovery" | "mfa"))
}

pub(in crate::http) fn require_recent_mfa_proof(
    session: &AuthSession,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    if !session_has_mfa_proof(session) || session.created_at + MFA_DESTRUCTIVE_ACTION_MAX_AGE < now
    {
        return Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "fresh MFA verification required",
        ));
    }

    Ok(())
}

pub(in crate::http) fn require_recent_authentication(
    session: &AuthSession,
    now: OffsetDateTime,
) -> Result<(), ApiError> {
    if session.created_at + MFA_DESTRUCTIVE_ACTION_MAX_AGE < now {
        return Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "fresh authentication required",
        ));
    }

    Ok(())
}

pub(in crate::http) fn authenticated_session(
    organization_id: OrganizationId,
    user_id: UserId,
    mfa_method: Option<&MfaVerificationMethod>,
    now: OffsetDateTime,
) -> AuthSession {
    AuthSession {
        id: Uuid::new_v4(),
        organization_id,
        user_id,
        acr: mfa_method
            .map(|method| method.acr())
            .unwrap_or("urn:cairn:acr:password")
            .to_owned(),
        amr: mfa_method
            .map(|method| method.amr())
            .unwrap_or_else(|| vec!["pwd".to_owned()]),
        created_at: now,
        expires_at: now + Duration::hours(12),
        revoked_at: None,
    }
}

pub(in crate::http) fn rotated_session_preserving_auth_context(
    session: &AuthSession,
    now: OffsetDateTime,
) -> AuthSession {
    AuthSession {
        id: Uuid::new_v4(),
        organization_id: session.organization_id,
        user_id: session.user_id,
        acr: session.acr.clone(),
        amr: session.amr.clone(),
        created_at: session.created_at,
        expires_at: now + Duration::hours(12),
        revoked_at: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_verification_methods_emit_expected_auth_context() {
        assert_eq!(
            MfaVerificationMethod::Totp.acr(),
            "urn:cairn:acr:password+totp"
        );
        assert_eq!(
            MfaVerificationMethod::Totp.amr(),
            vec!["pwd".to_owned(), "otp".to_owned()]
        );
        assert_eq!(
            MfaVerificationMethod::RecoveryCode.acr(),
            "urn:cairn:acr:password+recovery_code"
        );
        assert_eq!(
            MfaVerificationMethod::RecoveryCode.amr(),
            vec!["pwd".to_owned(), "recovery".to_owned()]
        );
        assert_eq!(
            MfaVerificationMethod::WebAuthn.acr(),
            "urn:cairn:acr:password+webauthn"
        );
        assert_eq!(
            MfaVerificationMethod::WebAuthn.amr(),
            vec!["pwd".to_owned(), "mfa".to_owned(), "user".to_owned()]
        );
    }

    #[test]
    fn recent_mfa_proof_accepts_supported_mfa_sessions() {
        let now = OffsetDateTime::now_utc();
        let supported_sessions = [
            (
                MfaVerificationMethod::Totp.acr(),
                vec!["pwd", "otp"],
                now - Duration::minutes(5),
            ),
            (
                MfaVerificationMethod::RecoveryCode.acr(),
                vec!["pwd", "recovery"],
                now - Duration::minutes(5),
            ),
            (
                MfaVerificationMethod::WebAuthn.acr(),
                vec!["pwd", "mfa", "user"],
                now - Duration::minutes(5),
            ),
            (
                MfaVerificationMethod::Totp.acr(),
                vec!["pwd", "otp"],
                now - MFA_DESTRUCTIVE_ACTION_MAX_AGE,
            ),
        ];

        for (acr, amr, created_at) in supported_sessions {
            let session = test_auth_session_with_context(acr, &amr, created_at);
            assert!(require_recent_mfa_proof(&session, now).is_ok());
        }
    }

    #[test]
    fn recent_mfa_proof_rejects_password_only_or_stale_mfa_sessions() {
        let now = OffsetDateTime::now_utc();
        let password_only = test_auth_session_with_context(
            "urn:cairn:acr:password",
            &["pwd"],
            now - Duration::minutes(1),
        );
        let stale_totp = test_auth_session_with_context(
            MfaVerificationMethod::Totp.acr(),
            &["pwd", "otp"],
            now - MFA_DESTRUCTIVE_ACTION_MAX_AGE - Duration::seconds(1),
        );

        assert_fresh_mfa_required(require_recent_mfa_proof(&password_only, now));
        assert_fresh_mfa_required(require_recent_mfa_proof(&stale_totp, now));
    }

    #[test]
    fn recent_authentication_accepts_password_only_sessions_without_extending_auth_time() {
        let now = OffsetDateTime::now_utc();
        let fresh_password = test_auth_session_with_context(
            "urn:cairn:acr:password",
            &["pwd"],
            now - Duration::minutes(5),
        );
        let stale_password = test_auth_session_with_context(
            "urn:cairn:acr:password",
            &["pwd"],
            now - MFA_DESTRUCTIVE_ACTION_MAX_AGE - Duration::seconds(1),
        );

        assert!(require_recent_authentication(&fresh_password, now).is_ok());
        assert_fresh_authentication_required(require_recent_authentication(&stale_password, now));
    }

    #[test]
    fn authenticated_sessions_record_password_or_mfa_context() {
        let organization_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let password_session = authenticated_session(organization_id, user_id, None, now);
        assert_eq!(password_session.organization_id, organization_id);
        assert_eq!(password_session.user_id, user_id);
        assert_eq!(password_session.acr, "urn:cairn:acr:password");
        assert_eq!(password_session.amr, vec!["pwd".to_owned()]);
        assert_eq!(password_session.created_at, now);
        assert_eq!(password_session.expires_at, now + Duration::hours(12));

        let totp_session = authenticated_session(
            organization_id,
            user_id,
            Some(&MfaVerificationMethod::Totp),
            now,
        );
        assert_eq!(totp_session.acr, "urn:cairn:acr:password+totp");
        assert_eq!(totp_session.amr, vec!["pwd".to_owned(), "otp".to_owned()]);
    }

    #[test]
    fn rotated_sessions_preserve_authentication_context_without_extending_auth_time() {
        let authenticated_at = OffsetDateTime::now_utc() - Duration::minutes(5);
        let rotated_at = authenticated_at + Duration::minutes(6);
        let session = test_auth_session_with_context(
            MfaVerificationMethod::WebAuthn.acr(),
            &["pwd", "mfa", "user"],
            authenticated_at,
        );

        let rotated = rotated_session_preserving_auth_context(&session, rotated_at);

        assert_ne!(rotated.id, session.id);
        assert_eq!(rotated.organization_id, session.organization_id);
        assert_eq!(rotated.user_id, session.user_id);
        assert_eq!(rotated.acr, session.acr);
        assert_eq!(rotated.amr, session.amr);
        assert_eq!(rotated.created_at, session.created_at);
        assert_eq!(rotated.expires_at, rotated_at + Duration::hours(12));
        assert_eq!(rotated.revoked_at, None);
    }

    fn test_auth_session_with_context(
        acr: &str,
        amr: &[&str],
        created_at: OffsetDateTime,
    ) -> AuthSession {
        AuthSession {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            acr: acr.to_owned(),
            amr: amr.iter().map(|method| (*method).to_owned()).collect(),
            created_at,
            expires_at: created_at + Duration::hours(12),
            revoked_at: None,
        }
    }

    fn assert_fresh_mfa_required(result: Result<(), ApiError>) {
        match result {
            Err(ApiError::Status {
                status, message, ..
            }) => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_eq!(message, "fresh MFA verification required");
            }
            other => panic!("expected fresh MFA verification error, got {other:?}"),
        }
    }

    fn assert_fresh_authentication_required(result: Result<(), ApiError>) {
        match result {
            Err(ApiError::Status {
                status, message, ..
            }) => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_eq!(message, "fresh authentication required");
            }
            other => panic!("expected fresh authentication error, got {other:?}"),
        }
    }
}
