#![forbid(unsafe_code)]

mod accounts;
mod audit;
mod email;
mod error;
mod groups;
mod ids;
mod mfa;
mod oidc;
mod organization;
mod signing;
mod users;
mod validation;

pub use accounts::{AccountToken, AccountTokenKind};
pub use audit::{AuditActorKind, AuditEvent};
pub use email::EmailOutboxMessage;
pub use error::DomainError;
pub use groups::{Group, Membership, MembershipRole};
pub use ids::{
    AccountTokenId, AuditEventId, ClientId, ConsentAuthorizationId, ConsentGrantId,
    ConsentPolicyTemplateId, EmailOutboxId, GroupId, MfaCredentialId, OrganizationId,
    RefreshTokenId, SessionId, UserId, WebAuthnChallengeId,
};
pub use mfa::{MfaCredential, MfaKind, WebAuthnChallenge, WebAuthnChallengeKind};
pub use oidc::{
    AuthSession, AuthorizationCode, ConsentAuthorization, ConsentGrant, ConsentGrantMode,
    ConsentPolicyTemplate, OidcClient, OidcClientStatus, OidcGrantType, PkceMethod, RedirectUri,
    RefreshToken,
};
pub use organization::{Environment, Organization};
pub use signing::{SigningKey, SigningKeyMaterial};
pub use users::{User, UserStatus};
pub use validation::{checked_string, normalize_email};

#[cfg(test)]
mod tests;
