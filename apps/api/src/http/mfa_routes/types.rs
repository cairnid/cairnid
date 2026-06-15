use cairn_authn::RegisterPublicKeyCredential;
use cairn_domain::{MfaCredential, MfaKind};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::mfa::mfa_metadata_status;

#[derive(Debug, Serialize)]
pub(in crate::http) struct MfaCredentialListResponse {
    pub(in crate::http::mfa_routes) credentials: Vec<MfaCredentialSummary>,
    pub(in crate::http::mfa_routes) recovery_code_count: usize,
}

#[derive(Debug, Serialize)]
pub(in crate::http) struct MfaCredentialSummary {
    id: Uuid,
    kind: MfaKind,
    label: String,
    status: String,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(default, with = "time::serde::rfc3339::option")]
    last_used_at: Option<OffsetDateTime>,
}

pub(in crate::http::mfa_routes) fn mfa_credential_summary(
    credential: &MfaCredential,
) -> MfaCredentialSummary {
    MfaCredentialSummary {
        id: credential.id,
        kind: credential.kind,
        label: credential.label.clone(),
        status: mfa_metadata_status(credential).to_owned(),
        created_at: credential.created_at,
        last_used_at: credential.last_used_at,
    }
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct StartTotpMfaRequest {
    #[serde(default)]
    pub(in crate::http::mfa_routes) label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct ConfirmTotpMfaRequest {
    pub(in crate::http::mfa_routes) credential_id: Uuid,
    pub(in crate::http::mfa_routes) code: String,
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct StartWebAuthnMfaRequest {
    #[serde(default)]
    pub(in crate::http::mfa_routes) label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(in crate::http) struct FinishWebAuthnMfaRequest {
    pub(in crate::http::mfa_routes) challenge_id: Uuid,
    pub(in crate::http::mfa_routes) credential: RegisterPublicKeyCredential,
    #[serde(default)]
    pub(in crate::http::mfa_routes) label: Option<String>,
}
