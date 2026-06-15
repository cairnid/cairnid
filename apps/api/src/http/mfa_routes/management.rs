use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use cairn_audit::AuditEventBuilder;
use cairn_domain::MfaKind;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{
    AppState,
    api_response::ApiError,
    cookies::require_csrf,
    mfa::{
        active_recovery_code_credentials_for_user, active_second_factor_count,
        replace_recovery_codes_for_session, require_recent_mfa_proof,
        visible_mfa_credentials_for_user,
    },
    session_auth::require_session,
};
use super::types::{MfaCredentialListResponse, mfa_credential_summary};

pub(in crate::http) async fn list_session_mfa_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MfaCredentialListResponse>, ApiError> {
    let session = require_session(&state, &headers).await?;
    let credentials =
        visible_mfa_credentials_for_user(&state, session.organization_id, session.user_id).await?;
    let recovery_code_count =
        active_recovery_code_credentials_for_user(&state, session.organization_id, session.user_id)
            .await?
            .len();

    Ok(Json(MfaCredentialListResponse {
        credentials: credentials.iter().map(mfa_credential_summary).collect(),
        recovery_code_count,
    }))
}

pub(in crate::http) async fn revoke_session_mfa_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(credential_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let now = OffsetDateTime::now_utc();
    require_recent_mfa_proof(&session, now)?;
    let revoked = state
        .database
        .revoke_mfa_credential(session.organization_id, session.user_id, credential_id, now)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::NOT_FOUND, "MFA credential not found"))?;
    let recovery_codes_revoked =
        if active_second_factor_count(&state, session.organization_id, session.user_id).await? == 0
        {
            state
                .database
                .revoke_active_mfa_credentials_by_kind(
                    session.organization_id,
                    session.user_id,
                    MfaKind::RecoveryCode,
                    now,
                )
                .await?
        } else {
            0
        };

    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                session.organization_id,
                session.user_id,
                "mfa.credential_revoked",
                revoked.id.to_string(),
            )
            .metadata(json!({
                "kind": revoked.kind,
                "label": revoked.label,
                "recovery_codes_revoked": recovery_codes_revoked
            }))
            .build(),
        )
        .await?;

    Ok(Json(mfa_credential_summary(&revoked)).into_response())
}

pub(in crate::http) async fn regenerate_session_recovery_codes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = require_session(&state, &headers).await?;
    require_csrf(&headers)?;
    let now = OffsetDateTime::now_utc();
    require_recent_mfa_proof(&session, now)?;

    if active_second_factor_count(&state, session.organization_id, session.user_id).await? == 0 {
        return Err(ApiError::status(
            StatusCode::CONFLICT,
            "active MFA credential required",
        ));
    }

    let (recovery_codes, recovery_codes_revoked) =
        replace_recovery_codes_for_session(&state, &session, now).await?;
    state
        .database
        .insert_audit_event(
            &AuditEventBuilder::user(
                session.organization_id,
                session.user_id,
                "mfa.recovery_codes_regenerated",
                session.user_id.to_string(),
            )
            .metadata(json!({
                "recovery_codes_issued": recovery_codes.len(),
                "recovery_codes_revoked": recovery_codes_revoked
            }))
            .build(),
        )
        .await?;

    Ok(Json(json!({
        "status": "regenerated",
        "recovery_codes": recovery_codes
    }))
    .into_response())
}
