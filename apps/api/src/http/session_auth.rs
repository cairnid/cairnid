use axum::http::{HeaderMap, StatusCode};
use cairn_domain::{
    AuthSession, Group, MembershipRole, OidcClient, OrganizationId, User, UserId, UserStatus,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    ADMINISTRATORS_GROUP_DISPLAY_NAME, ADMINISTRATORS_GROUP_SLUG, AppState,
    api_response::ApiError,
    cookies::{SESSION_COOKIE, cookie_value},
};

pub(super) async fn require_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthSession, ApiError> {
    session_from_cookie(state, headers)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::UNAUTHORIZED, "missing session"))
}

pub(super) fn session_exceeds_max_age(
    session: &AuthSession,
    max_age: Option<i64>,
    now: OffsetDateTime,
) -> bool {
    let Some(max_age) = max_age else {
        return false;
    };

    let age_seconds = now
        .unix_timestamp()
        .saturating_sub(session.created_at.unix_timestamp());
    age_seconds > max_age
}

pub(super) async fn require_admin_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthSession, ApiError> {
    let session = require_session(state, headers).await?;
    let is_admin = state
        .database
        .user_has_group_role(
            session.organization_id,
            session.user_id,
            ADMINISTRATORS_GROUP_SLUG,
            &[MembershipRole::Owner],
        )
        .await?;

    if !is_admin {
        return Err(ApiError::status(
            StatusCode::FORBIDDEN,
            "admin privileges required",
        ));
    }

    Ok(session)
}

pub(super) async fn require_recent_admin_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthSession, ApiError> {
    let session = require_admin_session(state, headers).await?;
    super::mfa::require_recent_mfa_proof(&session, OffsetDateTime::now_utc())?;
    Ok(session)
}

pub(super) fn bootstrap_admin_group(
    organization_id: OrganizationId,
    created_at: OffsetDateTime,
) -> Group {
    Group {
        id: Uuid::new_v4(),
        organization_id,
        slug: ADMINISTRATORS_GROUP_SLUG.to_owned(),
        scim_external_id: None,
        display_name: ADMINISTRATORS_GROUP_DISPLAY_NAME.to_owned(),
        created_at,
    }
}

pub(super) async fn require_group_in_organization(
    state: &AppState,
    group_id: Uuid,
) -> Result<Group, ApiError> {
    state
        .database
        .get_group(state.organization_id, group_id)
        .await?
        .ok_or_else(|| ApiError::status(StatusCode::NOT_FOUND, "group not found"))
}

pub(super) async fn groups_claim_for_user(
    state: &AppState,
    organization_id: OrganizationId,
    user_id: UserId,
    scopes: &[String],
) -> Result<Option<Vec<String>>, ApiError> {
    if scopes.iter().any(|scope| scope == "groups") {
        Ok(Some(
            state
                .database
                .list_user_group_slugs(organization_id, user_id)
                .await?,
        ))
    } else {
        Ok(None)
    }
}

pub(super) fn require_client_in_session_organization(
    client: &OidcClient,
    session: &AuthSession,
) -> Result<(), ApiError> {
    if client.organization_id != session.organization_id {
        return Err(ApiError::bad_request("unknown client"));
    }

    Ok(())
}

pub(super) async fn session_from_cookie(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<AuthSession>, ApiError> {
    let Some(raw) = cookie_value(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    let Ok(session_id) = Uuid::parse_str(raw) else {
        return Ok(None);
    };
    let Some(session) = state.database.get_auth_session(session_id).await? else {
        return Ok(None);
    };
    if session.organization_id != state.organization_id {
        return Ok(None);
    }
    if session.revoked_at.is_some() || session.expires_at <= OffsetDateTime::now_utc() {
        return Ok(None);
    }
    let Some(user) = state.database.get_user(session.user_id).await? else {
        return Ok(None);
    };
    if !user_allows_runtime_access(&user, session.organization_id) {
        return Ok(None);
    }
    Ok(Some(session))
}

pub(super) fn user_allows_runtime_access(user: &User, organization_id: OrganizationId) -> bool {
    user.organization_id == organization_id && user.status == UserStatus::Active
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_domain::{OidcClientStatus, OidcGrantType, RedirectUri};
    use time::Duration;

    #[test]
    fn runtime_access_requires_active_user_in_token_organization() {
        let organization_id = Uuid::new_v4();
        let mut user = User::new(organization_id, "runtime@example.com", "Runtime User").unwrap();

        assert!(user_allows_runtime_access(&user, organization_id));

        user.status = UserStatus::Suspended;
        assert!(!user_allows_runtime_access(&user, organization_id));

        user.status = UserStatus::Locked;
        assert!(!user_allows_runtime_access(&user, organization_id));

        user.status = UserStatus::Active;
        assert!(!user_allows_runtime_access(&user, Uuid::new_v4()));
    }

    #[test]
    fn oidc_clients_must_match_session_organization() {
        let organization_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let client = test_oidc_client(organization_id);
        let mut session = AuthSession {
            id: Uuid::new_v4(),
            organization_id,
            user_id: Uuid::new_v4(),
            acr: "urn:cairn:acr:password".to_owned(),
            amr: vec!["pwd".to_owned()],
            created_at: now,
            expires_at: now + Duration::hours(1),
            revoked_at: None,
        };

        assert!(require_client_in_session_organization(&client, &session).is_ok());

        session.organization_id = Uuid::new_v4();
        assert!(require_client_in_session_organization(&client, &session).is_err());
    }

    #[test]
    fn session_max_age_uses_session_authentication_time() {
        let organization_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let session = AuthSession {
            id: Uuid::new_v4(),
            organization_id,
            user_id: Uuid::new_v4(),
            acr: "urn:cairn:acr:password".to_owned(),
            amr: vec!["pwd".to_owned()],
            created_at: now - Duration::seconds(60),
            expires_at: now + Duration::hours(1),
            revoked_at: None,
        };

        assert!(!session_exceeds_max_age(&session, None, now));
        assert!(!session_exceeds_max_age(&session, Some(60), now));
        assert!(session_exceeds_max_age(&session, Some(59), now));
    }

    fn test_oidc_client(organization_id: Uuid) -> OidcClient {
        OidcClient {
            id: Uuid::new_v4(),
            organization_id,
            client_id: "public-client".to_owned(),
            client_secret_hash: None,
            consent_policy_template_id: None,
            name: "Public Client".to_owned(),
            redirect_uris: vec![RedirectUri::parse("http://localhost:3000/callback").unwrap()],
            post_logout_redirect_uris: vec![],
            allowed_scopes: vec!["openid".to_owned()],
            grant_types: vec![
                OidcGrantType::AuthorizationCode,
                OidcGrantType::RefreshToken,
            ],
            public_client: true,
            require_pkce: true,
            status: OidcClientStatus::Active,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}
