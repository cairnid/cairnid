use axum::http::StatusCode;
use cairn_domain::{ConsentGrantMode, OidcClient, OidcGrantType};
use cairn_oidc::{
    EndSessionRequest, append_post_logout_redirect_params, validate_logout_id_token_hint_issuer,
};
use uuid::Uuid;

use super::{
    AppState, api_response::ApiError, app_settings::resolve_signing_material,
    oauth_client::oidc_client_is_active,
};

pub(super) fn consent_scopes_allowed(scopes: &[String], client: &OidcClient) -> bool {
    scopes
        .iter()
        .all(|scope| client.allowed_scopes.iter().any(|allowed| allowed == scope))
        && (!scopes.iter().any(|scope| scope == "offline_access")
            || client.allows_grant(OidcGrantType::RefreshToken))
}

pub(super) async fn post_logout_redirect_target(
    state: &AppState,
    request: &EndSessionRequest,
) -> Result<Option<String>, ApiError> {
    let Some(post_logout_redirect_uri) = request
        .post_logout_redirect_uri
        .as_deref()
        .filter(|uri| !uri.is_empty())
    else {
        return Ok(None);
    };

    let id_token_hint = request
        .id_token_hint
        .as_deref()
        .filter(|hint| !hint.is_empty())
        .ok_or_else(|| ApiError::bad_request("id_token_hint is required"))?;
    let signing = resolve_signing_material(state).await?;
    let claims =
        validate_logout_id_token_hint_issuer(id_token_hint, &state.config.issuer, &signing)
            .map_err(|_| ApiError::bad_request("invalid id_token_hint"))?;
    let client_id = request
        .client_id
        .as_deref()
        .filter(|client_id| !client_id.is_empty())
        .unwrap_or(claims.aud.as_str());
    let client = state
        .database
        .get_oidc_client_by_public_id(client_id)
        .await?
        .ok_or_else(|| ApiError::bad_request("unknown client"))?;
    if client.organization_id != state.organization_id {
        return Err(ApiError::bad_request("unknown client"));
    }
    if !oidc_client_is_active(&client) {
        return Err(ApiError::bad_request("unknown client"));
    }
    if claims.aud != client.client_id {
        return Err(ApiError::bad_request("invalid id_token_hint"));
    }

    post_logout_redirect_target_for_client(request, &client, post_logout_redirect_uri)
}

fn post_logout_redirect_target_for_client(
    request: &EndSessionRequest,
    client: &OidcClient,
    post_logout_redirect_uri: &str,
) -> Result<Option<String>, ApiError> {
    if !client.allows_post_logout_redirect_uri(post_logout_redirect_uri) {
        return Err(ApiError::bad_request("invalid post_logout_redirect_uri"));
    }

    Ok(Some(append_post_logout_redirect_params(
        post_logout_redirect_uri,
        request.state.as_deref(),
    )))
}

pub(super) async fn organization_client_by_id(
    state: &AppState,
    client_id: Uuid,
) -> Result<OidcClient, ApiError> {
    let Some(client) = state
        .database
        .get_oidc_client_in_organization(state.organization_id, client_id)
        .await?
    else {
        return Err(ApiError::status(StatusCode::NOT_FOUND, "client not found"));
    };

    Ok(client)
}

pub(super) async fn validate_consent_policy_template_assignment(
    state: &AppState,
    template_id: Option<Uuid>,
) -> Result<Option<Uuid>, ApiError> {
    let Some(template_id) = template_id else {
        return Ok(None);
    };
    if state
        .database
        .get_consent_policy_template(state.organization_id, template_id)
        .await?
        .is_none()
    {
        return Err(ApiError::status(
            StatusCode::NOT_FOUND,
            "consent policy template not found",
        ));
    }

    Ok(Some(template_id))
}

pub(super) async fn client_consent_policy_requires_prompt(
    state: &AppState,
    organization_id: Uuid,
    client: &OidcClient,
) -> Result<bool, ApiError> {
    let Some(template_id) = client.consent_policy_template_id else {
        return Ok(false);
    };
    let Some(template) = state
        .database
        .get_consent_policy_template(organization_id, template_id)
        .await?
    else {
        return Ok(true);
    };

    Ok(template.grant_mode == ConsentGrantMode::AlwaysRequired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ApiConfig, AuditOperationsConfig, EmailDeliveryConfig, EmailProviderConfig,
        RequestIdentityConfig, ScimConfig,
    };
    use cairn_database::Database;
    use cairn_domain::{Environment, OidcClientStatus, RedirectUri};
    use time::OffsetDateTime;

    #[test]
    fn consent_offline_access_requires_refresh_grant() {
        let organization_id = Uuid::new_v4();
        let mut client = test_oidc_client(organization_id);
        client.allowed_scopes.push("offline_access".to_owned());
        let offline_scopes = vec!["openid".to_owned(), "offline_access".to_owned()];

        assert!(consent_scopes_allowed(&offline_scopes, &client));

        client.grant_types = vec![OidcGrantType::AuthorizationCode];
        assert!(!consent_scopes_allowed(&offline_scopes, &client));
    }

    #[tokio::test]
    async fn post_logout_redirect_target_allows_no_redirect_without_hint() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/cairn_identity")
            .expect("lazy pool");
        let state = AppState {
            database: Database::from_pool(pool),
            organization_id: Uuid::new_v4(),
            config: test_config(),
        };

        for post_logout_redirect_uri in [None, Some(String::new())] {
            let request = EndSessionRequest {
                id_token_hint: None,
                logout_hint: None,
                client_id: None,
                post_logout_redirect_uri,
                state: Some("not-echoed-locally".to_owned()),
                ui_locales: None,
            };

            assert_eq!(
                post_logout_redirect_target(&state, &request).await.unwrap(),
                None
            );
        }
    }

    #[test]
    fn post_logout_redirect_target_for_client_requires_registered_uri() {
        let organization_id = Uuid::new_v4();
        let mut client = test_oidc_client(organization_id);
        client.post_logout_redirect_uris =
            vec![RedirectUri::parse("http://localhost:3000/signed-out?source=cairn").unwrap()];

        let valid = EndSessionRequest {
            id_token_hint: None,
            logout_hint: None,
            client_id: None,
            post_logout_redirect_uri: Some(
                "http://localhost:3000/signed-out?source=cairn".to_owned(),
            ),
            state: Some("state value".to_owned()),
            ui_locales: Some("en-GB".to_owned()),
        };
        assert_eq!(
            post_logout_redirect_target_for_client(
                &valid,
                &client,
                valid.post_logout_redirect_uri.as_deref().unwrap(),
            )
            .unwrap(),
            Some("http://localhost:3000/signed-out?source=cairn&state=state%20value".to_owned())
        );

        let mut wrong_uri = valid;
        wrong_uri.post_logout_redirect_uri = Some("http://localhost:3000/signed-out/".to_owned());
        let wrong_post_logout_redirect_uri = wrong_uri.post_logout_redirect_uri.as_deref().unwrap();
        assert!(matches!(
            post_logout_redirect_target_for_client(
                &wrong_uri,
                &client,
                wrong_post_logout_redirect_uri
            ),
            Err(ApiError::Status {
                status: StatusCode::BAD_REQUEST,
                ..
            })
        ));
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

    fn test_config() -> ApiConfig {
        ApiConfig {
            environment: Environment::Development,
            bind: "127.0.0.1:8080".to_owned(),
            issuer: "http://localhost:8080".to_owned(),
            public_web_origin: "http://localhost:5173".to_owned(),
            database_url: "postgres://cairn:cairn@localhost:5432/cairn_identity".to_owned(),
            default_org_slug: "default".to_owned(),
            scim: ScimConfig {
                bearer_token_sha256_hashes: Vec::new(),
            },
            audit: AuditOperationsConfig {
                retention_days: 365,
                purge_batch_size: 1000,
                export_max_rows: 10_000,
            },
            email_delivery: EmailDeliveryConfig {
                provider: EmailProviderConfig::Stdout,
                batch_size: 10,
                max_attempts: 5,
                retry_seconds: 300,
                sending_timeout_seconds: 900,
            },
            request_identity: RequestIdentityConfig {
                trusted_proxy_ips: Vec::new(),
            },
            bootstrap_setup_secret_hash: None,
            signing: None,
            key_encryption_key: None,
        }
    }
}
