use axum::http::StatusCode;
use cairn_authn::generate_hashed_secret;
use cairn_domain::{OidcClient, OidcClientStatus, OidcGrantType, RedirectUri};
use secrecy::ExposeSecret;
use time::OffsetDateTime;
use uuid::Uuid;

use super::super::{api_response::ApiError, oauth_http::OAuthClientAuth};
use super::{
    authenticate_oauth_client, bearer_token_matches_organization,
    require_client_bound_to_stored_grant, require_confidential_client_credentials_client,
    require_oauth_client_organization, require_stored_token_organization,
    require_token_endpoint_grant,
};

#[test]
fn oauth_client_authenticates_public_and_confidential_clients() {
    let mut public_client = test_oidc_client(Uuid::new_v4());
    let public_auth = OAuthClientAuth {
        client_id: Some(public_client.client_id.clone()),
        client_secret: None,
    };
    let public_auth_with_secret = OAuthClientAuth {
        client_id: Some(public_client.client_id.clone()),
        client_secret: Some("unexpected".to_owned()),
    };

    assert!(authenticate_oauth_client(&public_client, &public_auth).is_ok());
    assert!(authenticate_oauth_client(&public_client, &public_auth_with_secret).is_err());

    let generated_secret = generate_hashed_secret(32);
    public_client.public_client = false;
    public_client.client_secret_hash = Some(generated_secret.hash);
    let confidential_auth = OAuthClientAuth {
        client_id: Some(public_client.client_id.clone()),
        client_secret: Some(generated_secret.value.expose_secret().to_owned()),
    };
    let wrong_secret = OAuthClientAuth {
        client_id: Some(public_client.client_id.clone()),
        client_secret: Some("wrong-secret".to_owned()),
    };

    assert!(authenticate_oauth_client(&public_client, &confidential_auth).is_ok());
    assert!(authenticate_oauth_client(&public_client, &wrong_secret).is_err());
}

#[test]
fn token_endpoint_grant_denial_uses_unauthorized_client_error() {
    let mut client = test_oidc_client(Uuid::new_v4());
    client.grant_types = vec![OidcGrantType::AuthorizationCode];

    let error = require_token_endpoint_grant(&client, OidcGrantType::ClientCredentials)
        .expect_err("client_credentials should be disallowed");

    assert!(matches!(
        error,
        ApiError::OAuth {
            status: StatusCode::BAD_REQUEST,
            ref body,
        } if body.error == "unauthorized_client"
            && body.error_description.as_deref()
                == Some("client is not authorized to use client_credentials")
    ));
    assert!(require_token_endpoint_grant(&client, OidcGrantType::AuthorizationCode).is_ok());
}

#[test]
fn client_credentials_grant_requires_confidential_client() {
    let public_client = test_oidc_client(Uuid::new_v4());
    let public_error = require_confidential_client_credentials_client(&public_client)
        .expect_err("public client must not use client_credentials");
    assert!(matches!(
        public_error,
        ApiError::OAuth {
            status: StatusCode::UNAUTHORIZED,
            ref body,
        } if body.error == "invalid_client"
    ));

    let mut malformed_confidential = public_client.clone();
    malformed_confidential.public_client = false;
    let malformed_error = require_confidential_client_credentials_client(&malformed_confidential)
        .expect_err("confidential client needs a stored secret");
    assert!(matches!(
        malformed_error,
        ApiError::OAuth {
            status: StatusCode::UNAUTHORIZED,
            ref body,
        } if body.error == "invalid_client"
    ));

    let mut confidential = malformed_confidential;
    confidential.client_secret_hash = Some("stored-hash".to_owned());
    assert!(require_confidential_client_credentials_client(&confidential).is_ok());
}

#[test]
fn stored_grant_client_binding_rejects_other_client() {
    let organization_id = Uuid::new_v4();
    let client = test_oidc_client(organization_id);

    assert!(require_client_bound_to_stored_grant(&client, organization_id, client.id).is_ok());
    assert!(require_client_bound_to_stored_grant(&client, Uuid::new_v4(), client.id).is_err());
    assert!(
        require_client_bound_to_stored_grant(&client, organization_id, Uuid::new_v4()).is_err()
    );
}

#[test]
fn oauth_client_auth_is_tenant_bound() {
    let organization_id = Uuid::new_v4();
    let client = test_oidc_client(organization_id);

    assert!(require_oauth_client_organization(&client, organization_id).is_ok());
    assert!(matches!(
        require_oauth_client_organization(&client, Uuid::new_v4()),
        Err(ApiError::OAuth {
            status: StatusCode::UNAUTHORIZED,
            ..
        })
    ));
}

#[test]
fn oauth_tokens_must_match_current_tenant() {
    let organization_id = Uuid::new_v4();

    assert!(require_stored_token_organization(organization_id, organization_id).is_ok());
    assert!(matches!(
        require_stored_token_organization(Uuid::new_v4(), organization_id),
        Err(ApiError::OAuth {
            status: StatusCode::BAD_REQUEST,
            ..
        })
    ));

    assert!(bearer_token_matches_organization(
        organization_id,
        organization_id
    ));
    assert!(!bearer_token_matches_organization(
        Uuid::new_v4(),
        organization_id
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
