use axum::http::StatusCode;
use cairn_domain::{OidcClient, OidcGrantType};
use cairn_oidc::{OAuthErrorBody, parse_scopes};

use super::super::api_response::ApiError;

pub(in crate::http) fn should_issue_refresh_token(scopes: &[String], client: &OidcClient) -> bool {
    client.allows_grant(OidcGrantType::RefreshToken)
        && scopes.iter().any(|scope| scope == "offline_access")
}

pub(in crate::http) fn token_response_scope(scopes: &[String]) -> Option<String> {
    (!scopes.is_empty()).then(|| scopes.join(" "))
}

pub(in crate::http) fn token_request_scopes(
    scope: Option<&str>,
) -> Result<Option<Vec<String>>, ApiError> {
    let Some(scope) = scope else {
        return Ok(None);
    };
    parse_scopes(scope).map(Some).map_err(|_| {
        ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_scope("invalid scope"),
        )
    })
}

pub(in crate::http) fn refresh_token_granted_scopes(
    requested_scope: Option<&str>,
    original_scopes: &[String],
) -> Result<Vec<String>, ApiError> {
    let Some(requested_scopes) = token_request_scopes(requested_scope)? else {
        return Ok(original_scopes.to_vec());
    };
    if requested_scopes
        .iter()
        .any(|scope| !original_scopes.iter().any(|granted| granted == scope))
    {
        return Err(ApiError::oauth(
            StatusCode::BAD_REQUEST,
            OAuthErrorBody::invalid_scope("requested scope exceeds original grant"),
        ));
    }
    Ok(requested_scopes)
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use cairn_domain::{OidcClient, OidcClientStatus, OidcGrantType, RedirectUri};
    use cairn_oidc::TokenResponse;
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::super::super::api_response::ApiError;
    use super::{
        refresh_token_granted_scopes, should_issue_refresh_token, token_request_scopes,
        token_response_scope,
    };

    #[test]
    fn token_response_scope_omits_empty_scope_and_serializes_granted_scope() {
        let empty_scopes: Vec<String> = Vec::new();
        assert_eq!(token_response_scope(&empty_scopes), None);

        let no_scope_payload = serde_json::to_value(TokenResponse {
            access_token: "access-token".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: 900,
            refresh_token: None,
            id_token: None,
            scope: token_response_scope(&empty_scopes),
        })
        .expect("token response serializes");
        assert!(
            !no_scope_payload
                .as_object()
                .expect("token response is an object")
                .contains_key("scope")
        );

        let granted_scopes = vec!["openid".to_owned(), "profile".to_owned()];
        assert_eq!(
            token_response_scope(&granted_scopes),
            Some("openid profile".to_owned())
        );

        let scoped_payload = serde_json::to_value(TokenResponse {
            access_token: "access-token".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: 900,
            refresh_token: None,
            id_token: None,
            scope: token_response_scope(&granted_scopes),
        })
        .expect("token response serializes");
        assert_eq!(scoped_payload["scope"], json!("openid profile"));
    }

    #[test]
    fn token_request_scopes_enforce_oauth_scope_syntax_and_preserve_order() {
        assert_eq!(token_request_scopes(None).expect("no scope is valid"), None);
        assert_eq!(
            token_request_scopes(Some("openid profile openid")).expect("valid duplicated scopes"),
            Some(vec!["openid".to_owned(), "profile".to_owned()])
        );
        assert_eq!(
            token_request_scopes(Some("read:users write.users")).expect("valid punctuation scopes"),
            Some(vec!["read:users".to_owned(), "write.users".to_owned()])
        );

        for scope in [
            "",
            "openid  profile",
            " openid",
            "openid ",
            "openid\tprofile",
            "bad\"scope",
            "bad\\scope",
            "caf\u{e9}",
        ] {
            assert!(matches!(
                token_request_scopes(Some(scope)),
                Err(ApiError::OAuth {
                    status: StatusCode::BAD_REQUEST,
                    ref body,
                }) if body.error == "invalid_scope"
                    && body.error_description.as_deref() == Some("invalid scope")
            ));
        }
    }

    #[test]
    fn refresh_token_scope_requests_can_only_narrow_original_grant() {
        let original_scopes = vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "offline_access".to_owned(),
        ];

        assert_eq!(
            refresh_token_granted_scopes(None, &original_scopes).expect("omitted scope"),
            original_scopes
        );
        assert_eq!(
            refresh_token_granted_scopes(Some("openid profile"), &original_scopes)
                .expect("narrowed scope"),
            vec!["openid".to_owned(), "profile".to_owned()]
        );
        assert!(matches!(
            refresh_token_granted_scopes(Some("openid admin"), &original_scopes),
            Err(ApiError::OAuth {
                status: StatusCode::BAD_REQUEST,
                ref body,
            }) if body.error == "invalid_scope"
                && body.error_description.as_deref()
                    == Some("requested scope exceeds original grant")
        ));
    }

    #[test]
    fn refresh_tokens_require_offline_access_and_refresh_grant() {
        let organization_id = Uuid::new_v4();
        let mut client = test_oidc_client(organization_id);
        let offline_scopes = vec!["openid".to_owned(), "offline_access".to_owned()];
        let online_scopes = vec!["openid".to_owned(), "profile".to_owned()];

        assert!(should_issue_refresh_token(&offline_scopes, &client));
        assert!(!should_issue_refresh_token(&online_scopes, &client));

        client.grant_types = vec![OidcGrantType::AuthorizationCode];
        assert!(!should_issue_refresh_token(&offline_scopes, &client));
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
            post_logout_redirect_uris: Vec::new(),
            allowed_scopes: vec!["openid".to_owned(), "profile".to_owned()],
            grant_types: vec![
                OidcGrantType::AuthorizationCode,
                OidcGrantType::RefreshToken,
                OidcGrantType::ClientCredentials,
            ],
            public_client: false,
            require_pkce: true,
            status: OidcClientStatus::Active,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}
