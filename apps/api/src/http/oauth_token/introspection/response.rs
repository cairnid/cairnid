use cairn_domain::{OidcClient, UserId};
use serde_json::{Value, json};
use time::OffsetDateTime;

pub(in crate::http) fn active_introspection_response(
    issuer: &str,
    client: &OidcClient,
    scopes: &[String],
    user_id: Option<UserId>,
    token_type: Option<&str>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> Value {
    let mut response = json!({
        "active": true,
        "client_id": client.client_id,
        "iss": issuer.trim_end_matches('/'),
        "iat": created_at.unix_timestamp(),
        "exp": expires_at.unix_timestamp(),
    });
    if !scopes.is_empty() {
        response["scope"] = json!(scopes.join(" "));
    }
    if let Some(user_id) = user_id {
        response["sub"] = json!(user_id.to_string());
    }
    if let Some(token_type) = token_type {
        response["token_type"] = json!(token_type);
    }

    response
}

pub(in crate::http) fn inactive_introspection_response() -> Value {
    json!({ "active": false })
}
