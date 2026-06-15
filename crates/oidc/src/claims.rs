use cairn_domain::{OidcClient, User};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

use crate::{OidcError, SigningMaterial};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
}

pub struct IdTokenIssueRequest<'a> {
    pub issuer: &'a str,
    pub client: &'a OidcClient,
    pub user: &'a User,
    pub scopes: &'a [String],
    pub nonce: Option<String>,
    pub auth_time: Option<OffsetDateTime>,
    pub amr: Vec<String>,
    pub acr: String,
    pub groups: Option<Vec<String>>,
    pub signing: &'a SigningMaterial,
}

pub fn issue_id_token(request: IdTokenIssueRequest<'_>) -> Result<String, OidcError> {
    let now = OffsetDateTime::now_utc();
    let claims = IdTokenClaims {
        iss: request.issuer.trim_end_matches('/').to_owned(),
        sub: request.user.id.to_string(),
        aud: request.client.client_id.clone(),
        exp: (now + Duration::minutes(10)).unix_timestamp(),
        iat: now.unix_timestamp(),
        auth_time: request
            .auth_time
            .map(|auth_time| auth_time.unix_timestamp()),
        nonce: request.nonce,
        email: scope_requested(request.scopes, "email").then(|| request.user.email.clone()),
        email_verified: scope_requested(request.scopes, "email")
            .then_some(request.user.email_verified),
        name: scope_requested(request.scopes, "profile").then(|| request.user.display_name.clone()),
        amr: Some(request.amr),
        acr: Some(request.acr),
        groups: request.groups,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(request.signing.key_id.clone());

    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(request.signing.private_key_pem.as_bytes())
            .map_err(|_| OidcError::TokenSigning)?,
    )
    .map_err(|_| OidcError::TokenSigning)
}

fn scope_requested(scopes: &[String], expected: &str) -> bool {
    scopes.iter().any(|scope| scope == expected)
}

pub fn validate_logout_id_token_hint(
    id_token_hint: &str,
    issuer: &str,
    client: &OidcClient,
    signing: &SigningMaterial,
) -> Result<IdTokenClaims, OidcError> {
    let claims = validate_logout_id_token_hint_issuer(id_token_hint, issuer, signing)?;
    if claims.aud != client.client_id {
        return Err(OidcError::InvalidIdTokenHint);
    }
    Ok(claims)
}

pub fn validate_logout_id_token_hint_issuer(
    id_token_hint: &str,
    issuer: &str,
    signing: &SigningMaterial,
) -> Result<IdTokenClaims, OidcError> {
    let header = decode_header(id_token_hint).map_err(|_| OidcError::InvalidIdTokenHint)?;
    if header.alg != Algorithm::RS256 || header.kid.as_deref() != Some(signing.key_id.as_str()) {
        return Err(OidcError::InvalidIdTokenHint);
    }

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_issuer(&[issuer.trim_end_matches('/')]);

    decode::<IdTokenClaims>(
        id_token_hint,
        &decoding_key_from_public_jwk(&signing.public_jwk)?,
        &validation,
    )
    .map(|token| token.claims)
    .map_err(|_| OidcError::InvalidIdTokenHint)
}

fn decoding_key_from_public_jwk(jwk: &Value) -> Result<DecodingKey, OidcError> {
    let modulus = jwk
        .get("n")
        .and_then(Value::as_str)
        .ok_or(OidcError::InvalidIdTokenHint)?;
    let exponent = jwk
        .get("e")
        .and_then(Value::as_str)
        .ok_or(OidcError::InvalidIdTokenHint)?;
    DecodingKey::from_rsa_components(modulus, exponent).map_err(|_| OidcError::InvalidIdTokenHint)
}

pub fn userinfo(user: &User, scopes: &[String], groups: Option<Vec<String>>) -> Value {
    let mut value = json!({
        "sub": user.id.to_string(),
    });

    if scope_requested(scopes, "email") {
        value["email"] = json!(user.email);
        value["email_verified"] = json!(user.email_verified);
    }
    if scope_requested(scopes, "profile") {
        value["name"] = json!(user.display_name);
    }
    if let Some(groups) = groups {
        value["groups"] = json!(groups);
    }

    value
}
