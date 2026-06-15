use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use cairn_authn::generate_secret;
use secrecy::ExposeSecret;
use serde_json::json;

use super::{AppState, api_response::ApiError, cookies::set_csrf_cookie};

mod bootstrap;
mod login;
mod password;
mod requests;

pub(super) use self::{
    bootstrap::bootstrap,
    login::{login, reauthenticate},
    password::change_password,
};

pub(super) async fn csrf_token(State(state): State<AppState>) -> Result<Response, ApiError> {
    let token = generate_secret(32);
    let token = token.expose_secret().to_owned();
    let mut response = Json(json!({ "csrf_token": token })).into_response();
    set_csrf_cookie(response.headers_mut(), &state.config, &token)?;
    Ok(response)
}
