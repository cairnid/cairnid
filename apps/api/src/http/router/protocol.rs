use axum::{
    Router,
    routing::{get, post},
};

use crate::http::{
    AppState,
    oauth_routes::{introspect, revoke, token, userinfo_route},
    oidc_browser_routes::{authorize, end_session, end_session_post},
    public_metadata::{healthz, jwks, openid_configuration},
};

pub(super) fn protocol_routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks))
        .route("/oauth2/authorize", get(authorize))
        .route("/oauth2/logout", get(end_session).post(end_session_post))
        .route("/oauth2/token", post(token))
        .route("/oauth2/userinfo", userinfo_route())
        .route("/oauth2/introspect", post(introspect))
        .route("/oauth2/revoke", post(revoke))
}
