use axum::{
    Router,
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware,
};
use std::time::Duration as StdDuration;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};

use crate::http::{
    AppState,
    cookies::CSRF_HEADER,
    security::{add_security_headers, http_trace_span},
};

pub(super) fn apply_router_layers(router: Router<AppState>, state: &AppState) -> Router<AppState> {
    let allowed_origin = HeaderValue::from_str(&state.config.public_web_origin)
        .unwrap_or_else(|_| HeaderValue::from_static("http://localhost:5173"));
    let cors = CorsLayer::new()
        .allow_origin(allowed_origin)
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            HeaderName::from_static(CSRF_HEADER),
        ]);
    let security_header_config = state.config.clone();

    router.layer(
        ServiceBuilder::new()
            .layer(TraceLayer::new_for_http().make_span_with(http_trace_span))
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                StdDuration::from_secs(30),
            ))
            .layer(middleware::from_fn_with_state(
                security_header_config,
                add_security_headers,
            ))
            .layer(cors),
    )
}
