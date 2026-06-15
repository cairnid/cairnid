use reqwest::StatusCode;

#[derive(Debug, Clone, Copy)]
pub(super) struct SecurityHeaderTarget {
    pub(super) service: &'static str,
    pub(super) path: &'static str,
    pub(super) expected_status: StatusCode,
    pub(super) csp_contains: &'static str,
    pub(super) cache_control_no_store: Option<bool>,
}

pub(super) fn security_header_targets() -> &'static [SecurityHeaderTarget] {
    &[
        SecurityHeaderTarget {
            service: "api",
            path: "/healthz",
            expected_status: StatusCode::OK,
            csp_contains: "default-src 'none'",
            cache_control_no_store: None,
        },
        SecurityHeaderTarget {
            service: "api",
            path: "/.well-known/openid-configuration",
            expected_status: StatusCode::OK,
            csp_contains: "default-src 'none'",
            cache_control_no_store: None,
        },
        SecurityHeaderTarget {
            service: "web",
            path: "/healthz",
            expected_status: StatusCode::OK,
            csp_contains: "default-src 'self'",
            cache_control_no_store: Some(true),
        },
        SecurityHeaderTarget {
            service: "web",
            path: "/login",
            expected_status: StatusCode::OK,
            csp_contains: "default-src 'self'",
            cache_control_no_store: None,
        },
    ]
}
