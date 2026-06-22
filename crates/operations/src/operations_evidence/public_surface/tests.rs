use super::{validate_browser_origin_smoke, validate_security_headers_smoke};
use serde_json::json;

#[test]
fn browser_origin_smoke_accepts_mutating_api_route_matrix() {
    let value = json!({
        "status": "ok",
        "base_url": "https://id.example.com",
        "hostile_origin": "https://browser-origin-smoke.invalid",
        "completed_at": "2026-06-07T12:00:00Z",
        "routes_checked": 2,
        "checks": [
            {
                "name": "admin-user-create",
                "method": "POST",
                "path": "/api/v1/users",
                "status": "passed",
                "origin_status": 403,
                "referer_status": 403,
                "no_store": true,
                "pragma_no_cache": true,
                "content_type_options_nosniff": true
            },
            {
                "name": "group-delete",
                "method": "DELETE",
                "path": "/api/v1/groups/example",
                "status": "passed",
                "origin_status": 403,
                "referer_status": 403,
                "no_store": true,
                "pragma_no_cache": true,
                "content_type_options_nosniff": true
            }
        ]
    });
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_browser_origin_smoke(&value, &mut checks, &mut failures);

    assert!(failures.is_empty(), "{failures:?}");
    assert!(
        checks.contains(&"browser-origin smoke rejected hostile Origin and Referer".to_owned())
    );
    assert!(
        checks.contains(&"browser-origin smoke covered mutating /api/v1 route classes".to_owned())
    );
}

#[test]
fn browser_origin_smoke_rejects_read_routes_and_mismatched_route_count() {
    let value = json!({
        "status": "ok",
        "base_url": "https://id.example.com",
        "hostile_origin": "https://browser-origin-smoke.invalid",
        "completed_at": "2026-06-07T12:00:00Z",
        "routes_checked": 2,
        "checks": [
            {
                "name": "bad-read-route",
                "method": "GET",
                "path": "/admin/users",
                "status": "passed",
                "origin_status": 200,
                "referer_status": 403,
                "no_store": true,
                "pragma_no_cache": true,
                "content_type_options_nosniff": true
            }
        ]
    });
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_browser_origin_smoke(&value, &mut checks, &mut failures);

    assert!(
        failures
            .iter()
            .any(|failure| failure == "routes_checked must match checks length")
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("checks[0].method must be POST"))
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("checks[0].path must be a /api/v1/ route"))
    );
}

#[test]
fn security_headers_smoke_accepts_exact_deployed_smoke_coverage() {
    let value = security_headers_smoke(complete_security_header_checks());
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_security_headers_smoke(&value, &mut checks, &mut failures);

    assert!(failures.is_empty(), "{failures:?}");
    assert!(checks.contains(&"API and web security headers passed deployed smoke".to_owned()));
}

#[test]
fn security_headers_smoke_rejects_missing_expected_path() {
    let value = security_headers_smoke(vec![
        security_header_check("api", "/healthz"),
        security_header_check("api", "/.well-known/openid-configuration"),
        security_header_check("web", "/healthz"),
    ]);
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_security_headers_smoke(&value, &mut checks, &mut failures);

    assert!(
        failures.iter().any(|failure| failure
            == "checks must include deployed security-header check for web /login")
    );
}

#[test]
fn security_headers_smoke_rejects_duplicate_path() {
    let mut smoke_checks = complete_security_header_checks();
    smoke_checks.push(security_header_check("api", "/healthz"));
    let value = security_headers_smoke(smoke_checks);
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_security_headers_smoke(&value, &mut checks, &mut failures);

    assert!(
        failures
            .iter()
            .any(|failure| failure == "checks[4] duplicates checks[0] for api /healthz")
    );
}

#[test]
fn security_headers_smoke_rejects_unexpected_path_service_and_bad_path() {
    let mut smoke_checks = complete_security_header_checks();
    smoke_checks.push(security_header_check("api", "/.well-known/jwks.json"));
    smoke_checks.push(security_header_check("admin", "/healthz"));
    smoke_checks.push(security_header_check("web", "login"));
    let value = security_headers_smoke(smoke_checks);
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_security_headers_smoke(&value, &mut checks, &mut failures);

    assert!(failures.iter().any(|failure| {
        failure
            == "checks[4] must target one of the deployed security-header smoke paths, got api /.well-known/jwks.json"
    }));
    assert!(
        failures
            .iter()
            .any(|failure| failure == "checks[5].service must be api or web, got admin")
    );
    assert!(
        failures
            .iter()
            .any(|failure| failure == "checks[6].path must start with /, got login")
    );
}

#[test]
fn security_headers_smoke_preserves_per_check_header_validation() {
    let mut smoke_checks = complete_security_header_checks();
    smoke_checks[2]["cache_control_no_store"] = json!(false);
    smoke_checks[2]["strict_transport_security"] = json!(false);
    let value = security_headers_smoke(smoke_checks);
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_security_headers_smoke(&value, &mut checks, &mut failures);

    assert!(failures.iter().any(|failure| {
        failure == "checks[2].cache_control_no_store must be true or null when present"
    }));
    assert!(
        failures
            .iter()
            .any(|failure| failure == "strict_transport_security must be true, got false")
    );
}

fn security_headers_smoke(checks: Vec<serde_json::Value>) -> serde_json::Value {
    json!({
        "status": "ok",
        "api_base_url": "https://id.example.com",
        "web_base_url": "https://app.example.com",
        "completed_at": "2026-06-07T12:00:00Z",
        "checks": checks
    })
}

fn complete_security_header_checks() -> Vec<serde_json::Value> {
    vec![
        security_header_check("api", "/healthz"),
        security_header_check("api", "/.well-known/openid-configuration"),
        security_header_check("web", "/healthz"),
        security_header_check("web", "/login"),
    ]
}

fn security_header_check(service: &str, path: &str) -> serde_json::Value {
    json!({
        "service": service,
        "path": path,
        "status": "passed",
        "status_code": 200,
        "content_security_policy": true,
        "strict_transport_security": true,
        "x_content_type_options_nosniff": true,
        "x_frame_options_deny": true,
        "referrer_policy_no_referrer": true,
        "permissions_policy_restrictive": true,
        "cross_origin_opener_policy_same_origin": true,
        "cache_control_no_store": true
    })
}
