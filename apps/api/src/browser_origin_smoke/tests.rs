use super::{
    resources::{
        browser_origin_resource_url, browser_origin_smoke_base_url, browser_origin_smoke_origin,
    },
    routes::browser_origin_mutation_routes,
};

#[test]
fn browser_origin_smoke_base_url_normalizes_origin_or_path_prefix() {
    let origin = browser_origin_smoke_base_url("https://id.example.com").expect("origin");
    assert_eq!(origin.as_str(), "https://id.example.com/");
    assert_eq!(
        browser_origin_resource_url(&origin, "api/v1/session/logout")
            .expect("resource URL")
            .as_str(),
        "https://id.example.com/api/v1/session/logout"
    );

    let prefixed =
        browser_origin_smoke_base_url("https://id.example.com/identity").expect("prefix");
    assert_eq!(
        browser_origin_resource_url(&prefixed, "api/v1/session/logout")
            .expect("resource URL")
            .as_str(),
        "https://id.example.com/identity/api/v1/session/logout"
    );
}

#[test]
fn browser_origin_smoke_rejects_unsafe_url_components() {
    for value in [
        "",
        "ftp://id.example.com",
        "https://user:pass@id.example.com",
        "https://id.example.com?debug=true",
        "https://id.example.com#fragment",
    ] {
        assert!(
            browser_origin_smoke_base_url(value).is_err(),
            "{value} should be rejected"
        );
    }

    for value in [
        "",
        "ftp://evil.example",
        "https://user:pass@evil.example",
        "https://evil.example/path",
        "https://evil.example?debug=true",
        "https://evil.example#fragment",
    ] {
        assert!(
            browser_origin_smoke_origin("TEST_HOSTILE_ORIGIN", value).is_err(),
            "{value} should be rejected"
        );
    }
}

#[test]
fn browser_origin_smoke_route_inventory_targets_mutating_api_paths() {
    let routes = browser_origin_mutation_routes();
    assert!(routes.len() >= 30);
    for route in routes {
        assert!(matches!(route.method, "POST" | "PUT" | "PATCH" | "DELETE"));
        assert!(route.path.starts_with("api/v1/"));
    }
}
