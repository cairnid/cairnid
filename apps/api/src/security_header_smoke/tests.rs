use super::{
    resources::{security_header_resource_url, security_header_smoke_origin},
    targets::security_header_targets,
};

#[test]
fn security_header_smoke_origins_must_be_https_origins() {
    let api = security_header_smoke_origin("TEST_API_ORIGIN", "https://id.example.com")
        .expect("valid origin");
    assert_eq!(api.as_str(), "https://id.example.com/");

    for value in [
        "",
        "http://id.example.com",
        "https://user:pass@id.example.com",
        "https://id.example.com/path",
        "https://id.example.com?debug=true",
        "https://id.example.com#fragment",
    ] {
        assert!(
            security_header_smoke_origin("TEST_API_ORIGIN", value).is_err(),
            "{value} should be rejected"
        );
    }
}

#[test]
fn security_header_smoke_targets_stable_api_and_web_paths() {
    let targets = security_header_targets();
    assert_eq!(targets.len(), 4);
    assert!(targets.iter().any(|target| target.service == "api"));
    assert!(targets.iter().any(|target| target.service == "web"));
    for target in targets {
        assert!(target.path.starts_with('/'));
    }
}

#[test]
fn security_header_smoke_resource_url_joins_origin_paths() {
    let origin = security_header_smoke_origin("TEST_API_ORIGIN", "https://id.example.com")
        .expect("valid origin");
    assert_eq!(
        security_header_resource_url(&origin, "/healthz")
            .expect("resource URL")
            .as_str(),
        "https://id.example.com/healthz"
    );
}
