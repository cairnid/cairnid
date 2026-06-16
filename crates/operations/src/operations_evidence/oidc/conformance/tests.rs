use super::validate_openid_conformance_result;
use serde_json::json;

#[test]
fn openid_conformance_rejects_wrong_origin_and_secret_fields() {
    let value = json!({
        "source": "openid-conformance-suite",
        "plan_name": "oidcc-config-certification-test-plan",
        "completed_at": "2026-06-07T12:00:00Z",
        "status": "FINISHED",
        "result": "PASSED",
        "published_result_url": "https://suite.example.com/plan-detail.html?plan=config-op",
        "evidence": {
            "clientSecret": "must-not-be-archived"
        }
    });
    let mut checks = Vec::new();
    let mut failures = Vec::new();

    validate_openid_conformance_result(
        &value,
        "Config OP",
        "oidcc-config-certification-test-plan",
        &mut checks,
        &mut failures,
    );

    assert!(failures.iter().any(|failure| {
        failure
            == "$.evidence.clientSecret must not be present in token-free OpenID result evidence"
    }));
    assert!(failures.iter().any(|failure| {
        failure
            .contains("published_result_url must be an HTTPS URL on www.certification.openid.net")
    }));
}
