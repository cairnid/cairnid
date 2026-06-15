use super::{
    types::{OpenIdConformanceResultProfile, OpenIdConformanceResultTemplateReport},
    validation::config_error,
};
use time::OffsetDateTime;

pub(super) fn openid_conformance_result_template(
    profile: &str,
) -> Result<OpenIdConformanceResultTemplateReport, Box<dyn std::error::Error>> {
    let profile = openid_conformance_result_profile(profile)?;

    Ok(OpenIdConformanceResultTemplateReport {
        generated_at: OffsetDateTime::now_utc(),
        source: "openid-conformance-suite",
        status: "template",
        result: "pending",
        certification_profile: profile.certification_profile,
        plan_name: profile.plan_name,
        completed_at: "<replace with RFC3339 completion timestamp from the OIDF result>",
        published_result_url: "https://www.certification.openid.net/published-result-url",
        accepted_results: vec!["PASSED", "WARNING"],
        required_updates: vec![
            "Run the matching OpenID Foundation certification plan against the production-like HTTPS issuer.",
            "Replace completed_at with the suite completion or publication timestamp.",
            "Replace published_result_url with the official published result URL on www.certification.openid.net.",
            "Set status to FINISHED only after the suite result is complete.",
            "Set result to PASSED or WARNING only when the OIDF result supports that value.",
        ],
        forbidden_fields: vec![
            "client_secret",
            "clientSecret",
            "authorization",
            "authorization_header",
            "cookie",
            "password",
        ],
        operator_notes: vec![
            "This template is not release evidence until the external OIDF suite run is complete.",
            "operations evidence-check rejects status=\"template\", result=\"pending\", placeholder timestamps, and non-official result URLs.",
            "Do not include static-client secrets, cookies, request headers, passwords, screenshots, or browser session data in normalized result summaries.",
        ],
    })
}

pub(super) fn openid_conformance_result_profile(
    profile: &str,
) -> Result<OpenIdConformanceResultProfile, Box<dyn std::error::Error>> {
    match profile.trim().to_ascii_lowercase().as_str() {
        "config-op" | "config" | "configuration" | "oidcc-config-certification-test-plan" => {
            Ok(OpenIdConformanceResultProfile {
                certification_profile: "Config OP",
                plan_name: "oidcc-config-certification-test-plan",
            })
        }
        "basic-op" | "basic" | "oidcc-basic-certification-test-plan" => {
            Ok(OpenIdConformanceResultProfile {
                certification_profile: "Basic OP",
                plan_name: "oidcc-basic-certification-test-plan",
            })
        }
        _ => Err(config_error(
            "OpenID conformance result template profile must be config-op or basic-op",
        )),
    }
}
