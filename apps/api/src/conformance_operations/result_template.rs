use super::{
    types::{
        OpenIdConformanceResultProfile, OpenIdConformanceResultTemplateProvenance,
        OpenIdConformanceResultTemplateReport, OpenIdConformanceResultTemplateSelectedInstance,
    },
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
        oidf_export_provenance: OpenIdConformanceResultTemplateProvenance {
            schema: "cairnid.oidf-export-provenance.v1",
            normalizer: "cairn-api conformance oidcc-normalize-export",
            source_format: "<zip|directory from normalizer output>",
            exported_from: "https://www.certification.openid.net/",
            suite_version: "<suite version from OIDF export>",
            plan_module_count: 0,
            test_log_count: 0,
            module_names: vec!["<module names from normalizer output>"],
            selected_instances: vec![OpenIdConformanceResultTemplateSelectedInstance {
                module_name: "<module name from normalizer output>",
                test_id: "<selected latest test instance from normalizer output>",
            }],
            plan_modules_sha256: "<64 lowercase hex SHA-256 from normalizer output>",
            test_logs_sha256: "<64 lowercase hex SHA-256 from normalizer output>",
        },
        accepted_results: vec!["PASSED", "WARNING"],
        required_updates: vec![
            "Run the matching OpenID Foundation certification plan against the production-like HTTPS issuer.",
            "Prefer cairn-api conformance oidcc-normalize-export to generate passing normalized evidence from the OIDF ZIP or unpacked export directory.",
            "If keeping this file as operator notes, do not hand-fill oidf_export_provenance; it is generated from index.json and matching selected/latest test logs.",
            "Set status to FINISHED only after the suite result is complete, but this alone is not sufficient release evidence.",
            "Set result to PASSED or WARNING only when the OIDF result supports that value, but this alone is not sufficient release evidence.",
            "Replace published_result_url with the official published result URL on www.certification.openid.net.",
        ],
        forbidden_fields: vec![
            "client_secret",
            "clientSecret",
            "authorization",
            "authorization_header",
            "bearer_token",
            "cookie",
            "id_token",
            "password",
            "private_key",
            "request_headers",
            "secret",
            "session_cookie",
            "token",
        ],
        operator_notes: vec![
            "This template is not release evidence; passing normalized summaries must include oidf_export_provenance emitted by oidcc-normalize-export.",
            "cairnid evidence check rejects status=\"template\", result=\"pending\", placeholder timestamps, non-official result URLs, and placeholder provenance.",
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
