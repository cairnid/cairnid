mod notes;
mod requirements;

use self::notes::{evidence_capture_is_manual, evidence_operator_notes};
use self::requirements::{evidence_environment_requirements, missing_environment_for_requirements};
use super::registry::{EvidenceSpec, evidence_validator_name};
use super::{ReleaseEvidencePlanReport, ReleaseEvidencePlanStep};
use std::collections::BTreeSet;
use time::OffsetDateTime;

pub(super) fn release_evidence_capture_plan_from_specs<F>(
    specs: &[EvidenceSpec],
    generated_at: OffsetDateTime,
    environment_present: F,
) -> ReleaseEvidencePlanReport
where
    F: Fn(&'static str) -> bool,
{
    let steps = specs
        .iter()
        .map(|spec| {
            let required_environment = evidence_environment_requirements(spec.validator);
            let missing_environment = missing_environment_for_requirements(
                spec.name,
                &required_environment,
                &environment_present,
            );
            let manual = evidence_capture_is_manual(spec.validator);
            let status = if missing_environment.is_empty() {
                if manual { "manual_external" } else { "ready" }
            } else {
                "missing_environment"
            };

            ReleaseEvidencePlanStep {
                name: spec.name,
                file_name: spec.file_name,
                command: spec.command,
                validator: evidence_validator_name(spec.validator),
                status,
                contains_secrets: spec.contains_secrets,
                requires_production_like_environment: spec.requires_production_like_environment,
                writes_application_state: spec.writes_application_state,
                touches_external_provider: spec.touches_external_provider,
                required_environment,
                missing_environment,
                operator_notes: evidence_operator_notes(spec),
            }
        })
        .collect::<Vec<_>>();
    let missing_environment = steps
        .iter()
        .flat_map(|step| step.missing_environment.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    ReleaseEvidencePlanReport {
        status: if missing_environment.is_empty() {
            "ready"
        } else {
            "missing_environment"
        },
        generated_at,
        artifact_count: steps.len(),
        ready_artifact_count: steps.iter().filter(|step| step.status == "ready").count(),
        manual_artifact_count: steps
            .iter()
            .filter(|step| step.status == "manual_external")
            .count(),
        missing_environment_artifact_count: steps
            .iter()
            .filter(|step| step.status == "missing_environment")
            .count(),
        secret_artifact_count: specs.iter().filter(|spec| spec.contains_secrets).count(),
        state_changing_artifact_count: specs
            .iter()
            .filter(|spec| spec.writes_application_state)
            .count(),
        external_provider_artifact_count: specs
            .iter()
            .filter(|spec| spec.touches_external_provider)
            .count(),
        steps,
        missing_environment,
        notes: vec![
            "This plan only reports whether required command inputs are present; it never prints environment values.",
            "Run public-beta evidence with CAIRN_ENV=production and production-like HTTPS origins.",
            "A ready plan is not release approval; collect artifacts and run evidence-check.",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::super::registry::EVIDENCE_SPECS;
    use super::release_evidence_capture_plan_from_specs;
    use time::OffsetDateTime;

    #[test]
    fn capture_plan_reports_missing_inputs_without_environment_values() {
        let report =
            release_evidence_capture_plan_from_specs(EVIDENCE_SPECS, generated_at(), |name| {
                matches!(name, "CAIRN_ISSUER" | "DATABASE_URL")
            });

        assert_eq!(report.status, "missing_environment");
        assert!(
            report
                .missing_environment
                .iter()
                .any(|failure| failure.contains("CAIRN_ENV"))
        );
        assert!(
            report
                .missing_environment
                .iter()
                .all(|failure| !failure.contains("postgres://") && !failure.contains("raw-token"))
        );
    }

    #[test]
    fn capture_plan_marks_external_manual_evidence_when_inputs_are_present() {
        let report =
            release_evidence_capture_plan_from_specs(EVIDENCE_SPECS, generated_at(), |_| true);

        let openid = report
            .steps
            .iter()
            .find(|step| step.name == "openid_config_op_conformance")
            .expect("OpenID Config OP step");
        let okta = report
            .steps
            .iter()
            .find(|step| step.name == "scim_okta_connector_smoke")
            .expect("Okta connector-smoke step");

        assert_eq!(openid.status, "manual_external");
        assert_eq!(okta.status, "manual_external");
        assert!(
            openid
                .operator_notes
                .iter()
                .any(|note| note.contains("OpenID Foundation conformance suite"))
        );
        assert!(
            okta.operator_notes
                .iter()
                .any(|note| note.contains("connector-smoke-template"))
        );
    }

    fn generated_at() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2026-06-07T12:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("valid test timestamp")
    }
}
