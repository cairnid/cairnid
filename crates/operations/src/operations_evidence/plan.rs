mod notes;
mod requirements;

use self::notes::{evidence_capture_is_manual, evidence_operator_notes};
use self::requirements::{evidence_environment_requirements, missing_environment_for_requirements};
use super::registry::{EvidenceSpec, evidence_validator_name};
use super::{
    RELEASE_EVIDENCE_SCHEMA_VERSION, ReleaseEvidencePlanPendingArtifact, ReleaseEvidencePlanReport,
    ReleaseEvidencePlanStep,
};
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
            let pending_external_evidence = spec.touches_external_provider;
            let status = if missing_environment.is_empty() {
                if manual { "manual_external" } else { "ready" }
            } else {
                "missing_environment"
            };

            ReleaseEvidencePlanStep {
                name: spec.name,
                file_name: spec.file_name,
                release_gate: spec.release_gate,
                command: spec.command,
                validator: evidence_validator_name(spec.validator),
                status,
                pending_manual_evidence: manual,
                pending_external_evidence,
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
    let pending_manual_evidence = steps
        .iter()
        .filter(|step| step.pending_manual_evidence)
        .map(pending_artifact_from_step)
        .collect::<Vec<_>>();
    let pending_external_evidence = steps
        .iter()
        .filter(|step| step.pending_external_evidence)
        .map(pending_artifact_from_step)
        .collect::<Vec<_>>();
    let local_capture_ready = missing_environment.is_empty();
    let manual_pending_count = pending_manual_evidence.len();
    let external_pending_count = pending_external_evidence.len();

    ReleaseEvidencePlanReport {
        schema_version: RELEASE_EVIDENCE_SCHEMA_VERSION,
        status: if local_capture_ready {
            "ready"
        } else {
            "missing_environment"
        },
        generated_at,
        local_capture_ready,
        manual_evidence_pending: manual_pending_count > 0,
        external_evidence_pending: external_pending_count > 0,
        artifact_count: steps.len(),
        ready_artifact_count: steps.iter().filter(|step| step.status == "ready").count(),
        manual_artifact_count: steps
            .iter()
            .filter(|step| step.status == "manual_external")
            .count(),
        manual_pending_count,
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
        external_pending_count,
        pending_manual_evidence,
        pending_external_evidence,
        steps,
        missing_environment,
        notes: vec![
            "This plan only reports whether required command inputs are present; it never prints environment values.",
            "Run first-public-RC evidence with CAIRN_ENV=production and production-like HTTPS origins where the artifact requires them.",
            "status=\"ready\" means local/generated capture prerequisites are present; it does not mean manual or provider-backed evidence has been captured.",
            "Review pending_manual_evidence and pending_external_evidence before collecting artifacts, then run cairnid evidence check.",
        ],
    }
}

fn pending_artifact_from_step(
    step: &ReleaseEvidencePlanStep,
) -> ReleaseEvidencePlanPendingArtifact {
    ReleaseEvidencePlanPendingArtifact {
        name: step.name,
        file_name: step.file_name,
        release_gate: step.release_gate,
        status: step.status,
    }
}

#[cfg(test)]
mod tests {
    use super::super::registry::{EVIDENCE_SPECS, EvidenceSpec, EvidenceValidator};
    use super::release_evidence_capture_plan_from_specs;
    use time::OffsetDateTime;

    #[test]
    fn release_evidence_plan_reports_missing_inputs_without_environment_values() {
        let report =
            release_evidence_capture_plan_from_specs(EVIDENCE_SPECS, generated_at(), |name| {
                matches!(name, "CAIRN_ISSUER" | "DATABASE_URL")
            });

        assert_eq!(report.status, "missing_environment");
        assert!(!report.local_capture_ready);
        assert!(report.manual_evidence_pending);
        assert!(report.external_evidence_pending);
        assert_eq!(report.manual_pending_count, 5);
        assert_eq!(report.pending_manual_evidence.len(), 5);
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
    fn release_evidence_plan_marks_external_manual_evidence_when_inputs_are_present() {
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
        assert!(openid.pending_manual_evidence);
        assert!(openid.pending_external_evidence);
        assert_eq!(okta.status, "manual_external");
        assert!(okta.pending_manual_evidence);
        assert!(okta.pending_external_evidence);
        assert!(report.local_capture_ready);
        assert!(report.manual_evidence_pending);
        assert!(report.external_evidence_pending);
        assert_eq!(report.manual_pending_count, 5);
        assert_eq!(report.external_pending_count, 7);
        assert!(
            report
                .pending_manual_evidence
                .iter()
                .any(|artifact| artifact.name == "openid_config_op_conformance")
        );
        assert!(
            report
                .pending_external_evidence
                .iter()
                .any(|artifact| artifact.name == "scim_okta_connector_smoke")
        );
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

    #[test]
    fn release_evidence_plan_has_no_pending_manual_or_external_evidence_for_local_only_specs() {
        let specs = [EvidenceSpec {
            name: "dependency_policy_check",
            file_name: "dependency-policy-check.json",
            release_gate: "Dependency policy",
            command: "cairn-api operations dependency-policy-evidence > dependency-policy-check.json",
            validator: EvidenceValidator::DependencyPolicyCheck,
            contains_secrets: false,
            requires_production_like_environment: false,
            writes_application_state: false,
            touches_external_provider: false,
        }];

        let report = release_evidence_capture_plan_from_specs(&specs, generated_at(), |_| true);

        assert_eq!(report.status, "ready");
        assert!(report.local_capture_ready);
        assert!(!report.manual_evidence_pending);
        assert!(!report.external_evidence_pending);
        assert_eq!(report.manual_pending_count, 0);
        assert_eq!(report.external_pending_count, 0);
        assert!(report.pending_manual_evidence.is_empty());
        assert!(report.pending_external_evidence.is_empty());
        assert_eq!(report.steps.len(), 1);
        assert_eq!(report.steps[0].status, "ready");
        assert!(!report.steps[0].pending_manual_evidence);
        assert!(!report.steps[0].pending_external_evidence);
    }

    fn generated_at() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2026-06-07T12:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("valid test timestamp")
    }
}
