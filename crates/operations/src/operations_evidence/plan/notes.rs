use super::super::registry::{EvidenceSpec, EvidenceValidator};

pub(super) fn evidence_capture_is_manual(validator: EvidenceValidator) -> bool {
    matches!(
        validator,
        EvidenceValidator::OpenIdConfigOpConformance
            | EvidenceValidator::OpenIdBasicOpConformance
            | EvidenceValidator::ScimOktaConnectorSmoke
            | EvidenceValidator::ScimEntraConnectorSmoke
    )
}

pub(super) fn evidence_operator_notes(spec: &EvidenceSpec) -> Vec<&'static str> {
    let mut notes = Vec::new();
    match spec.validator {
        EvidenceValidator::DependencyPolicyCheck => {
            notes.push(
                "Run from the repository root after installing the pinned dependency-security tools.",
            );
            notes.push("The generated receipt records tool versions, exit codes, and byte counts only; do not archive full audit stdout or stderr in release evidence.");
        }
        EvidenceValidator::OpenIdConfigOpConformance
        | EvidenceValidator::OpenIdBasicOpConformance => {
            notes.push("Export this artifact from the OpenID Foundation conformance suite after running the generated static-client plan.");
            notes.push("Use `cairn-api conformance oidcc-result-template <config-op|basic-op>` to generate the token-free normalized published-result shape when archiving an official result URL instead of a full suite export.");
            notes.push("Do not include static-client secrets, cookies, request headers, passwords, screenshots, or browser session data in normalized OpenID result summaries.");
        }
        EvidenceValidator::ScimOktaConnectorSmoke | EvidenceValidator::ScimEntraConnectorSmoke => {
            notes.push("Record a normalized connector smoke summary after the external provisioning client completes the required SCIM create, update, deactivation, deletion, Bulk, and token-rotation checks.");
            notes.push("Use `cairn-api scim connector-smoke-template <okta|entra>` to generate the token-free JSON shape, then replace every placeholder with verified external connector evidence.");
            notes.push("Do not include raw connector bearer tokens, provider credentials, end-user secrets, or provider console screenshots in this JSON artifact.");
        }
        _ => {}
    }
    if matches!(spec.validator, EvidenceValidator::ScimSmoke) {
        notes.push("Public-beta SCIM evidence requires primary, secondary, and rejected token checks even though the smoke command can run without optional rotation variables.");
    }
    if matches!(spec.validator, EvidenceValidator::EmailProviderSmoke) {
        notes.push("The smoke-provider command also requires a controlled recipient email argument; the plan does not record mailbox addresses.");
    }
    if spec.writes_application_state {
        notes.push(
            "Run this command only against a production-like tenant prepared for state-changing release smoke.",
        );
    }
    if spec.contains_secrets {
        notes.push(
            "The artifact or command inputs can contain secrets; keep the evidence directory access-controlled and uncommitted.",
        );
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::super::super::registry::EvidenceValidator;
    use super::evidence_capture_is_manual;

    #[test]
    fn manual_capture_set_is_limited_to_external_suite_and_connector_evidence() {
        assert!(evidence_capture_is_manual(
            EvidenceValidator::OpenIdBasicOpConformance
        ));
        assert!(evidence_capture_is_manual(
            EvidenceValidator::ScimEntraConnectorSmoke
        ));
        assert!(!evidence_capture_is_manual(EvidenceValidator::ScimSmoke));
        assert!(!evidence_capture_is_manual(
            EvidenceValidator::OperationsPreflight
        ));
    }
}
