use super::{
    email_evidence, oidc, operations_drill, operations_readiness, public_surface,
    registry::EvidenceValidator, scim,
};
use serde_json::Value;

pub(super) fn validate_artifact(
    validator: EvidenceValidator,
    value: &Value,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    match validator {
        EvidenceValidator::OperationsPreflight => {
            operations_readiness::validate_operations_preflight(value, checks, failures);
        }
        EvidenceValidator::DependencyPolicyCheck => {
            operations_readiness::validate_dependency_policy_check(value, checks, failures);
        }
        EvidenceValidator::OpenIdStaticRegistration => {
            oidc::validate_openid_static_registration(value, checks, failures);
        }
        EvidenceValidator::OpenIdStaticConfig => {
            oidc::validate_openid_static_config(value, checks, failures);
        }
        EvidenceValidator::OidcMetadataSmoke => {
            oidc::validate_oidc_metadata_smoke(value, checks, failures);
        }
        EvidenceValidator::OpenIdConfigOpConformance => {
            oidc::validate_openid_conformance_result(
                value,
                "Config OP",
                "oidcc-config-certification-test-plan",
                checks,
                failures,
            );
        }
        EvidenceValidator::OpenIdBasicOpConformance => {
            oidc::validate_openid_conformance_result(
                value,
                "Basic OP",
                "oidcc-basic-certification-test-plan",
                checks,
                failures,
            );
        }
        EvidenceValidator::ScimSmoke => {
            scim::validate_scim_smoke(value, checks, failures);
        }
        EvidenceValidator::ScimOktaConnectorSmoke => {
            scim::validate_scim_connector_smoke(value, "okta", checks, failures);
        }
        EvidenceValidator::ScimEntraConnectorSmoke => {
            scim::validate_scim_connector_smoke(value, "entra", checks, failures);
        }
        EvidenceValidator::ScimGenericConnectorProfile => {
            scim::validate_scim_connector_profile(value, "generic", checks, failures);
        }
        EvidenceValidator::ScimOktaConnectorProfile => {
            scim::validate_scim_connector_profile(value, "okta", checks, failures);
        }
        EvidenceValidator::ScimEntraConnectorProfile => {
            scim::validate_scim_connector_profile(value, "entra", checks, failures);
        }
        EvidenceValidator::BrowserOriginSmoke => {
            public_surface::validate_browser_origin_smoke(value, checks, failures);
        }
        EvidenceValidator::SecurityHeadersSmoke => {
            public_surface::validate_security_headers_smoke(value, checks, failures);
        }
        EvidenceValidator::EmailProviderSmoke => {
            email_evidence::validate_email_provider_smoke(value, checks, failures);
        }
        EvidenceValidator::LifecycleEmailSmoke => {
            email_evidence::validate_lifecycle_email_smoke(value, checks, failures);
        }
        EvidenceValidator::RestoreDrill => {
            operations_drill::validate_restore_drill(value, checks, failures);
        }
        EvidenceValidator::BreakGlassAdminRecovery => {
            operations_drill::validate_break_glass_admin_recovery(value, checks, failures);
        }
        EvidenceValidator::SigningKeyRotation => {
            operations_drill::validate_signing_key_rotation(value, checks, failures);
        }
        EvidenceValidator::KeyEncryptionRotation => {
            operations_drill::validate_key_encryption_rotation(value, checks, failures);
        }
        EvidenceValidator::AuditExportArchive => {
            operations_drill::validate_audit_export_archive(value, checks, failures);
        }
        EvidenceValidator::AuditRetentionPurge => {
            operations_drill::validate_audit_retention_purge(value, checks, failures);
        }
    }
}
