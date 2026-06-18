use super::types::EvidenceValidator;

pub(in crate::operations_evidence) fn evidence_validator_name(
    validator: EvidenceValidator,
) -> &'static str {
    match validator {
        EvidenceValidator::OperationsPreflight => "operations_preflight",
        EvidenceValidator::DependencyPolicyCheck => "dependency_policy_check",
        EvidenceValidator::ReleaseAssetsVerification => "release_assets_verification",
        EvidenceValidator::OpenIdStaticRegistration => "openid_static_registration",
        EvidenceValidator::OpenIdStaticConfig => "openid_static_config",
        EvidenceValidator::OidcMetadataSmoke => "oidc_metadata_smoke",
        EvidenceValidator::OpenIdConfigOpConformance => "openid_config_op_conformance",
        EvidenceValidator::OpenIdBasicOpConformance => "openid_basic_op_conformance",
        EvidenceValidator::ScimGenericConnectorProfile => "scim_connector_profile_generic",
        EvidenceValidator::ScimOktaConnectorProfile => "scim_connector_profile_okta",
        EvidenceValidator::ScimEntraConnectorProfile => "scim_connector_profile_entra",
        EvidenceValidator::ScimSmoke => "scim_smoke",
        EvidenceValidator::ScimOktaConnectorSmoke => "scim_connector_smoke_okta",
        EvidenceValidator::ScimEntraConnectorSmoke => "scim_connector_smoke_entra",
        EvidenceValidator::BrowserOriginSmoke => "browser_origin_smoke",
        EvidenceValidator::SecurityHeadersSmoke => "security_headers_smoke",
        EvidenceValidator::EmailProviderSmoke => "email_provider_smoke",
        EvidenceValidator::LifecycleEmailSmoke => "lifecycle_email_smoke",
        EvidenceValidator::RestoreDrill => "restore_drill",
        EvidenceValidator::BreakGlassAdminRecovery => "break_glass_admin_recovery",
        EvidenceValidator::SigningKeyRotation => "signing_key_rotation",
        EvidenceValidator::KeyEncryptionRotation => "key_encryption_rotation",
        EvidenceValidator::AuditExportArchive => "audit_export_archive",
        EvidenceValidator::AuditRetentionPurge => "audit_retention_purge",
    }
}
