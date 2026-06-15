#[derive(Debug, Clone, Copy)]
pub(in crate::operations_evidence) enum EvidenceValidator {
    OperationsPreflight,
    DependencyPolicyCheck,
    OpenIdStaticRegistration,
    OpenIdStaticConfig,
    OidcMetadataSmoke,
    OpenIdConfigOpConformance,
    OpenIdBasicOpConformance,
    ScimGenericConnectorProfile,
    ScimOktaConnectorProfile,
    ScimEntraConnectorProfile,
    ScimSmoke,
    ScimOktaConnectorSmoke,
    ScimEntraConnectorSmoke,
    BrowserOriginSmoke,
    SecurityHeadersSmoke,
    EmailProviderSmoke,
    LifecycleEmailSmoke,
    RestoreDrill,
    BreakGlassAdminRecovery,
    SigningKeyRotation,
    KeyEncryptionRotation,
    AuditExportArchive,
    AuditRetentionPurge,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::operations_evidence) struct EvidenceSpec {
    pub(in crate::operations_evidence) name: &'static str,
    pub(in crate::operations_evidence) file_name: &'static str,
    pub(in crate::operations_evidence) command: &'static str,
    pub(in crate::operations_evidence) validator: EvidenceValidator,
    pub(in crate::operations_evidence) contains_secrets: bool,
    pub(in crate::operations_evidence) requires_production_like_environment: bool,
    pub(in crate::operations_evidence) writes_application_state: bool,
    pub(in crate::operations_evidence) touches_external_provider: bool,
}
