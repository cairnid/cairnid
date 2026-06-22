use super::helpers::env_req;
use crate::operations_evidence::{
    ReleaseEvidenceEnvironmentRequirement, registry::EvidenceValidator,
};

const DRILL_DATABASE_PURPOSE: &str = "production-like or restored Postgres drill database for release evidence; local rehearsal receipts are not release-ready evidence";
const RESTORED_DRILL_DATABASE_PURPOSE: &str = "restored production-like Postgres database for release evidence; local rehearsal receipts are not release-ready evidence";
const STATE_CHANGING_DRILL_DATABASE_PURPOSE: &str = "production-like or restored Postgres drill database prepared for state-changing release evidence; local rehearsal receipts are not release-ready evidence";

pub(super) fn evidence_environment_requirements(
    validator: EvidenceValidator,
) -> Vec<ReleaseEvidenceEnvironmentRequirement> {
    match validator {
        EvidenceValidator::DependencyPolicyCheck => Vec::new(),
        EvidenceValidator::ReleaseAssetsVerification => Vec::new(),
        EvidenceValidator::OperationsPreflight => vec![
            env_req(vec![vec!["CAIRN_ENV"]], "production-mode preflight", false),
            env_req(vec![vec!["DATABASE_URL"]], "database connectivity", true),
            env_req(vec![vec!["CAIRN_ISSUER"]], "public HTTPS issuer", false),
            env_req(
                vec![vec!["CAIRN_PUBLIC_WEB_ORIGIN"]],
                "public web origin",
                false,
            ),
            env_req(
                vec![
                    vec!["CAIRN_KEY_ENCRYPTION_KEY"],
                    vec![
                        "CAIRN_SIGNING_KEY_ID",
                        "CAIRN_SIGNING_PRIVATE_KEY_PEM",
                        "CAIRN_SIGNING_PUBLIC_JWK",
                    ],
                ],
                "OIDC signing source",
                true,
            ),
            env_req(
                vec![vec!["CAIRN_EMAIL_PROVIDER"]],
                "production email provider mode",
                false,
            ),
            env_req(
                vec![vec!["CAIRN_EMAIL_COMMAND_PATH"]],
                "production email provider command path",
                false,
            ),
        ],
        EvidenceValidator::OpenIdStaticRegistration => vec![
            env_req(vec![vec!["CAIRN_ISSUER"]], "public HTTPS issuer", false),
            env_req(
                vec![vec!["CAIRN_CONFORMANCE_ALIAS"]],
                "OpenID conformance suite alias",
                false,
            ),
            env_req(
                vec![vec!["CAIRN_CONFORMANCE_SUITE_BASE_URL"]],
                "OpenID conformance suite base URL",
                false,
            ),
            env_req(
                vec![vec!["CAIRN_CONFORMANCE_CLIENT_ID"]],
                "primary static client ID",
                false,
            ),
            env_req(
                vec![vec!["CAIRN_CONFORMANCE_CLIENT2_ID"]],
                "secondary static client ID",
                false,
            ),
        ],
        EvidenceValidator::OpenIdStaticConfig => vec![
            env_req(vec![vec!["CAIRN_ISSUER"]], "public HTTPS issuer", false),
            env_req(
                vec![vec!["CAIRN_CONFORMANCE_ALIAS"]],
                "OpenID conformance suite alias",
                false,
            ),
            env_req(
                vec![vec!["CAIRN_CONFORMANCE_CLIENT_ID"]],
                "primary static client ID",
                false,
            ),
            env_req(
                vec![vec!["CAIRN_CONFORMANCE_CLIENT_SECRET"]],
                "primary static client secret",
                true,
            ),
            env_req(
                vec![vec!["CAIRN_CONFORMANCE_CLIENT2_ID"]],
                "secondary static client ID",
                false,
            ),
            env_req(
                vec![vec!["CAIRN_CONFORMANCE_CLIENT2_SECRET"]],
                "secondary static client secret",
                true,
            ),
        ],
        EvidenceValidator::OidcMetadataSmoke => vec![env_req(
            vec![
                vec!["CAIRN_OIDC_METADATA_SMOKE_ISSUER"],
                vec!["CAIRN_ISSUER"],
            ],
            "deployed HTTPS issuer for metadata/JWKS smoke",
            false,
        )],
        EvidenceValidator::OpenIdConfigOpConformance
        | EvidenceValidator::OpenIdBasicOpConformance => Vec::new(),
        EvidenceValidator::ScimGenericConnectorProfile
        | EvidenceValidator::ScimOktaConnectorProfile
        | EvidenceValidator::ScimEntraConnectorProfile => vec![env_req(
            vec![vec!["CAIRN_ISSUER"]],
            "public HTTPS issuer for connector profile URLs",
            false,
        )],
        EvidenceValidator::ScimSmoke => vec![
            env_req(
                vec![vec!["CAIRN_SCIM_SMOKE_BASE_URL"], vec!["CAIRN_ISSUER"]],
                "deployed SCIM base URL",
                false,
            ),
            env_req(
                vec![vec!["CAIRN_SCIM_BEARER_TOKEN"]],
                "primary raw SCIM smoke token",
                true,
            ),
            env_req(
                vec![vec!["CAIRN_SCIM_SECONDARY_BEARER_TOKEN"]],
                "secondary raw SCIM token for rotation-window release evidence",
                true,
            ),
            env_req(
                vec![vec!["CAIRN_SCIM_REJECTED_BEARER_TOKEN"]],
                "retired or invalid raw SCIM token for rejection release evidence",
                true,
            ),
        ],
        EvidenceValidator::ScimOktaConnectorSmoke | EvidenceValidator::ScimEntraConnectorSmoke => {
            Vec::new()
        }
        EvidenceValidator::BrowserOriginSmoke => vec![env_req(
            vec![
                vec!["CAIRN_BROWSER_ORIGIN_SMOKE_BASE_URL"],
                vec!["CAIRN_ISSUER"],
            ],
            "deployed API base URL for browser-origin rejection smoke",
            false,
        )],
        EvidenceValidator::SecurityHeadersSmoke => vec![
            env_req(
                vec![
                    vec!["CAIRN_SECURITY_HEADERS_API_BASE_URL"],
                    vec!["CAIRN_ISSUER"],
                ],
                "deployed API base URL for security-header smoke",
                false,
            ),
            env_req(
                vec![
                    vec!["CAIRN_SECURITY_HEADERS_WEB_BASE_URL"],
                    vec!["CAIRN_PUBLIC_WEB_ORIGIN"],
                ],
                "deployed web base URL for security-header smoke",
                false,
            ),
        ],
        EvidenceValidator::EmailProviderSmoke => vec![
            env_req(
                vec![vec!["CAIRN_EMAIL_PROVIDER"]],
                "production email provider mode",
                false,
            ),
            env_req(
                vec![vec!["CAIRN_EMAIL_COMMAND_PATH"]],
                "production email provider command path",
                false,
            ),
        ],
        EvidenceValidator::LifecycleEmailSmoke => vec![
            env_req(vec![vec!["DATABASE_URL"]], "database connectivity", true),
            env_req(
                vec![vec!["CAIRN_EMAIL_PROVIDER"]],
                "production email provider mode",
                false,
            ),
            env_req(
                vec![vec!["CAIRN_EMAIL_COMMAND_PATH"]],
                "production email provider command path",
                false,
            ),
            env_req(
                vec![vec!["CAIRN_KEY_ENCRYPTION_KEY"]],
                "encrypted lifecycle action-link rendering",
                true,
            ),
        ],
        EvidenceValidator::RestoreDrill => vec![
            env_req(
                vec![vec!["DATABASE_URL"]],
                RESTORED_DRILL_DATABASE_PURPOSE,
                true,
            ),
            env_req(
                vec![
                    vec!["CAIRN_KEY_ENCRYPTION_KEY"],
                    vec![
                        "CAIRN_SIGNING_KEY_ID",
                        "CAIRN_SIGNING_PRIVATE_KEY_PEM",
                        "CAIRN_SIGNING_PUBLIC_JWK",
                    ],
                ],
                "post-restore OIDC signing source",
                true,
            ),
        ],
        EvidenceValidator::BreakGlassAdminRecovery => vec![
            env_req(
                vec![vec!["DATABASE_URL"]],
                STATE_CHANGING_DRILL_DATABASE_PURPOSE,
                true,
            ),
            env_req(
                vec![vec!["CAIRN_BREAK_GLASS_CONFIRM"]],
                "explicit break-glass acknowledgement",
                false,
            ),
        ],
        EvidenceValidator::SigningKeyRotation => vec![
            env_req(
                vec![vec!["DATABASE_URL"]],
                STATE_CHANGING_DRILL_DATABASE_PURPOSE,
                true,
            ),
            env_req(
                vec![vec!["CAIRN_KEY_ENCRYPTION_KEY"]],
                "database-backed signing-key encryption",
                true,
            ),
        ],
        EvidenceValidator::KeyEncryptionRotation => vec![
            env_req(
                vec![vec!["DATABASE_URL"]],
                STATE_CHANGING_DRILL_DATABASE_PURPOSE,
                true,
            ),
            env_req(
                vec![vec!["CAIRN_OLD_KEY_ENCRYPTION_KEY"]],
                "old database key-encryption key",
                true,
            ),
            env_req(
                vec![vec!["CAIRN_NEW_KEY_ENCRYPTION_KEY"]],
                "new database key-encryption key",
                true,
            ),
        ],
        EvidenceValidator::AuditExportArchive | EvidenceValidator::AuditRetentionPurge => {
            let purpose = if matches!(validator, EvidenceValidator::AuditRetentionPurge) {
                STATE_CHANGING_DRILL_DATABASE_PURPOSE
            } else {
                DRILL_DATABASE_PURPOSE
            };
            vec![env_req(vec![vec!["DATABASE_URL"]], purpose, true)]
        }
    }
}
