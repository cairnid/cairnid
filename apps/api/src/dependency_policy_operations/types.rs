use serde::Serialize;
use time::OffsetDateTime;

#[derive(Debug, Serialize)]
pub(crate) struct DependencyPolicyEvidenceReport {
    pub(in crate::dependency_policy_operations) status: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    pub(in crate::dependency_policy_operations) completed_at: OffsetDateTime,
    pub(in crate::dependency_policy_operations) workspace: DependencyPolicyWorkspaceReport,
    pub(in crate::dependency_policy_operations) checks: Vec<DependencyPolicyCheckReport>,
    pub(crate) failures: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(in crate::dependency_policy_operations) struct DependencyPolicyWorkspaceReport {
    pub(in crate::dependency_policy_operations) cargo_lock_present: bool,
    pub(in crate::dependency_policy_operations) bun_lock_present: bool,
    pub(in crate::dependency_policy_operations) package_json_present: bool,
    pub(in crate::dependency_policy_operations) deny_toml_present: bool,
    pub(in crate::dependency_policy_operations) cargo_audit_config_present: bool,
    pub(in crate::dependency_policy_operations) dependency_docs_present: bool,
}

#[derive(Debug, Serialize)]
pub(in crate::dependency_policy_operations) struct DependencyPolicyCheckReport {
    pub(in crate::dependency_policy_operations) name: &'static str,
    pub(in crate::dependency_policy_operations) command: &'static str,
    pub(in crate::dependency_policy_operations) status: &'static str,
    pub(in crate::dependency_policy_operations) exit_code: Option<i32>,
    pub(in crate::dependency_policy_operations) stdout_bytes: usize,
    pub(in crate::dependency_policy_operations) stderr_bytes: usize,
    pub(in crate::dependency_policy_operations) tool_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::dependency_policy_operations) failure: Option<String>,
}
