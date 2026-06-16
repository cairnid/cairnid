mod catalog;
mod helpers;

use super::super::ReleaseEvidenceEnvironmentRequirement;
use super::super::registry::EvidenceValidator;

pub(super) fn evidence_environment_requirements(
    validator: EvidenceValidator,
) -> Vec<ReleaseEvidenceEnvironmentRequirement> {
    catalog::evidence_environment_requirements(validator)
}

pub(super) fn missing_environment_for_requirements<F>(
    artifact_name: &'static str,
    requirements: &[ReleaseEvidenceEnvironmentRequirement],
    environment_present: &F,
) -> Vec<String>
where
    F: Fn(&'static str) -> bool,
{
    helpers::missing_environment_for_requirements(artifact_name, requirements, environment_present)
}

#[cfg(test)]
mod tests;
