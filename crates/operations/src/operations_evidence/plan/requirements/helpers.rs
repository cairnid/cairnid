use crate::operations_evidence::ReleaseEvidenceEnvironmentRequirement;

pub(super) fn missing_environment_for_requirements<F>(
    artifact_name: &'static str,
    requirements: &[ReleaseEvidenceEnvironmentRequirement],
    environment_present: &F,
) -> Vec<String>
where
    F: Fn(&'static str) -> bool,
{
    requirements
        .iter()
        .filter(|requirement| !environment_requirement_satisfied(requirement, environment_present))
        .map(|requirement| missing_environment_message(artifact_name, requirement))
        .collect()
}

pub(super) fn env_req(
    alternatives: Vec<Vec<&'static str>>,
    purpose: &'static str,
    contains_secret: bool,
) -> ReleaseEvidenceEnvironmentRequirement {
    ReleaseEvidenceEnvironmentRequirement {
        alternatives,
        purpose,
        contains_secret,
    }
}

pub(super) fn environment_requirement_satisfied<F>(
    requirement: &ReleaseEvidenceEnvironmentRequirement,
    environment_present: &F,
) -> bool
where
    F: Fn(&'static str) -> bool,
{
    requirement
        .alternatives
        .iter()
        .any(|alternative| alternative.iter().all(|name| environment_present(name)))
}

fn missing_environment_message(
    artifact_name: &'static str,
    requirement: &ReleaseEvidenceEnvironmentRequirement,
) -> String {
    let alternatives = requirement
        .alternatives
        .iter()
        .map(|alternative| alternative.join(" + "))
        .collect::<Vec<_>>()
        .join(" OR ");
    format!(
        "{artifact_name}: set {alternatives} for {}",
        requirement.purpose
    )
}
