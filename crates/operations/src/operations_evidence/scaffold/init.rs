use super::super::{ReleaseEvidenceError, ReleaseEvidenceInitReport, release_evidence_manifest};
use super::readme::release_evidence_readme;
use super::{
    RELEASE_EVIDENCE_GITIGNORE, RELEASE_EVIDENCE_GITIGNORE_FILE, RELEASE_EVIDENCE_MANIFEST_FILE,
    RELEASE_EVIDENCE_README_FILE,
};
use std::{fs, path::Path};
use time::OffsetDateTime;

pub(in crate::operations_evidence) fn init_release_evidence_directory(
    evidence_dir: &Path,
    generated_at: OffsetDateTime,
    force: bool,
) -> Result<ReleaseEvidenceInitReport, ReleaseEvidenceError> {
    fs::create_dir_all(evidence_dir)?;
    let scaffold_files = [
        RELEASE_EVIDENCE_MANIFEST_FILE,
        RELEASE_EVIDENCE_README_FILE,
        RELEASE_EVIDENCE_GITIGNORE_FILE,
    ];

    if !force {
        for file_name in scaffold_files {
            let path = evidence_dir.join(file_name);
            if path.exists() {
                return Err(ReleaseEvidenceError::ExistingScaffoldFile(
                    path.to_string_lossy().into_owned(),
                ));
            }
        }
    }

    let manifest = release_evidence_manifest(generated_at);
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    let readme = release_evidence_readme(&manifest);

    let files = [
        (RELEASE_EVIDENCE_MANIFEST_FILE, manifest_json),
        (RELEASE_EVIDENCE_README_FILE, readme),
        (
            RELEASE_EVIDENCE_GITIGNORE_FILE,
            RELEASE_EVIDENCE_GITIGNORE.to_owned(),
        ),
    ];

    let mut files_written = Vec::with_capacity(files.len());
    for (file_name, contents) in files {
        let path = evidence_dir.join(file_name);
        fs::write(&path, contents)?;
        files_written.push(file_name.to_owned());
    }

    Ok(ReleaseEvidenceInitReport {
        status: "initialized",
        evidence_dir: evidence_dir.to_string_lossy().into_owned(),
        generated_at,
        force,
        artifact_count: manifest.artifact_count,
        secret_artifact_count: manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.contains_secrets)
            .count(),
        state_changing_artifact_count: manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.writes_application_state)
            .count(),
        external_provider_artifact_count: manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.touches_external_provider)
            .count(),
        files_written,
        next_command: format!("cairnid evidence check {}", evidence_dir.to_string_lossy()),
    })
}
