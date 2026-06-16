mod init;
mod manifest;
mod readme;
mod validation;

pub(super) use init::init_release_evidence_directory;
pub(super) use manifest::release_evidence_manifest_from_specs;
pub(super) use validation::{
    validate_release_evidence_file_inventory, validate_release_evidence_scaffold,
};

pub(super) const RELEASE_EVIDENCE_MANIFEST_FILE: &str = "release-evidence-manifest.json";
pub(super) const RELEASE_EVIDENCE_README_FILE: &str = "README.md";
pub(super) const RELEASE_EVIDENCE_GITIGNORE_FILE: &str = ".gitignore";

pub(super) const RELEASE_EVIDENCE_GITIGNORE: &str = "\
# Release evidence can contain provider receipts and client secrets.
# Keep artifact JSON out of source control by default.
*
!.gitignore
!README.md
!release-evidence-manifest.json
";

#[cfg(test)]
mod tests;
