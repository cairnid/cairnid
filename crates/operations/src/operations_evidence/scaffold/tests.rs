use super::super::registry::EVIDENCE_SPECS;
use super::super::{ReleaseEvidenceError, release_evidence_manifest};
use super::init::init_release_evidence_directory;
use super::readme::release_evidence_readme;
use super::validation::{
    validate_release_evidence_file_inventory, validate_release_evidence_scaffold,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use time::OffsetDateTime;
use uuid::Uuid;

#[test]
fn scaffold_init_refuses_existing_files_unless_force_is_explicit() {
    let root = temp_evidence_dir("existing-scaffold");
    init_release_evidence_directory(&root, generated_at(), false).expect("first init");

    let error = init_release_evidence_directory(&root, generated_at(), false)
        .expect_err("existing scaffold must be protected");
    assert!(matches!(
        error,
        ReleaseEvidenceError::ExistingScaffoldFile(_)
    ));

    let forced = init_release_evidence_directory(&root, generated_at(), true)
        .expect("forced scaffold overwrite");
    assert!(forced.force);
    assert_eq!(
        forced.files_written,
        vec![
            "release-evidence-manifest.json".to_owned(),
            "README.md".to_owned(),
            ".gitignore".to_owned(),
        ]
    );
}

#[test]
fn scaffold_readme_contains_required_operator_guidance_and_artifact_table() {
    let readme = release_evidence_readme(&release_evidence_manifest(generated_at()));

    assert!(readme.contains("Do not commit the evidence artifacts"));
    assert!(readme.contains("cairnid evidence check <evidence-dir>"));
    assert!(readme.contains("Do not add screenshots, raw provider exports"));
    assert!(readme.contains("| Release Gate | File | Command |"));
    assert!(readme.contains("`operations-preflight.json`"));
    assert!(readme.contains("CLI/MCP public release assets"));
    assert!(readme.contains("`release-assets-verification.json`"));
    assert!(readme.contains("`cairn-oidcc-static.json`"));
}

#[test]
fn scaffold_inventory_rejects_unexpected_entries() {
    let root = temp_evidence_dir("inventory");
    init_release_evidence_directory(&root, generated_at(), false).expect("init scaffold");
    fs::write(root.join("unexpected.json"), "{}").expect("write unexpected file");

    let mut failures = Vec::new();
    validate_release_evidence_file_inventory(&root, EVIDENCE_SPECS, &mut failures)
        .expect("inventory validation");

    assert!(
        failures
            .iter()
            .any(|failure| failure.contains("unexpected release evidence entry: unexpected.json"))
    );
}

#[test]
fn scaffold_validation_rejects_symlinked_manifest_before_reading_target() {
    let root = temp_evidence_dir("symlink-manifest-validation");
    init_release_evidence_directory(&root, generated_at(), false).expect("init scaffold");
    let target = root.join("target-manifest.json");
    fs::write(&target, "{").expect("write symlink target");
    let manifest_path = root.join("release-evidence-manifest.json");
    fs::remove_file(&manifest_path).expect("remove generated manifest");
    if !create_file_symlink_or_skip(&target, &manifest_path) {
        fs::remove_dir_all(root).expect("cleanup temp dir");
        return;
    }

    let mut failures = Vec::new();
    validate_release_evidence_scaffold(&root, generated_at(), 30, &mut failures)
        .expect("validate scaffold");

    assert!(failures.iter().any(|failure| {
        failure
            == "release-evidence-manifest.json: scaffold file must be a regular file, got symlink"
    }));
    assert!(
        !failures.iter().any(
            |failure| failure.contains("scaffold manifest must be valid release-evidence JSON")
        )
    );

    fs::remove_dir_all(root).expect("cleanup temp dir");
}

#[test]
fn scaffold_init_force_rejects_symlinked_readme_without_touching_target() {
    let root = temp_evidence_dir("symlink-readme-init");
    init_release_evidence_directory(&root, generated_at(), false).expect("init scaffold");
    let target = root.join("target-readme.md");
    fs::write(&target, "sentinel readme").expect("write symlink target");
    let readme_path = root.join("README.md");
    fs::remove_file(&readme_path).expect("remove generated README");
    if !create_file_symlink_or_skip(&target, &readme_path) {
        fs::remove_dir_all(root).expect("cleanup temp dir");
        return;
    }

    let error = init_release_evidence_directory(&root, generated_at(), true)
        .expect_err("forced init must reject symlinked scaffold file");

    assert!(matches!(error, ReleaseEvidenceError::Io(_)));
    assert_eq!(
        fs::read_to_string(&target).expect("read symlink target"),
        "sentinel readme"
    );

    fs::remove_dir_all(root).expect("cleanup temp dir");
}

#[test]
fn scaffold_init_force_rejects_non_symlink_directory_entry_before_writing_any_scaffold() {
    let root = temp_evidence_dir("directory-readme-init");
    init_release_evidence_directory(&root, generated_at(), false).expect("init scaffold");
    let manifest_path = root.join("release-evidence-manifest.json");
    fs::write(&manifest_path, "sentinel manifest").expect("replace manifest");
    let readme_path = root.join("README.md");
    fs::remove_file(&readme_path).expect("remove generated README");
    fs::create_dir(&readme_path).expect("create directory at README path");

    let error = init_release_evidence_directory(&root, generated_at(), true)
        .expect_err("forced init must reject directory scaffold entry");

    assert!(matches!(error, ReleaseEvidenceError::Io(_)));
    assert_eq!(
        fs::read_to_string(&manifest_path).expect("read manifest"),
        "sentinel manifest"
    );

    fs::remove_dir_all(root).expect("cleanup temp dir");
}

fn generated_at() -> OffsetDateTime {
    OffsetDateTime::parse(
        "2026-06-07T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .expect("valid test timestamp")
}

fn temp_evidence_dir(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "cairn-release-evidence-scaffold-{name}-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&root).expect("create temp evidence dir");
    root
}

fn create_file_symlink_or_skip(target: &Path, link: &Path) -> bool {
    match create_file_symlink(target, link) {
        Ok(()) => true,
        Err(error) if windows_symlink_creation_unavailable(&error) => {
            eprintln!(
                "skipping symlink-specific scaffold assertion; Windows denied symlink creation: {error}"
            );
            false
        }
        Err(error) => panic!("create file symlink: {error}"),
    }
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

fn windows_symlink_creation_unavailable(error: &io::Error) -> bool {
    cfg!(windows)
        && (error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314))
}
