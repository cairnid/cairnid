use super::super::registry::EVIDENCE_SPECS;
use super::super::{ReleaseEvidenceError, release_evidence_manifest};
use super::init::init_release_evidence_directory;
use super::readme::release_evidence_readme;
use super::validation::validate_release_evidence_file_inventory;
use std::fs;
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
    assert!(readme.contains("| `operations-preflight.json` |"));
    assert!(readme.contains("| `cairn-oidcc-static.json` |"));
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

fn generated_at() -> OffsetDateTime {
    OffsetDateTime::parse(
        "2026-06-07T12:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .expect("valid test timestamp")
}

fn temp_evidence_dir(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "cairn-release-evidence-scaffold-{name}-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&root).expect("create temp evidence dir");
    root
}
