use super::super::ReleaseEvidenceManifest;

pub(super) fn release_evidence_readme(manifest: &ReleaseEvidenceManifest) -> String {
    let mut readme = String::new();
    readme.push_str("# Cairn Identity Release Evidence\n\n");
    readme.push_str(
        "This directory is for first-public-RC and public-release evidence. Keep it access-controlled. ",
    );
    readme.push_str(
        "The generated `.gitignore` keeps evidence artifacts out of source control by default.\n\n",
    );
    readme.push_str(
        "One required artifact, `cairn-oidcc-static.json`, contains OIDC client secrets. ",
    );
    readme.push_str(
        "Provider receipts and drill reports can also reveal operational posture, so store the directory with the same care as deployment records.\n\n",
    );
    readme.push_str("## Workflow\n\n");
    readme.push_str("1. Produce each artifact with the command in the checklist.\n");
    readme.push_str("2. Capture restore, signing-key rotation, KEK rotation, break-glass, audit export, and audit purge drill evidence from production-like or restored Postgres databases.\n");
    readme.push_str(
        "3. Keep state-changing drills on an approved production-like or restored database only.\n",
    );
    readme.push_str("4. Use local rehearsal only with disposable or restored databases; local rehearsal receipts are not release-ready evidence.\n");
    readme.push_str("5. Run `cairnid evidence check <evidence-dir>` before the first public RC and each public release.\n");
    readme.push_str("6. Do not commit the evidence artifacts.\n");
    readme.push_str("7. Do not add screenshots, raw provider exports, logs, or extra files to this directory.\n\n");
    readme.push_str("## Required Artifacts\n\n");
    readme.push_str("| Release Gate | File | Command | Secrets | Production-like Env | Mutates | External Provider |\n");
    readme.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for artifact in &manifest.artifacts {
        readme.push_str(&format!(
            "| {} | `{}` | `{}` | {} | {} | {} | {} |\n",
            artifact.release_gate,
            artifact.file_name,
            artifact.command,
            yes_no(artifact.contains_secrets),
            yes_no(artifact.requires_production_like_environment),
            yes_no(artifact.writes_application_state),
            yes_no(artifact.touches_external_provider)
        ));
    }
    readme.push_str("\n## Notes\n\n");
    for note in &manifest.notes {
        readme.push_str("- ");
        readme.push_str(note);
        readme.push('\n');
    }
    readme
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
