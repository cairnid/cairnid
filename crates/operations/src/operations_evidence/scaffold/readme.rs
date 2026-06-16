use super::super::ReleaseEvidenceManifest;

pub(super) fn release_evidence_readme(manifest: &ReleaseEvidenceManifest) -> String {
    let mut readme = String::new();
    readme.push_str("# Cairn Identity Release Evidence\n\n");
    readme.push_str(
        "This directory is for public-beta release evidence. Keep it access-controlled. ",
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
    readme.push_str("2. Keep state-changing drills on a production-like environment only.\n");
    readme.push_str(
        "3. Run `cairn-api operations evidence-check <evidence-dir>` before public beta.\n",
    );
    readme.push_str("4. Do not commit the evidence artifacts.\n\n");
    readme.push_str(
        "5. Do not add screenshots, raw provider exports, logs, or extra files to this directory.\n\n",
    );
    readme.push_str("## Required Artifacts\n\n");
    readme.push_str("| File | Command | Secrets | Mutates | External Provider |\n");
    readme.push_str("| --- | --- | --- | --- | --- |\n");
    for artifact in &manifest.artifacts {
        readme.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} |\n",
            artifact.file_name,
            artifact.command,
            yes_no(artifact.contains_secrets),
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
