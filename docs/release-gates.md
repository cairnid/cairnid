# Release Gates

Cairn Identity has not published a first public RC. A release can be recommended for production use only after every required gate below has current evidence from the required environment for that gate.

## Required Gates

| Gate | Evidence | Status |
| --- | --- | --- |
| Source hygiene | `bun run check:public-surface` passes | CI-gated |
| Dependency policy | `dependency-policy-check.json` from `cairn-api operations dependency-policy-evidence`; proves `cargo deny check`, `cargo audit`, and `bun run audit` without archived command output | CI-gated locally; release receipt required |
| Rust quality | `cargo fmt`, `cargo check`, `cargo test`, and `cargo clippy -D warnings` pass | CI-gated |
| CLI Windows lifecycle proof | `cargo test -p cairnid --locked` passes on Windows, including binary-level release-evidence manifest, init, incomplete status/check, and failure-redaction coverage | CI-gated |
| MCP stdio and Windows behavior | `cargo test -p cairnid-mcp --locked` and `cargo clippy -p cairnid-mcp --locked --all-targets -- -D warnings` pass on Windows, including stdio initialize, `tools/list`, and sanitized `tools/call` coverage | CI-gated |
| CLI/MCP public release assets | `release-assets-verification.json`; proves tag, source commit, release URL or workflow run URL, CLI and MCP archives, SHA-256 verification, CycloneDX SBOM presence, `release-manifest.json`, and GitHub provenance plus SBOM attestation verification | Tag-gated; first RC pending |
| Frontend quality | `bun run check`, `bun run test`, `bun run build`, and `bun run test:e2e` pass | CI-gated |
| Docs export | `bun run docs:site -- --out <temp-dir>` completes without committing generated output | CI-gated |
| Database migrations | Postgres 17 migration tests pass against a disposable database | CI-gated |
| Containers | Compose validates, API image builds, web image builds, and image-level smoke checks pass; no container images are published by the release workflow | CI-gated smoke only |
| Operations preflight | `operations-preflight.json` from `cairn-api operations preflight`; proves production mode, migrations, signing/JWKS, email readiness, queue health, HTTPS issuer posture, static OpenID env readiness, and SCIM posture | Pending external evidence |
| Static OpenID artifacts | `openid-static-registration.json` and `cairn-oidcc-static.json` generated from the target issuer and static clients | Pending external evidence |
| Deployed OIDC metadata | `oidc-metadata-smoke.json` from `cairn-api operations oidc-metadata-smoke` passes against the HTTPS API origin | Pending external evidence |
| OpenID conformance | `openid-config-op-result.json` and `openid-basic-op-result.json` pass using generated static registration/config artifacts | Pending external evidence |
| Browser origin defense | `browser-origin-smoke.json` from `cairn-api operations browser-origin-smoke` passes against the HTTPS API origin | Pending external evidence |
| Security headers | `security-headers-smoke.json` from `cairn-api operations security-headers-smoke` passes against HTTPS API and web origins | Pending external evidence |
| SCIM provisioning | `scim-generic-connector-profile.json`, `scim-okta-connector-profile.json`, `scim-entra-connector-profile.json`, `scim-smoke.json`, `scim-okta-connector-smoke.json`, and `scim-entra-connector-smoke.json` pass | Pending external evidence |
| Email delivery | `email-provider-smoke.json` and `lifecycle-email-smoke.json` pass through the configured command provider | Pending external evidence |
| Restore drill | `restore-drill.json` from `cairn-api operations restore-check` passes against a restored database | Pending external evidence |
| Key operations | `signing-key-rotation-drill.json` and `kek-rotation-drill.json` pass evidence validation | Pending external evidence |
| Emergency access | `break-glass-admin-recovery-drill.json` passes and records audit evidence | Pending external evidence |
| Audit operations | `audit-export-archive-drill.json` and `audit-retention-purge-drill.json` pass evidence validation | Pending external evidence |
| Final release evidence | `cairnid evidence check <evidence-dir>` passes with fresh artifacts, current manifest, release-gate ownership metadata, and no unexpected files | Pending external evidence |

## Evidence Workflow

Until the first tagged RC is published, run the current CLI from a local checkout with `cargo run -p cairnid --locked -- <args>` or build it locally with `cargo build -p cairnid --locked` and run the resulting binary from `target`.

```powershell
cargo run -p cairnid --locked -- evidence plan
cargo run -p cairnid --locked -- evidence init <evidence-dir>
cargo run -p cairnid --locked -- evidence status --evidence-dir <evidence-dir>
cargo run -p cairnid --locked -- evidence check --evidence-dir <evidence-dir>
```

`cairnid evidence plan` confirms that required environment variable names are present without printing values. `cairnid evidence init` creates the guarded evidence directory. `cairnid evidence status` shows missing or failed artifacts while evidence is being collected. `cairnid evidence check` is the final local release gate.

The CLI evidence JSON reports carry root `schema_version="cairnid.evidence.v1"` for machine-readable contract stability. Additive fields can appear under the same version, but removing or renaming fields, changing field meanings, changing stable status values, weakening redaction expectations, or changing count/failure semantics requires a new schema version. Artifact entries in plan, manifest, status/check, next-action, and generated README output include `release_gate` ownership labels so operators can map each artifact back to this gate table.

Stable `cairnid evidence` exit codes:

- `0`: success.
- `1`: unexpected internal error.
- `2`: clap usage or parse error before runtime execution.
- `3`: the command printed JSON, but the release evidence set or capture environment is incomplete.
- `4`: operator input, path, or scaffold error, such as an evidence path that is not a directory or an existing scaffold without `--force`.

Do not commit release evidence directories. They can include operational context and must stay in controlled storage.

## CLI and MCP Release Assets

Pushing a tag that matches `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-rc.N` starts `.github/workflows/release.yml`. The workflow validates the tag with an exact regex, rejects tags that are not reachable from `origin/main`, and requires a successful completed `CI` run for the exact tagged commit before release artifacts are built. It then builds release-mode `cairnid` and `cairnid-mcp` binaries for:

- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`

For each tag, the workflow creates a draft GitHub Release containing:

- Versioned archives for each binary and target. Each `cairnid` CLI archive also contains generated Bash, Zsh, Fish, PowerShell, and Elvish completions under `completions/`, plus `man/man1/cairnid.1`; `cairnid-mcp` archives do not contain these CLI-only files.
- CycloneDX JSON SBOMs generated with `cargo-cyclonedx`.
- `SHA256SUMS.txt`.
- `release-manifest.json` with source commit, workflow run, target, archive, SBOM, CLI archive auxiliary-file paths, and SHA-256 metadata.
- GitHub artifact attestations created with `actions/attest@v4`, GitHub Actions OIDC, and Sigstore, without long-lived signing keys.

Maintainers must review and publish the draft before the assets are public. RC tags are marked as prereleases and are not marked latest. The workflow does not publish crates.io packages, Homebrew formulae, MSI installers, macOS notarized assets, Authenticode signatures, containers, or any site/runtime artifact.

CI distribution smoke artifacts are different. The regular CI workflow uploads short-lived Actions artifacts named `*-ci-rehearsal-*` to prove release-mode binaries can build and smoke-test before a tag exists. Those CI artifacts are not public release assets, are not attached to a GitHub Release, and are not the install path for users.

Container checks are also different from public release assets. CI validates Compose configuration, builds the API and web images, and runs image-level smoke checks, but no workflow currently pushes images to a registry or records public container digests. Container publication requires a separate registry policy and workflow before it can be documented as a release artifact.

After a draft release is published, download and verify the archive, checksum file, manifest, and SBOM from the GitHub Release page or with `gh release download`. Example:

```powershell
gh release download v0.1.0-rc.1 --repo cairnid/cairnid --dir cairnid-release
cd cairnid-release
gh attestation verify .\cairnid-v0.1.0-rc.1-x86_64-pc-windows-msvc.zip --repo cairnid/cairnid --signer-workflow cairnid/cairnid/.github/workflows/release.yml --source-ref refs/tags/v0.1.0-rc.1
gh attestation verify .\cairnid-v0.1.0-rc.1-x86_64-pc-windows-msvc.zip --repo cairnid/cairnid --signer-workflow cairnid/cairnid/.github/workflows/release.yml --source-ref refs/tags/v0.1.0-rc.1 --predicate-type https://cyclonedx.org/bom
Get-FileHash .\cairnid-v0.1.0-rc.1-x86_64-pc-windows-msvc.zip -Algorithm SHA256
```

The first `gh attestation verify` command checks the default SLSA provenance attestation. The second verifies the CycloneDX SBOM attestation for the same archive with the CycloneDX predicate type. Compare the `Get-FileHash` value with `SHA256SUMS.txt`, `release-manifest.json`, and the digest GitHub exposes for the release asset. On Linux, use `sha256sum -c SHA256SUMS.txt --ignore-missing` and the same `gh attestation verify` commands against `./cairnid-v0.1.0-rc.1-x86_64-unknown-linux-gnu.tar.gz`.

After every required archive and SBOM is verified, save a token-free `release-assets-verification.json` receipt into the release-evidence directory. The receipt must record `status="ok"`, `completed_at`, the release tag, source commit, release URL or workflow run URL, checksum-file presence and verification, release-manifest presence and checksum verification, the four expected CLI/MCP archives, the four matching CycloneDX SBOMs, per-asset SHA-256 verification, release-manifest entries, and GitHub provenance plus SBOM attestation verification booleans. Do not include GitHub tokens, request headers, cookies, raw attestation payloads, debug logs, or copied command stdout/stderr.

## Current Blockers

- No first public RC tag has been pushed and published.
- No `release-assets-verification.json` can be captured until a first public RC GitHub Release exists and its assets are verified.
- No current `dependency-policy-check.json` release receipt has been captured for a release-evidence directory.
- No current `operations-preflight.json` has been captured from the target production-like deployment.
- No current static OpenID artifacts, `openid-static-registration.json` and `cairn-oidcc-static.json`, have been captured from the target issuer/static clients.
- No container image publishing workflow or registry policy exists; CI container checks are smoke evidence only.
- No published OpenID Foundation conformance result.
- No deployed HTTPS metadata/JWKS smoke receipt.
- No deployed browser-origin or security-header smoke receipt.
- No command-provider `email-provider-smoke.json` or `lifecycle-email-smoke.json` receipt.
- No production-like restore, signing-key rotation, KEK rotation, break-glass, audit export, or audit purge drill receipt.
- No SCIM connector profile artifacts, built-in `scim-smoke.json`, or external Okta and Entra SCIM connector summaries.
- Repository or organization release immutability must be enabled before publishing the first public RC if the release should lock assets and tags after publication.
