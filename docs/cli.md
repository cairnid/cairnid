# cairnid CLI Contract

`cairnid` is the public operator CLI for CairnID release evidence. Its current support boundary is release-evidence planning, evidence-directory scaffolding, local evidence validation, release-asset verification, and generated shell/manpage reference files. It is not an API server, an install manager, an MCP server, or a production-support claim.

CairnID has not published a first public RC. Until a reviewed GitHub Release exists, run the CLI from a source checkout with Cargo or from a locally built binary. Do not describe CI artifacts or workflow rehearsal artifacts as the public install path.

## Command Surface

The current top-level commands are:

- `cairnid completions <shell>`: writes one completion script to stdout. Supported shells are `bash`, `zsh`, `fish`, `powershell`, and `elvish`.
- `cairnid evidence <command>`: plans, initializes, summarizes, and checks release evidence.
- `cairnid release-assets verify <release-dir> ...`: verifies a local directory of downloaded or workflow-produced release assets and prints a JSON receipt.
- `cairnid manpage`: writes the root `cairnid.1` roff manpage to stdout.
- `cairnid manpages <OUTPUT_DIR>`: writes the root manpage and visible subcommand manpages into the output directory.
- `cairnid --help` and `cairnid --version`: print clap-generated help and the package version.

The implemented evidence subcommands are:

- `cairnid evidence plan`: prints the release evidence capture plan as JSON.
- `cairnid evidence manifest`: prints the release evidence manifest contract as JSON without writing files.
- `cairnid evidence init <EVIDENCE_DIR> [--force]`: creates the evidence scaffold directory.
- `cairnid evidence status <EVIDENCE_DIR>` or `cairnid evidence status --evidence-dir <EVIDENCE_DIR>`: validates evidence and prints a compact JSON readiness summary.
- `cairnid evidence check <EVIDENCE_DIR>` or `cairnid evidence check --evidence-dir <EVIDENCE_DIR>`: validates evidence and prints the full per-artifact JSON report.

`status` and `check` accept `--max-age-days <DAYS>`, currently limited to `1..=365` with a default of `30`.

## Evidence Lifecycle

Use `cairnid evidence plan` before capture. It reports required artifact metadata, commands, validator names, release-gate labels, safety flags, required environment variable names, missing environment variable names, and manual or provider-backed evidence that still needs operator action. It checks whether required variable names are present; it does not validate secret values or deployed service behavior.

Use `cairnid evidence init <EVIDENCE_DIR>` to create the guarded scaffold before collecting artifacts. The scaffold writes `release-evidence-manifest.json`, `README.md`, and `.gitignore`. Existing scaffold files are not replaced unless `--force` is passed.

Collect only the required JSON evidence artifacts into the initialized directory. Use `cairnid evidence status` while collecting evidence and `cairnid evidence check` as the final local release gate. Both reject missing, stale, malformed, unexpected, or contract-incompatible evidence, including forbidden secret-shaped fields in token-free artifacts.

Evidence directories are operational records. Keep them access-controlled and out of source control.

## JSON Contract

`cairnid evidence plan`, `manifest`, `init`, `status`, and `check` print pretty JSON to stdout when runtime execution begins. Their root `schema_version` is `cairnid.evidence.v1`.

The `cairnid.evidence.v1` version identifies the CLI and operations release-evidence report contract, not the format of every individual evidence artifact. Additive root fields, nested fields, artifact entries, counts, notes, and next-action details may be added under the same version. Removing or renaming fields, changing field meanings, changing stable status values, weakening redaction expectations, or changing count and failure semantics requires a new schema version.

Current evidence report status values are:

- `plan`: `ready` or `missing_environment`.
- `manifest`: `ok`.
- `init`: `initialized`.
- `status` and `check`: `ready` or `incomplete`.

The CLI exposes sanitized report fields needed for release work: artifact names, file names, release-gate labels, commands, checks, counts, next actions, stable `failure_codes`, and sanitized failure text. `status` and `check` include root `failure_codes`; `status.next_actions[]` and `check.artifacts[]` include per-artifact `failure_codes` where validation reached an evidence artifact. Current code values are `missing_evidence`, `stale_or_invalid_scaffold`, `invalid_json`, `invalid_json_root`, `stale_or_invalid_timestamp`, `timestamp_contract`, `forbidden_field`, `artifact_path_failure`, `contract_mismatch`, and `validation_failed`. The CLI does not print raw evidence artifact JSON, provider exports, logs, standard streams, cookies, bearer tokens, client secrets, lifecycle tokens, request headers, or secret-bearing OpenID static artifacts. Missing environment reporting is by variable name only.

`cairnid release-assets verify` prints a separate release-assets verification receipt with root `schema_version="cairnid.release_assets_verification.v1"`. It is the expected content for `release-assets-verification.json` only when it exits successfully with `status="ok"` and an empty `failures` array.

## Exit Behavior

The CLI has stable high-level exit behavior:

- `0`: success.
- `1`: unexpected internal error.
- `2`: clap usage or parse error before runtime execution.
- `3`: runtime validation completed and printed JSON, but the evidence set, capture environment, or release-assets verification is incomplete or failed.
- `4`: operator input, path, scaffold, tag, source-commit, or run-URL error.

Clap errors exit before runtime execution, print usage diagnostics to stderr, and do not print JSON. Runtime validation failures that can produce a report print JSON to stdout and a short `cairnid failed: ...` message to stderr. Operator-input errors avoid echoing secret-like values and path fragments tested as sensitive.

## Release-Assets Verification

`cairnid release-assets verify <release-dir>` reads local files and prints a token-free receipt. It does not download assets, call `gh`, verify remote attestations itself, query GitHub release settings, publish anything, or write files.

Required arguments are:

- `--tag <TAG>`: must match `vMAJOR.MINOR.PATCH` or `vMAJOR.MINOR.PATCH-rc.N`.
- `--source-commit <SHA>`: must be a 40-character hexadecimal source commit.
- Exactly one of `--release-url <URL>` or `--run-url <URL>`.
- `--provenance-attestations-verified`: operator confirmation that provenance attestations were verified externally.
- `--sbom-attestations-verified`: operator confirmation that SBOM attestations were verified externally.

For final published-release evidence, use `--release-url <URL>` and include `--github-release-immutability-enabled-before-publish` after confirming release immutability was enabled before publication. A `--run-url` receipt is workflow-local validation output and is not final release evidence.

The verifier checks `SHA256SUMS.txt`, `release-manifest.json`, four expected CLI/MCP archives, four expected CycloneDX SBOMs, per-file SHA-256 metadata, manifest source and distribution flags, SBOM `bomFormat="CycloneDX"`, and archive member structure. CLI archives must include `LICENSE`, `README.md`, the `cairnid` binary, generated completions, and generated manpages. MCP archives must not include CLI-only completions or manpages.

After a published release is available and external attestation checks have passed, generate the evidence receipt with:

```powershell
cairnid release-assets verify <release-dir> --tag <tag> --source-commit <sha> --release-url <release-url> --github-release-immutability-enabled-before-publish --provenance-attestations-verified --sbom-attestations-verified > release-assets-verification.json
```

Then place `release-assets-verification.json` in the initialized evidence directory and run `cairnid evidence check <evidence-dir>`.

## Generated Reference Files

The CLI can generate local reference files from the same clap command definition used at runtime:

```powershell
cairnid completions powershell > cairnid.ps1
cairnid completions bash > cairnid.bash
cairnid manpage > cairnid.1
cairnid manpages .\man\man1
```

The release workflow regenerates completion scripts and roff manpages from the freshly built `cairnid` binary and packages them inside each CLI archive under `completions/` and `man/man1/`. `cairnid-mcp` archives do not include those CLI-only files. Generated completions and manpages should be regenerated from the binary used for packaging or local shell support rather than committed as source.

## Out Of Scope

The current CLI contract does not claim package-manager distribution, Homebrew support, crates.io publication, public Docker registry distribution, cloud-managed service support, unattended install scripts, OpenID Certification, production readiness, or a published RC. Those claims require separate release evidence and documentation updates.
