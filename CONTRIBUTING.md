# Contributing

Cairn Identity is security-sensitive infrastructure. Contributions should keep the implementation boring, explicit, and testable.

Participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Report vulnerabilities through [SECURITY.md](SECURITY.md), not public issues.

## Local Checks

```powershell
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny check
cargo audit
bun install --frozen-lockfile
bun run audit
bun run check
bun run check:public-surface
bun run test
bun run build
bun run test:e2e
```

Use Bun for JavaScript package management, script execution, local tool execution, and web runtime paths. Do not add non-Bun JavaScript lockfiles.

## Release Tooling

Before a first-public-RC release-evidence run, use `cairnid evidence plan` in the release capture environment, then `cairnid evidence init`, `cairnid evidence status`, and `cairnid evidence check` as documented in [docs/operations.md](docs/operations.md). These commands may name required environment variables and artifact commands, but they must not print secret values.

## Dependency Rule

Before adding or materially changing a direct dependency, read the relevant upstream docs or source for the API being used and record non-obvious version, feature-flag, security, or MSRV decisions in the relevant docs or PR description.

## Code Style

- Keep Rust crates focused on clear boundaries: domain, authn, oidc, database, audit, and API.
- Prefer typed errors and validation over ad hoc strings.
- Do not log secrets, bearer tokens, authorization codes, password material, or raw MFA state.
- Keep web UI operational and dense; this is an admin product, not a landing page.
- Keep tests focused on security and protocol invariants.
- Update [docs/threat-model.md](docs/threat-model.md) when changing authentication, OIDC/OAuth behavior, secrets, cookies, persistence, deployment, audit behavior, or trust boundaries.

## Pull Requests

Every PR should include:

- What changed.
- Which checks were run.
- Any security or compatibility impact.
- Documentation updates for dependency, milestone, or release-gate changes.
- Threat model updates for changed assets, trust boundaries, controls, invariants, or residual risks.
