# Dependency Policy

Cairn Identity treats dependency changes as security-sensitive changes.

## Required Checks

Run these before merging Rust dependency changes:

```powershell
cargo deny check
cargo audit
```

Run this before merging frontend dependency changes:

```powershell
bun install --frozen-lockfile
bun run audit
```

Generate the dependency-policy release-evidence receipt from the repository root:

```powershell
cairn-api operations dependency-policy-evidence > dependency-policy-check.json
```

The receipt runs `cargo deny check`, `cargo audit`, and `bun run audit` without a shell. It records lockfile/config/doc presence, tool versions, exit codes, and stdout/stderr byte counts only. Do not archive full audit output in release evidence.

CI installs pinned versions of the policy tools:

- `cargo-deny 0.19.8`
- `cargo-audit 0.22.2`
- `bun 1.3.14`

## Cargo Policy

The repository-level [deny.toml](../deny.toml) enforces:

- RustSec advisories with yanked crates denied.
- Unknown registries and unknown Git sources denied.
- Wildcard dependency declarations denied.
- Duplicate workspace dependency declarations denied.
- Licenses denied by default unless explicitly allowed.
- Duplicate transitive crate versions denied unless an exact-version skip documents the upstream cause.

The current duplicate-version skips are intentionally exact versions. When upstream crates converge, `cargo deny check` will warn about unused skips and the entry should be removed.

## Bun Policy

Frontend dependencies are installed with `bun install --frozen-lockfile` and audited with `bun audit`. The root `package.json` uses Bun's top-level `overrides` for security-driven transitive dependency pins.

Current overrides:

- `cookie=0.7.2`: forces SvelteKit's transitive cookie parser above the vulnerable `<0.7.0` advisory range while upstream still declares `cookie ^0.6.0`.

Use Bun for JavaScript package management. Do not add npm, pnpm, or yarn lockfiles.

## Review Expectations

Before adding or materially changing a direct dependency:

1. Read the upstream documentation or source for the API being used.
2. Prefer stable public APIs over private internals.
3. Record any non-obvious version, feature-flag, security, or MSRV decision in the relevant docs or PR description.
4. Keep `Cargo.lock`, `bun.lock`, CI, and release-evidence checks green.

## Notes

- The workspace Rust floor is 1.96 for this RC toolchain.
- JWT signing uses `jsonwebtoken` with the `aws_lc_rs` backend.
- Signing-key generation/export uses `openssl`, which is already required by WebAuthn support.
- Startup origin validation uses the `url` crate instead of ad hoc string parsing.
- SQLx migrations use four-digit sequential versions; migration tests reject malformed, duplicate, or non-contiguous filenames.
