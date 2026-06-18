# Changelog

All notable changes will be documented here.

This project follows semantic versioning once tagged releases begin.

## Unreleased

### Added

- Initial pre-beta Cairn Identity codebase with Rust Axum API, SvelteKit web UI, SQLx/Postgres persistence, Docker Compose deployment files, and GitHub Actions CI.
- OIDC/OAuth core endpoints, session management, MFA, account lifecycle, SCIM subset, audit operations, signing-key operations, and release-evidence tooling.
- Local stdio MCP server for read-only release-evidence inspection.
- Tag-driven draft GitHub Release workflow for `cairnid` and `cairnid-mcp` Linux and Windows archives, CycloneDX SBOMs, SHA256 checksums, release manifest, and GitHub artifact attestations.
- Public release gates, roadmap, security policy, contribution guide, support policy, governance notes, and maintainer ownership metadata.

### Documented

- Release workflow publishes CLI/MCP archives and evidence metadata only; it does not publish container images, package-manager assets, installers, macOS signed assets, or site/runtime artifacts.
- CI builds and smokes API and web container images as release-gate evidence, not as public distribution artifacts.
