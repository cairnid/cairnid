# Release Gates

Cairn Identity is pre-beta. A release can be recommended for production use only after every required gate below has current evidence from a production-like HTTPS deployment.

## Required Gates

| Gate | Evidence | Status |
| --- | --- | --- |
| Source hygiene | `bun run check:public-surface` passes | CI-gated |
| Dependency policy | `cargo deny check`, `cargo audit`, `bun run audit`, and `cairn-api operations dependency-policy-evidence` pass | CI-gated locally; release receipt required |
| Rust quality | `cargo fmt`, `cargo check`, `cargo test`, and `cargo clippy -D warnings` pass | CI-gated |
| Frontend quality | `bun run check`, `bun run test`, `bun run build`, and `bun run test:e2e` pass | CI-gated |
| Database migrations | Postgres 17 migration tests pass against a disposable database | CI-gated |
| Containers | Compose validates, API image builds, web image builds, and image-level smoke checks pass | CI-gated |
| Deployed OIDC metadata | `cairn-api operations oidc-metadata-smoke` passes against the HTTPS API origin | Pending external evidence |
| OpenID conformance | Config OP and Basic OP suite runs pass using generated static registration/config artifacts | Pending external evidence |
| Browser origin defense | `cairn-api operations browser-origin-smoke` passes against the HTTPS API origin | Pending external evidence |
| Security headers | `cairn-api operations security-headers-smoke` passes against HTTPS API and web origins | Pending external evidence |
| SCIM provisioning | Built-in SCIM smoke and token-free Okta/Entra connector summaries pass | Pending external evidence |
| Email delivery | Provider smoke and lifecycle email smoke pass through the configured production command provider | Pending external evidence |
| Restore drill | `cairn-api operations restore-check` passes against a restored database | Pending external evidence |
| Key operations | Signing-key rotation and KEK re-encryption receipts pass evidence validation | Pending external evidence |
| Emergency access | Break-glass admin recovery drill passes and records audit evidence | Pending external evidence |
| Audit operations | NDJSON archive and retention purge receipts pass evidence validation | Pending external evidence |
| Final release evidence | `cairn-api operations evidence-check <evidence-dir>` passes with fresh artifacts and no unexpected files | Pending external evidence |

## Evidence Workflow

```powershell
cairn-api operations evidence-plan
cairn-api operations evidence-init <evidence-dir>
cairn-api operations evidence-status <evidence-dir>
cairn-api operations evidence-check <evidence-dir>
```

`evidence-plan` confirms that required environment variable names are present without printing values. `evidence-init` creates the guarded evidence directory. `evidence-status` shows missing or failed artifacts while evidence is being collected. `evidence-check` is the final local release gate.

Do not commit release evidence directories. They can include operational context and must stay in controlled storage.

## Current Blockers

- No published OpenID Foundation conformance result.
- No deployed HTTPS metadata/JWKS smoke receipt.
- No deployed browser-origin or security-header smoke receipt.
- No production provider email smoke receipt.
- No production-like restore, signing-key rotation, KEK rotation, break-glass, audit export, or audit purge drill receipt.
- No external Okta and Entra SCIM connector summaries.
