<p align="center">
  <img src="docs/assets/cairn-wordmark.svg" alt="Cairn Identity" width="420">
</p>

<p align="center">
  <strong>A small, auditable identity provider for teams that want strict OIDC without a heavy platform.</strong>
</p>

<p align="center">
  <a href="https://github.com/ibuuvai/cairnid/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/ibuuvai/cairnid/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="Rust" src="https://img.shields.io/badge/rust-1.94%2B-f46623">
  <img alt="Bun" src="https://img.shields.io/badge/bun-1.3.4-black">
</p>

<p align="center">
  <a href="docs/architecture/overview.md">Architecture</a>
  | <a href="docs/api.md">API</a>
  | <a href="docs/deployment.md">Deployment</a>
  | <a href="docs/security.md">Security</a>
  | <a href="docs/release-gates.md">Release Gates</a>
</p>

> Cairn Identity is pre-beta. It is not OpenID Certified and should not be used as a production identity provider until the gates in [docs/release-gates.md](docs/release-gates.md) are complete.

## Scope

Cairn Identity focuses on a narrow identity-provider core: issue tokens correctly, keep organization data isolated, make administrative workflows clear, and give operators verifiable release evidence. It does not support legacy OAuth flows by default.

## Core Features

| Area | Included |
| --- | --- |
| OIDC/OAuth | Discovery, JWKS, authorization, token, UserInfo, introspection, revocation, and RP-initiated logout |
| Flows | Authorization Code + PKCE, refresh-token rotation, and client credentials |
| Security posture | Exact redirect matching, RS256 ID tokens, opaque access tokens, no implicit/hybrid/password grants |
| Admin model | Organizations, users, groups, memberships, OIDC clients, consent policies, audit events |
| Authentication | Password login, Argon2 hashing, TOTP, WebAuthn/passkeys, recovery codes, session review and revocation |
| Account lifecycle | Invitations, email verification, password recovery, security notifications, outbox delivery worker |
| Provisioning | SCIM 2.0 user and group subset with bounded PATCH/Bulk behavior and token-rotation support |
| Operations | Docker Compose, health checks, signing-key rotation, KEK rotation, restore checks, audit export/purge |

## Quick Start

Run the full local stack with Docker Compose:

```powershell
docker compose -f infra/docker-compose.yml up --build
```

Open `http://localhost:5173`, bootstrap the first administrator from `/login`, then use `/admin` to create users, groups, memberships, and OIDC clients.

For local development, install JavaScript dependencies with Bun and run the API and web app separately:

```powershell
bun install
cargo run -p cairn-api -- signing-key generate-kek
$env:DATABASE_URL="postgres://cairn:cairn@localhost:5432/cairn_identity"
$env:CAIRN_ISSUER="http://localhost:8080"
$env:CAIRN_PUBLIC_WEB_ORIGIN="http://localhost:5173"
$env:CAIRN_KEY_ENCRYPTION_KEY="<paste generated value>"
# Required when CAIRN_ENV=production:
# $env:CAIRN_BOOTSTRAP_SETUP_SECRET="<random setup secret>"
cargo run -p cairn-api
```

```powershell
bun run dev
```

## Protocol Endpoints

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET /oauth2/authorize`
- `POST /oauth2/token`
- `GET /oauth2/userinfo`
- `POST /oauth2/introspect`
- `POST /oauth2/revoke`

## Repository Layout

```text
apps/api          Rust Axum API and OIDC provider
apps/web          SvelteKit admin, login, consent, and user UI
crates/audit      Audit event builders and redaction
crates/authn      Password, token, PKCE, TOTP, and WebAuthn primitives
crates/database   SQLx repositories and migrations
crates/domain     Core organization-scoped domain types
crates/oidc       OIDC/OAuth policy, discovery, claims, and signing
docs              Architecture, API, deployment, operations, and security docs
infra             Compose, migrations, and local scripts
```

## Development

Use Bun for JavaScript package management.

```powershell
cargo fmt --all -- --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo deny check
cargo audit
bun install --frozen-lockfile
bun run audit
bun run check:public-surface
bun run check
bun run test
bun run build
bun run test:e2e
```

For the real Postgres migration smoke, point `CAIRN_DATABASE_TEST_URL` at a disposable database:

```powershell
$env:CAIRN_DATABASE_TEST_URL="postgres://cairn:cairn@localhost:5432/cairn_identity_test"
cargo test -p cairn-database --test postgres_migrations --locked
```

## Documentation

- [Architecture](docs/architecture/overview.md)
- [API](docs/api.md)
- [Deployment](docs/deployment.md)
- [Operations](docs/operations.md)
- [Security posture](docs/security.md)
- [Threat model](docs/threat-model.md)
- [MFA](docs/mfa.md)
- [Account lifecycle](docs/account-lifecycle.md)
- [SCIM](docs/scim.md)
- [OpenID conformance](docs/openid-conformance.md)
- [Dependency policy](docs/dependencies.md)
- [Release gates](docs/release-gates.md)
- [Roadmap](ROADMAP.md)

## Security

Report vulnerabilities privately. Do not open public issues for suspected auth, session, token, signing-key, cross-organization access, MFA, SCIM, audit, deployment, or secret-handling vulnerabilities. See [SECURITY.md](SECURITY.md).

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). The short version: keep protocol behavior strict, keep JavaScript tooling Bun-first, update threat-model and operations docs when security boundaries change, and include the checks you ran in every PR.

## License

Apache-2.0. See [LICENSE](LICENSE).
