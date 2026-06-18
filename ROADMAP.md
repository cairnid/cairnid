# Roadmap

Cairn Identity should earn trust through a small hardened core before broad protocol coverage.

## 0.1.0 Beta

- Close every gate in [docs/release-gates.md](docs/release-gates.md).
- Publish OpenID Foundation Config OP and Basic OP conformance results.
- Publish a draft-reviewed GitHub Release with changelog, CLI/MCP archives, SBOMs, provenance attestations, checksums, and release manifest.
- Keep container images as CI build/smoke evidence only until a separate container publishing workflow and registry policy exist.
- Capture Docker Compose and container deployment smoke evidence for release gates.
- Keep SAML, LDAP, reverse-proxy auth, device trust, and identity brokering out of scope.

## 0.2.x

- SAML IdP.
- LDAP/Active Directory directory integration.
- Upstream OIDC identity brokering.
- Reverse-proxy authentication mode.
- Stronger admin policy controls and conditional access primitives.

## 0.3.x

- Helm/Kubernetes deployment package.
- External metrics and tracing integration.
- Shared signals and device posture foundations.
- Provider-specific SCIM templates and validation reports.

## Ongoing

- Keep protocol behavior strict by default.
- Prefer explicit operator commands and evidence receipts over informal runbook notes.
- Avoid adding feature breadth until security, tests, and documentation are in place.
