# CairnID Documentation

CairnID documentation lives in this repository so implementation changes, review context, and published docs stay together. The website should publish these files at `cairnid.com/docs` instead of keeping a separate copy.

## Start Here

- [Architecture](architecture/overview.md): runtime shape, crate boundaries, storage, and deployment flow.
- [API](api.md): implemented HTTP, OIDC/OAuth, session, admin, MFA, account lifecycle, and SCIM endpoints.
- [Deployment](deployment.md): local Compose, container runtime, environment variables, and Windows build notes.
- [Operations](operations.md): release evidence, preflight, backup/restore, key rotation, audit export, and drills.
- [MCP](mcp.md): local read-only release-evidence tools over stdio.
- [Security posture](security.md): implemented controls, gaps, release evidence, and reporting boundaries.
- [Release gates](release-gates.md): required evidence before production recommendation.

## Protocol And Product Areas

- [MFA](mfa.md)
- [Account lifecycle](account-lifecycle.md)
- [SCIM](scim.md)
- [OpenID conformance](openid-conformance.md)
- [Dependency policy](dependencies.md)
- [Threat model](threat-model.md)

## Project References

- [Changelog](../CHANGELOG.md)
- [Security policy](../SECURITY.md)
- [Support](../SUPPORT.md)
- [Roadmap](../ROADMAP.md)

## Website Export

The canonical docs can be exported with:

```powershell
bun run docs:site -- --out dist/site-docs
```

The export writes Markdown files plus `manifest.json`. It rewrites links between exported docs to `/docs/<slug>` paths and copies configured assets. A website repository such as `site` can ingest that generated directory without keeping a separate copy of these docs. Generated output should not be committed back to this repository.
